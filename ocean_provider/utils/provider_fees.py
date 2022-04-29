import json
import logging
import os
import requests
from datetime import datetime
from typing import Any, Dict

from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.basics import LocalFileAdapter, get_provider_wallet, get_web3
from ocean_provider.utils.currency import parse_units
from ocean_provider.utils.datatoken import get_datatoken_contract, validate_order
from ocean_provider.utils.services import Service
from ocean_provider.utils.url import is_this_same_provider
from ocean_provider.utils.compute_environments import (
    get_c2d_environments,
    get_environment,
)

logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())


def get_provider_fees(
    did: str,
    service: Service,
    consumer_address: str,
    valid_until: int,
    compute_env: str = None,
    force_zero: bool = False,
) -> Dict[str, Any]:
    web3 = get_web3()
    provider_wallet = get_provider_wallet()
    provider_fee_address = provider_wallet.address
    provider_fee_token = os.environ.get(
        "PROVIDER_FEE_TOKEN", "0x0000000000000000000000000000000000000000"
    )

    if compute_env and not force_zero:
        provider_fee_amount = get_provider_fee_amount(
            valid_until, compute_env, web3, provider_fee_token
        )
    else:
        provider_fee_amount = 0

    provider_data = json.dumps({"environment": compute_env}, separators=(",", ":"))
    message_hash = web3.solidityKeccak(
        ["bytes", "address", "address", "uint256", "uint256"],
        [
            web3.toHex(web3.toBytes(text=provider_data)),
            provider_fee_address,
            provider_fee_token,
            provider_fee_amount,
            valid_until,
        ],
    )

    pk = keys.PrivateKey(provider_wallet.key)
    prefix = "\x19Ethereum Signed Message:\n32"
    signable_hash = web3.solidityKeccak(
        ["bytes", "bytes"], [web3.toBytes(text=prefix), web3.toBytes(message_hash)]
    )
    signed = keys.ecdsa_sign(message_hash=signable_hash, private_key=pk)

    provider_fee = {
        "providerFeeAddress": provider_fee_address,
        "providerFeeToken": provider_fee_token,
        "providerFeeAmount": provider_fee_amount,
        "providerData": web3.toHex(web3.toBytes(text=provider_data)),
        # make it compatible with last openzepellin https://github.com/OpenZeppelin/openzeppelin-contracts/pull/1622
        "v": (signed.v + 27) if signed.v <= 1 else signed.v,
        "r": web3.toHex(web3.toBytes(signed.r).rjust(32, b"\0")),
        "s": web3.toHex(web3.toBytes(signed.s).rjust(32, b"\0")),
        "validUntil": valid_until,
    }
    logger.debug(f"Returning provider_fees: {provider_fee}")
    return provider_fee


def get_provider_fees_or_remote(
    asset, service, consumer_address, valid_until, compute_env, force_zero, dataset
):
    valid_order = None
    if "transferTxId" in dataset:
        web3 = get_web3()
        try:
            _tx, _order_log, _provider_fees_log = validate_order(
                web3,
                consumer_address,
                dataset["transferTxId"],
                asset,
                service,
                {"environment": compute_env},
                allow_expired_provider_fees=True,
            )
            log_valid_until = _provider_fees_log.args.validUntil
            if datetime.utcnow().timestamp() <= log_valid_until:
                # already paid provider fees and both order and provider fees are still valid
                return {"validOrder": _order_log.transactionHash.hex()}
            else:
                valid_order = _order_log.transactionHash.hex()
        except Exception:
            # order does not exist or is expired, so we need new provider fees
            pass

    if is_this_same_provider(service.service_endpoint):
        result = {
            "datatoken": service.datatoken_address,
            "providerFee": get_provider_fees(
                asset.did,
                service,
                consumer_address,
                valid_until,
                compute_env,
                force_zero=force_zero,
            ),
        }
    else:
        # delegate to different provider
        response = requests.get(
            service.service_endpoint + "/api/services/initialize", params=dataset
        )

        result = response.json()

    if valid_order:
        result["validOrder"] = valid_order

    return result


def get_provider_fee_amount(valid_until, compute_env, web3, provider_fee_token):
    seconds = (datetime.fromtimestamp(valid_until) - datetime.utcnow()).seconds
    env = get_environment(get_c2d_environments(), compute_env)

    if provider_fee_token == "0x0000000000000000000000000000000000000000":
        return 0

    provider_fee_amount = float(seconds * env["priceMin"] / 60)

    dt = get_datatoken_contract(web3, provider_fee_token)
    decimals = dt.caller.decimals()

    return parse_units(str(provider_fee_amount), decimals)
