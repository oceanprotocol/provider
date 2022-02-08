import json
import logging
import os
from typing import Any, Dict, List

from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.basics import LocalFileAdapter, get_provider_wallet, get_web3
from ocean_provider.utils.services import Service
from ocean_provider.utils.util import get_compute_environments_endpoint

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
) -> Dict[str, Any]:
    web3 = get_web3()
    provider_wallet = get_provider_wallet()
    provider_fee_amount = 0
    provider_data = json.dumps(
        {"environment": compute_env, "timeout": 0}, separators=(",", ":")
    )
    provider_fee_address = provider_wallet.address
    provider_fee_token = os.environ.get(
        "PROVIDER_FEE_TOKEN", "0x0000000000000000000000000000000000000000"
    )
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


def get_c2d_environments() -> List:
    standard_headers = {"Content-type": "application/json", "Connection": "close"}
    try:
        response = requests_session.get(
            get_compute_environments_endpoint(), headers=standard_headers
        )

        # loop envs and add provider token from config
        envs = response.json()
        for env in envs:
            env["feeToken"] = os.getenv("PROVIDER_FEE_TOKEN")

        return envs
    except Exception:
        return []
