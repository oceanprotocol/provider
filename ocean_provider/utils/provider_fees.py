import json
import logging
import os
from typing import Any, Dict

from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from ocean_provider.log import setup_logging
from ocean_provider.utils.basics import get_provider_wallet, get_web3
from ocean_provider.utils.services import Service

setup_logging()
logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)


def get_provider_fees(
    did: str, service: Service, consumer_address: str
) -> Dict[str, Any]:
    web3 = get_web3()
    provider_wallet = get_provider_wallet()
    provider_fee_amount = 0
    provider_data = json.dumps({"timeout": 0}, separators=(",", ":"))
    provider_fee_address = provider_wallet.address
    provider_fee_token = os.environ.get(
        "PROVIDER_FEE_TOKEN", "0x0000000000000000000000000000000000000000"
    )
    message_hash = web3.solidityKeccak(
        ["bytes", "address", "address", "uint256"],
        [
            web3.toHex(web3.toBytes(text=provider_data)),
            provider_fee_address,
            provider_fee_token,
            provider_fee_amount,
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
    }
    logger.debug(f"Returning provider_fees: {provider_fee}")
    return provider_fee
