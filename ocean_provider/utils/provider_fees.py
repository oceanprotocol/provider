from web3.main import Web3
from typing import Any, Dict
import os
import json
from ocean_provider.utils.basics import get_provider_wallet, get_web3
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.services import Service
import eth_keys
from eth_account.account import Account
from eth_account.messages import encode_defunct
import logging
from ocean_provider.log import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


def get_provider_fees(
    did: str, service: Service, consumer_address: str
) -> Dict[str, Any]:
    provider_wallet = get_provider_wallet()
    provider_fee_amount = 0
    provider_data = {}
    provider_fee_address = provider_wallet.address
    provider_fee_token = os.environ.get(
        "PROVIDER_FEE_TOKEN", "0x0000000000000000000000000000000000000000"
    )
    message = Web3.solidityKeccak(
        ["bytes", "address", "address", "uint256"],
        [
            Web3.toHex(text=json.dumps(provider_data)),
            provider_fee_address,
            provider_fee_token,
            provider_fee_amount,
        ],
    )
    provider_wallet = get_provider_wallet()
    w3 = get_web3()
    signed = w3.eth.account.sign_message(
        encode_defunct(message), private_key=provider_wallet.key
    )
    provider_fee = {
        "providerFeeAddress": provider_fee_address,
        "providerFeeToken": provider_fee_token,
        "providerFeeAmount": provider_fee_amount,
        "providerData": Web3.toHex(text=json.dumps(provider_data)),
        "v": signed.v,
        "r": Web3.toHex(Web3.toBytes(signed.r).rjust(32, b"\0")),
        "s": Web3.toHex(Web3.toBytes(signed.s).rjust(32, b"\0")),
    }
    return provider_fee
