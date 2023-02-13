#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import os
from datetime import datetime
from distutils.util import strtobool
from typing import Optional, Union

from eth_account import Account
from hexbytes import HexBytes
from ocean_provider.http_provider import CustomHTTPProvider
from web3 import WebsocketProvider
from web3.exceptions import ExtraDataLengthError
from web3.main import Web3
from web3.middleware import geth_poa_middleware

logger = logging.getLogger(__name__)


def get_metadata_url():
    return os.getenv("AQUARIUS_URL")


def get_provider_wallet(web3: Optional[Web3] = None):
    """
    :return: Wallet instance
    """
    if web3 is None:
        web3 = get_web3()

    pk = os.environ.get("PROVIDER_PRIVATE_KEY")
    wallet = Account.from_key(private_key=pk)

    if wallet is None:
        raise AssertionError(
            f"Ocean Provider cannot run without a valid "
            f"ethereum account. `PROVIDER_PRIVATE_KEY` was not found in the environment "
            f"variables. \nENV WAS: {sorted(os.environ.items())}"
        )

    if not wallet.key:
        raise AssertionError(
            "Ocean Provider cannot run without a valid ethereum private key."
        )

    return wallet


def get_web3(network_url: Optional[str] = None, cached=True) -> Web3:
    """
    :return: `Web3` instance
    """
    global app_web3_instance

    if cached and "app_web3_instance" in globals():
        return app_web3_instance

    if network_url is None:
        network_url = os.getenv("NETWORK_URL")

    web3 = Web3(provider=get_web3_connection_provider(network_url))

    try:
        web3.eth.get_block("latest")
    except ExtraDataLengthError:
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    web3.chain_id = web3.eth.chain_id
    app_web3_instance = web3
    return web3


def get_web3_connection_provider(
    network_url: str,
) -> Union[CustomHTTPProvider, WebsocketProvider]:
    if network_url.startswith("http"):
        return CustomHTTPProvider(network_url)
    elif network_url.startswith("ws"):
        return WebsocketProvider(network_url)
    else:
        msg = (
            f"The given network_url *{network_url}* does not start with either"
            f"`http` or `wss`. A correct network url is required."
        )
        raise AssertionError(msg)


def send_ether(web3, from_wallet: Account, to_address: str, amount: int):
    """Sends ether from wallet to the address."""
    if not Web3.isChecksumAddress(to_address):
        to_address = Web3.toChecksumAddress(to_address)

    chain_id = web3.eth.chain_id
    nonce = web3.eth.get_transaction_count(from_wallet.address)
    gas_price = int(web3.eth.gas_price * 1.1)
    tx = {
        "from": from_wallet.address,
        "to": to_address,
        "value": amount,
        "chainId": chain_id,
        "nonce": nonce,
        "gasPrice": gas_price,
    }
    tx["gas"] = web3.eth.estimate_gas(tx)
    raw_tx = Account.sign_transaction(tx, from_wallet.key).rawTransaction
    tx_hash = web3.eth.send_raw_transaction(raw_tx)

    return web3.eth.wait_for_transaction_receipt(HexBytes(tx_hash), timeout=120)


def validate_timestamp(value):
    """Checks whether a timestamp is valid (correctly formed and in the future)."""
    try:
        valid_until = datetime.fromtimestamp(int(value))
        now = datetime.utcnow()

        return valid_until > now
    except Exception as e:
        logger.error(f"Failed to validate timestamp {value}: {e}\n")
        return False


def bool_value_of_env(env_key):
    if not os.getenv(env_key):
        return False

    return bool(strtobool(str(os.getenv(env_key))))
