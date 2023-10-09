#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
import os
from datetime import datetime, timezone
from distutils.util import strtobool
from json.decoder import JSONDecodeError
from typing import Union

from eth_account import Account
from hexbytes import HexBytes
from ocean_provider.http_provider import CustomHTTPProvider
from web3 import WebsocketProvider
from web3.exceptions import ExtraDataLengthError
from web3.main import Web3
from web3.middleware import geth_poa_middleware

logger = logging.getLogger(__name__)

NETWORK_NAME_MAP = {
    1: "Mainnet",
    5: "Goerli",
    56: "Binance Smart Chain",
    137: "Polygon",
    246: "Energy Web",
    1285: "Moonriver",
    80001: "Mumbai",
    11155111: "Sepolia",
    8996: "Ganache",
}


def decode_keyed(env_key):
    try:
        decoded = json.loads(os.environ.get(env_key))
        return decoded
    except (JSONDecodeError, TypeError):
        return False

    return False


def get_value_from_decoded_env(chain_id, env_key):
    chain_id = str(chain_id)
    decoded = decode_keyed(env_key)

    if not decoded:
        return os.environ.get(env_key)

    if not chain_id or chain_id not in decoded:
        raise Exception("Unconfigured chain_id")

    return decoded[chain_id]


def get_configured_chains():
    decoded = decode_keyed("NETWORK_URL")
    single = os.environ.get("NETWORK_URL")

    if not decoded and not single:
        raise Exception("No chains configured")

    if not decoded:
        web3 = get_web3(os.environ.get("NETWORK_URL"))
        return [web3.eth.chain_id]

    return [int(key) for key in decoded.keys()]


def get_provider_addresses():
    chain_ids = get_configured_chains()
    if (not decode_keyed("NETWORK_URL") and decode_keyed("PROVIDER_PRIVATE_KEY")) or (
        decode_keyed("NETWORK_URL") and not decode_keyed("PROVIDER_PRIVATE_KEY")
    ):
        raise Exception(
            "NETWORK_URL and PROVIDER_PRIVATE_KEY must both be single or both json encoded."
        )
    if not decode_keyed("NETWORK_URL") and not decode_keyed("PROVIDER_PRIVATE_KEY"):
        wallet = Account.from_key(private_key=os.environ.get("PROVIDER_PRIVATE_KEY"))
        return {chain_ids[0]: wallet.address}

    return {chain_id: get_provider_wallet(chain_id).address for chain_id in chain_ids}


def get_provider_private_key(chain_id: int = None, use_universal_key: bool = False):
    if use_universal_key:
        universal_key = os.getenv("UNIVERSAL_PRIVATE_KEY")
        if universal_key:
            return universal_key

        if decode_keyed("PROVIDER_PRIVATE_KEY"):
            raise Exception(
                "Must define UNIVERSAL_PRIVATE_KEY or a single PROVIDER_PRIVATE_KEY."
            )

        return os.getenv("PROVIDER_PRIVATE_KEY")

    return get_value_from_decoded_env(chain_id, "PROVIDER_PRIVATE_KEY")


def get_metadata_url():
    return os.getenv("AQUARIUS_URL")


def get_provider_wallet(chain_id=None, use_universal_key=False):
    """
    :return: Wallet instance
    """
    if use_universal_key:
        wallet = Account.from_key(
            private_key=get_provider_private_key(0, use_universal_key=True)
        )
        return wallet

    pk = get_provider_private_key(chain_id)
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


def get_web3(chain_id, cached=True) -> Web3:
    """
    :return: `Web3` instance
    """
    global app_web3_instances

    if cached and "app_web3_instances" in globals() and chain_id in app_web3_instances:
        return app_web3_instances[chain_id]

    network_url = get_value_from_decoded_env(chain_id, "NETWORK_URL")

    web3 = Web3(provider=get_web3_connection_provider(network_url))

    try:
        web3.eth.get_block("latest")
    except ExtraDataLengthError:
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    web3.chain_id = web3.eth.chain_id
    if "app_web3_instances" not in globals():
        app_web3_instances = {}
    app_web3_instances[chain_id] = web3
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


def get_network_name(chain_id: int) -> str:
    if not chain_id:
        logger.error("Chain ID is missing")

    return NETWORK_NAME_MAP[chain_id]


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
        valid_until = datetime.fromtimestamp(int(value), timezone.utc)
        now = datetime.now(timezone.utc)

        return valid_until > now
    except Exception as e:
        logger.error(f"Failed to validate timestamp {value}: {e}\n")
        return False


def bool_value_of_env(env_key):
    if not os.getenv(env_key):
        return False

    return bool(strtobool(str(os.getenv(env_key))))
