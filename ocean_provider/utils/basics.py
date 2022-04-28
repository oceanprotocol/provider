#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime
import os
from typing import Optional, Union

import artifacts
import requests
from eth_account import Account
from hexbytes import HexBytes
from ocean_provider.config import Config
from ocean_provider.http_provider import CustomHTTPProvider
from requests_testadapter import Resp
from web3 import WebsocketProvider
from web3.main import Web3


def get_config(config_file: Optional[str] = None) -> Config:
    """
    :return: Config instance
    """
    return Config(
        filename=config_file
        if config_file is not None
        else os.getenv("PROVIDER_CONFIG_FILE", "config.ini")
    )


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


def get_web3(network_url: Optional[str] = None) -> Web3:
    """
    :return: `Web3` instance
    """
    global app_web3_instance

    if "app_web3_instance" in globals():
        return app_web3_instance

    if network_url is None:
        network_url = get_config().network_url

    web3 = Web3(provider=get_web3_connection_provider(network_url))

    if network_url.startswith("wss"):
        from web3.middleware import geth_poa_middleware

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


class LocalFileAdapter(requests.adapters.HTTPAdapter):
    def build_response_from_file(self, request):
        file_path = request.url[7:]
        with open(file_path, "rb") as file:
            buff = bytearray(os.path.getsize(file_path))
            file.readinto(buff)
            resp = Resp(buff)
            r = self.build_response(request, resp)

            return r

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):

        return self.build_response_from_file(request)


def send_ether(web3, from_wallet: Account, to_address: str, amount: int):
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
    try:
        valid_until = datetime.fromtimestamp(int(value))
        now = datetime.utcnow()

        return valid_until > now
    except Exception:
        return False
