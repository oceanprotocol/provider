#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import os
from pathlib import Path
from typing import Optional, Union
from web3 import WebsocketProvider

import requests
from ocean_lib.assets.asset import Asset
from ocean_lib.models.data_token import DataToken
from ocean_lib.web3_internal.wallet import Wallet
from ocean_provider.http_provider import CustomHTTPProvider
from requests_testadapter import Resp

import artifacts
from ocean_provider.config import Config
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


def get_provider_wallet(web3: Optional[Web3] = None) -> Wallet:
    """
    :return: Wallet instance
    """
    if web3 is None:
        web3 = get_web3()

    pk = os.environ.get("PROVIDER_PRIVATE_KEY")
    wallet = Wallet(web3, private_key=pk)

    if wallet is None:
        raise AssertionError(
            f"Ocean Provider cannot run without a valid "
            f"ethereum account. `PROVIDER_PRIVATE_KEY` was not found in the environment "
            f"variables. \nENV WAS: {sorted(os.environ.items())}"
        )

    if not wallet.private_key:
        raise AssertionError(
            "Ocean Provider cannot run without a valid ethereum private key."
        )

    return wallet


def get_datatoken_minter(datatoken_address):
    """
    :return: Eth account address of the Datatoken minter
    """
    dt = DataToken(get_web3(), datatoken_address)
    publisher = dt.minter()
    return publisher


def get_artifacts_path():
    """
    :return: Path to the artifact directory
    """
    return Path(artifacts.__file__).parent.expanduser().resolve()


def get_web3(network_url: Optional[str] = None) -> Web3:
    """
    :return: `Web3` instance
    """
    if network_url is None:
        network_url = get_config().network_url

    web3 = Web3(provider=get_web3_connection_provider(network_url))

    if network_url.startswith("wss"):
        from web3.middleware import geth_poa_middleware

        web3.middleware_onion.inject(geth_poa_middleware, layer=0)

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


def get_asset_from_metadatastore(metadata_url, document_id):
    """
    :return: `Ddo` instance
    """
    url = f"{metadata_url}/api/v1/aquarius/assets/ddo/{document_id}"
    response = requests.get(url)

    return Asset(dictionary=response.json()) if response.status_code == 200 else None
