#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
from pathlib import Path

from jsonsempai import magic  # noqa: F401
from artifacts import ERC721Factory
from ocean_provider.utils.basics import get_config
from web3.contract import Contract
from web3.logs import DISCARD
from web3.main import Web3

CHAIN_ID_TO_NETWORK_NAME = {1337: "development"}


def get_data_nft_factory_address(web3: Web3) -> str:
    # TODO Get ERC721Factory address better
    return "0x06F712732acfC7Be52997C94D12A4313C83d6bB7"
    address_file = Path(get_config().address_file).expanduser().resolve()
    with open(address_file) as f:
        address_json = json.load(f)

    chain_id = web3.eth.chain_id
    network_name = CHAIN_ID_TO_NETWORK_NAME.get(chain_id)
    if not network_name:
        raise ValueError(f"Unsupported chain id: {chain_id}")

    return address_json[network_name]["v4"]["ERC721Factory"]


def get_data_nft_factory_contract(web3: Web3) -> Contract:
    abi = ERC721Factory.abi
    data_nft_factory_address = get_data_nft_factory_address(web3)
    return web3.eth.contract(address=data_nft_factory_address, abi=abi)


def get_data_nft_address_from_tx_id(web3: Web3, tx_id_nft_created: str) -> str:
    tx_receipt = web3.eth.get_transaction_receipt(tx_id_nft_created)
    data_nft_factory = get_data_nft_factory_contract(web3)
    processed_logs = data_nft_factory.events.NFTCreated().processReceipt(
        tx_receipt, errors=DISCARD
    )
    if not processed_logs:
        raise ValueError(f"NFTCreated event not found in tx id: {tx_id_nft_created}")
    return processed_logs[0].args["newTokenAddress"]
