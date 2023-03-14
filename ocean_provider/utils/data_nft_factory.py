#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import os

from ocean_provider.utils.address import get_contract_address, get_contract_definition
from web3.contract import Contract
from web3.main import Web3


def get_data_nft_factory_address(web3: Web3) -> str:
    return get_contract_address(
        os.getenv("ADDRESS_FILE"), "ERC721Factory", web3.chain_id
    )


def get_data_nft_factory_contract(web3: Web3) -> Contract:
    abi = get_contract_definition("ERC721Factory")["abi"]
    data_nft_factory_address = get_data_nft_factory_address(web3)
    return web3.eth.contract(
        address=web3.toChecksumAddress(data_nft_factory_address), abi=abi
    )


def is_nft_deployed_from_factory(web3: Web3, nft_address: str) -> bool:
    """Check if NFT is deployed from the factory."""
    data_nft_factory = get_data_nft_factory_contract(web3)
    return data_nft_factory.caller.erc721List(nft_address) == nft_address
