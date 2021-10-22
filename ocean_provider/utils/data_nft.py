#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from enum import Enum
from typing import Tuple

from jsonsempai import magic  # noqa: F401
from artifacts.contracts.templates.ERC721Template_sol import ERC721Template
from web3.contract import Contract
from web3.logs import DISCARD
from web3.main import Web3


class MetadataState(Enum):
    ACTIVE = 0
    END_OF_LIFE = 1
    DEPRECATED = 2
    REVOKED = 3


def get_data_nft_contract(web3: Web3, address: str) -> Contract:
    abi = ERC721Template.abi
    return web3.eth.contract(address=address, abi=abi)


def get_metadata(web3: Web3, address: str) -> Tuple[str, str, MetadataState, bool]:
    """Queries the ERC721 Template smart contract getMetaData call.
    Returns metaDataDecryptorUrl, metaDataDecryptorAddress, metaDataState, and hasMetaData"""
    data_nft_contract = get_data_nft_contract(web3, address)
    return data_nft_contract.caller.getMetaData()


def get_encrypted_document_and_flags_and_hash_from_tx_id(
    web3: Web3, data_nft_address: str, transaction_id: str
) -> Tuple[str, str]:
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    tx_receipt = web3.eth.get_transaction_receipt(transaction_id)
    processed_logs = data_nft_contract.events.MetadataCreated().processReceipt(
        tx_receipt, errors=DISCARD
    )
    if not processed_logs:
        processed_logs = data_nft_contract.events.MetadataUpdated().processReceipt(
            tx_receipt, errors=DISCARD
        )
    if not processed_logs:
        raise ValueError(
            f"MetadataCreated/MetadataUpdated event not found in tx id: {transaction_id}"
        )
    log_args = processed_logs[0].args
    return (log_args["data"], log_args["flags"], log_args["metaDataHash"])
