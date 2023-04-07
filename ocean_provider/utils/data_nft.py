#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
from enum import IntEnum, IntFlag
from typing import Iterable, Optional, Tuple

from ocean_provider.utils.address import get_contract_definition
from web3.contract import Contract
from web3.logs import DISCARD
from web3.main import Web3
from web3.types import EventData, TxReceipt

logger = logging.getLogger(__name__)


class MetadataState(IntEnum):
    ACTIVE = 0
    END_OF_LIFE = 1
    DEPRECATED = 2
    REVOKED = 3
    TEMPORARILY_DISABLED = 4
    UNLISTED = 5


class Flags(IntFlag):
    PLAIN = 0
    COMPRESSED = 1
    ENCRYPTED = 2

    def to_byte(self):
        return self.to_bytes(1, "big")


def get_data_nft_contract(web3: Web3, address: Optional[str] = None) -> Contract:
    """
    Build a web3 Contract instance using the Ocean Protocol ERC721Template ABI.

    This function assumes that the standard `ERC721Template` stored at index 1
    of the `ERC721Factory` provides all the functionality needed by Provider,
    especially the `getMetaData` contract method.
    """
    abi = get_contract_definition("ERC721Template")["abi"]
    return web3.eth.contract(address=address, abi=abi)


def get_metadata(web3: Web3, address: str) -> Tuple[str, str, MetadataState, bool]:
    """Queries the ERC721 Template smart contract getMetaData call.
    Returns metaDataDecryptorUrl, metaDataDecryptorAddress, metaDataState, and hasMetaData"""
    data_nft_contract = get_data_nft_contract(web3, address)

    return data_nft_contract.caller.getMetaData()


def get_metadata_logs_from_tx_receipt(
    web3: Web3, tx_receipt: TxReceipt, data_nft_address
) -> Iterable[EventData]:
    """Selects MetadataCreated or MetadataUpdated log based on tx receipt."""
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    logs = data_nft_contract.events.MetadataCreated().processReceipt(
        tx_receipt, errors=DISCARD
    )
    if not logs:
        logs = data_nft_contract.events.MetadataUpdated().processReceipt(
            tx_receipt, errors=DISCARD
        )
    if not logs:
        raise ValueError(
            f"MetadataCreated/MetadataUpdated event not found "
            f"in tx id: {tx_receipt.transactionHash}"
        )
    if len(logs) > 1:
        logger.warning(
            f"More than 1 MetadataCreated/MetadataUpdated event found"
            f"in tx id: {tx_receipt.transactionHash}"
        )
    return logs
