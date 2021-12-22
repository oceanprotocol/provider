#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
from pathlib import Path
from typing import Any, Dict, Union
from web3.main import Web3
from eth_typing.evm import HexAddress


def get_address_json(address_path: Union[str, Path]) -> Dict[str, Any]:
    """Return the json object of all Ocean contract addresses on all chains."""
    if isinstance(address_path, str):
        address_path = Path(address_path)
    address_file = address_path.expanduser().resolve()
    with open(address_file) as f:
        return json.load(f)


def get_contract_address(
    address_path: str, contract_name: str, chain_id: int
) -> HexAddress:
    """Return the contract address with the given name and chain id"""
    address_json = get_address_json(address_path)
    return next(
        chain_addresses[contract_name]
        for chain_addresses in address_json.values()
        if chain_addresses["chainId"] == chain_id
    )
