#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import os
from pathlib import Path
from typing import Any, Dict, Union

import addresses
import artifacts
from eth_typing.evm import HexAddress

BLACK_HOLE_ADDRESS = "0x0000000000000000000000000000000000000000"


def get_address_json(address_path: Union[str, Path]) -> Dict[str, Any]:
    """Return the json object of all Ocean contract addresses on all chains."""
    if isinstance(address_path, str):
        address_path = Path(address_path)
    else:
        address_path = Path(os.path.join(addresses.__file__, "..", "address.json"))
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


def get_contract_definition(contract_name: str) -> Dict[str, Any]:
    """Returns the abi JSON for a contract name."""
    path = os.path.join(artifacts.__file__, "..", f"{contract_name}.json")
    path = Path(path).expanduser().resolve()

    if not path.exists():
        raise TypeError("Contract name does not exist in artifacts.")

    with open(path) as f:
        return json.load(f)


def get_provider_fee_token(chain_id):
    fee_token = os.environ.get("PROVIDER_FEE_TOKEN", get_ocean_address(chain_id))
    return fee_token if fee_token else BLACK_HOLE_ADDRESS


def get_ocean_address(chain_id):
    return get_contract_address(os.getenv("ADDRESS_FILE"), "Ocean", chain_id)
