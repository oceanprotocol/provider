#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import os
from pathlib import Path
from typing import Any, Dict, Union
from eth_typing.evm import HexAddress
from ocean_provider.utils.basics import get_config

BLACK_HOLE_ADDRESS = "0x0000000000000000000000000000000000000000"


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
    print(address_json)
    print(contract_name)
    print(chain_id)
    return next(
        chain_addresses[contract_name]
        for chain_addresses in address_json.values()
        if chain_addresses["chainId"] == chain_id
    )


def get_provider_fee_token(chain_id):
    fee_token = os.environ.get("PROVIDER_FEE_TOKEN", get_ocean_address(chain_id))
    if not fee_token:
        fee_token = BLACK_HOLE_ADDRESS
    return fee_token


def get_ocean_address(chain_id):
    return get_contract_address(get_config().address_file, "Ocean", chain_id)
