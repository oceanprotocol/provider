import re
from hashlib import sha256
from typing import Dict

from eth_typing.encoding import HexStr
from eth_typing.evm import HexAddress
from web3.main import Web3


def compute_did_from_data_nft_address_and_chain_id(
    data_nft_address: HexAddress, chain_id: int
) -> HexStr:
    return Web3.toHex(
        sha256((data_nft_address + str(chain_id)).encode("utf-8")).digest()
    )


def did_to_id(did: str) -> str:
    """Return an id extracted from a DID string."""
    result = did_parse(did)
    return result["id"] if result and (result["id"] is not None) else None


def did_parse(did: str) -> Dict[str, str]:
    if not isinstance(did, str):
        raise TypeError(f"Expecting DID of string type, got {did} of {type(did)} type")

    match = re.match("^did:([a-z0-9]+):([a-zA-Z0-9-.]+)(.*)", did)
    if not match:
        raise ValueError(f"DID {did} does not seem to be valid.")

    result = {"method": match.group(1), "id": match.group(2)}

    return result
