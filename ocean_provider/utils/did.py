import re
from typing import Dict


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
