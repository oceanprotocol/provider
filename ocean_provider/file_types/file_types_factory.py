import logging
from typing import Any, Tuple

from enforce_typing import enforce_types

from ocean_provider.file_types.file_types import (
    ArweaveFile,
    IpfsFile,
    UrlFile,
    GraphqlQuery,
)
from ocean_provider.file_types.types.smartcontract import SmartContractCall

logger = logging.getLogger(__name__)


@enforce_types
class FilesTypeFactory:
    """Factory Method"""

    @staticmethod
    def validate_and_create(file_obj) -> Tuple[bool, Any]:
        if not file_obj:
            return False, "cannot decrypt files for this service."

        try:
            if file_obj["type"] == "url":
                instance = UrlFile(
                    file_obj.get("url"),
                    method=file_obj.get("method"),
                    headers=file_obj.get("headers"),
                    userdata=file_obj.get("userdata"),
                )
            elif file_obj["type"] == "arweave":
                instance = ArweaveFile(
                    file_obj.get("transactionId"),
                    headers=file_obj.get("headers"),
                    userdata=file_obj.get("userdata"),
                )
            elif file_obj["type"] == "ipfs":
                instance = IpfsFile(
                    file_obj.get("hash"),
                    headers=file_obj.get("headers"),
                    userdata=file_obj.get("userdata"),
                )
            elif file_obj["type"] == "graphql":
                instance = GraphqlQuery(
                    url=file_obj.get("url"),
                    query=file_obj.get("query"),
                    headers=file_obj.get("headers"),
                    userdata=file_obj.get("userdata"),
                )
            elif file_obj["type"] == "smartcontract":
                instance = SmartContractCall(
                    address=file_obj.get("address"),
                    abi=file_obj.get("abi"),
                    userdata=file_obj.get("userdata"),
                )
            else:
                return False, f'Unsupported type {file_obj["type"]}'
        except TypeError:
            return False, "malformed file object."

        return instance.validate_dict()
