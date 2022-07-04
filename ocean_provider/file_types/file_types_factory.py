import logging
from typing import Any, Tuple

from enforce_typing import enforce_types

from ocean_provider.file_types.file_types import IpfsFile, UrlFile

logger = logging.getLogger(__name__)


@enforce_types
class FilesTypeFactory:
    """Factory Method"""

    @staticmethod
    def validate_and_create(file_obj) -> Tuple[bool, Any]:
        if not file_obj:
            return False, "cannot decrypt files for this service."

        if "type" not in file_obj or file_obj["type"] not in ["ipfs", "url"]:
            return (
                False,
                "malformed or unsupported type for service files.",
            )

        try:
            if file_obj["type"] == "url":
                instance = UrlFile(
                    file_obj.get("url"),
                    method=file_obj.get("method"),
                    headers=file_obj.get("headers"),
                    userdata=file_obj.get("userdata"),
                )
            else:
                instance = IpfsFile(
                    file_obj.get("hash"),
                    headers=file_obj.get("headers"),
                    userdata=file_obj.get("userdata"),
                )
        except TypeError:
            return False, "malformed or unsupported types."

        return instance.validate_dict()
