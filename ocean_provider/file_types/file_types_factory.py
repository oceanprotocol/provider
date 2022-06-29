from abc import abstractmethod
from typing import Any, Optional, Protocol

from enforce_typing import enforce_types


class FilesType(Protocol):
    @enforce_types
    @abstractmethod
    def validate_dict(url_object) -> tuple[bool, str]:
        raise NotImplementedError


class UrlFile(FilesType):
    @enforce_types
    def __init__(
        self, url: Optional[str] = None, method: Optional[str] = None, headers: Optional[dict] = None
    ) -> None:
        self.url = url
        self.method = method.lower() if method else "get"
        self.headers = headers if headers else {}
        self.type = "url"

    @enforce_types
    def validate_dict(self) -> tuple[bool, str]:
        if not self.url:
            return False, "malformed service files, missing required keys."

        if self.method not in ["get", "post"]:
            return False, f"Unsafe method {self.method}"

        return True, self


class IpfsFile(FilesType):
    @enforce_types
    def __init__(self, hash: Optional[str] = None) -> None:
        self.hash = hash
        self.type = "ipfs"

    @enforce_types
    def validate_dict(self) -> tuple[bool, str]:
        if not self.hash:
            return False, "malformed service files, missing required keys."

        return True, ""


@enforce_types
class FilesTypeFactory:
    """Factory Method"""
    @staticmethod
    def validate_and_create(file_obj) -> tuple[bool, Any]:
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
                )
            else:
                instance = IpfsFile(file_obj.get("hash"))
        except TypeError:
            return False, "malformed or unsupported types."

        return instance.validate_dict()

