import logging
import os
import json
from typing import Any, Optional, Tuple
from urllib.parse import urljoin
from uuid import uuid4

from enforce_typing import enforce_types

from ocean_provider.file_types.definitions import EndUrlType, FilesType

logger = logging.getLogger(__name__)


class UrlFile(EndUrlType, FilesType):
    @enforce_types
    def __init__(
        self,
        url: Optional[str] = None,
        method: Optional[str] = None,
        headers: Optional[dict] = None,
        userdata=None,
    ) -> None:
        self.url = url
        self.method = method.lower() if method else "get"
        self.headers = headers if headers else {}
        self.type = "url"
        self.userdata = userdata

    @enforce_types
    def validate_dict(self) -> Tuple[bool, Any]:
        if not self.url:
            return False, "malformed service files, missing required keys."

        if self.method not in ["get", "post"]:
            return False, f"Unsafe method {self.method}."

        return True, self

    def get_download_url(self):
        return self.url

    @enforce_types
    def get_filename(self) -> str:
        return self.url.split("/")[-1]


class IpfsFile(EndUrlType, FilesType):
    @enforce_types
    def __init__(
        self, hash: Optional[str] = None, headers: Optional[dict] = None, userdata=None
    ) -> None:
        self.hash = hash
        self.type = "ipfs"
        self.headers = headers if headers else {}
        self.userdata = userdata
        self.method = "get"

    @enforce_types
    def validate_dict(self) -> Tuple[bool, Any]:
        if not self.hash:
            return False, "malformed service files, missing required keys."

        return True, self

    def get_download_url(self):
        if not os.getenv("IPFS_GATEWAY"):
            raise Exception("No IPFS_GATEWAY defined, can not resolve ipfs hash.")

        return urljoin(os.getenv("IPFS_GATEWAY"), urljoin("ipfs/", self.hash))

    @enforce_types
    def get_filename(self):
        return uuid4().hex


class ArweaveFile(EndUrlType, FilesType):
    @enforce_types
    def __init__(
        self,
        transactionId: Optional[str] = None,
        headers: Optional[dict] = None,
        userdata=None,
    ) -> None:
        self.transactionId = transactionId
        self.type = "arweave"
        self.headers = headers if headers else {}
        self.userdata = userdata
        self.method = "get"

    @enforce_types
    def validate_dict(self) -> Tuple[bool, Any]:
        if not self.transactionId:
            return False, "malformed service files, missing transactionId."

        return True, self

    def get_download_url(self):
        if not os.getenv("ARWEAVE_GATEWAY"):
            raise Exception(
                "No ARWEAVE_GATEWAY defined, can not resolve arweave transaction id."
            )

        return urljoin(os.getenv("ARWEAVE_GATEWAY"), self.transactionId)

    @enforce_types
    def get_filename(self):
        return uuid4().hex


class GraphqlQuery(EndUrlType, FilesType):
    @enforce_types
    def __init__(
        self,
        url: Optional[str] = None,
        query=None,
        headers: Optional[dict] = None,
        userdata=None,
    ) -> None:
        self.url = url
        self.userdata = {"query": query}
        if userdata:
            self.userdata["variables"] = (
                userdata if isinstance(userdata, dict) else json.loads(userdata)
            )

        self.method = "post"
        self.headers = headers if headers else {}
        self.type = "graphql"

    @enforce_types
    def validate_dict(self) -> Tuple[bool, Any]:
        if not self.url:
            return False, "missing graphql endpoint"

        return True, self

    def get_download_url(self):
        return self.url

    @enforce_types
    def get_filename(self):
        return uuid4().hex
