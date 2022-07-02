import logging
import os
from typing import Any, Optional, Tuple
from urllib.parse import urljoin

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
        self.gateway = os.getenv("IPFS_GATEWAY")
        self.url = self.get_download_url()

    @enforce_types
    def validate_dict(self) -> Tuple[bool, Any]:
        if not self.hash:
            return False, "malformed service files, missing required keys."

        return True, self

    def get_download_url(self):
        if not self.gateway:
            raise Exception("No IPFS_GATEWAY defined, can not resolve ipfs hash.")

        if self.gateway == "https://api.web3.storage/upload":
            url = f"https://{self.hash}.ipfs.dweb.link"
        elif self.gateway in ["https://api.estuary.tech/content/add", "https://shuttle-5.estuary.tech/content/add"]:
            url = f'https://dweb.link/ipfs/{cid}'
        else:
            url = urljoin(os.getenv("IPFS_GATEWAY"), urljoin("ipfs/", self.hash))

        return url

