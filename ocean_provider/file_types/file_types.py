import json
import logging
import os
import re
import copy
from typing import Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
from uuid import uuid4

from enforce_typing import enforce_types
from ocean_provider.file_types.definitions import EndUrlType, FilesType
import requests
from ocean_provider.utils.url import is_safe_url

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

        if not self.validate_url(self.url):
            msg = "Invalid file name format. It was not possible to get the file name."
            logger.error(msg)
            return False, msg

        return True, self

    def get_download_url(self):
        return self.url

    def validate_url(self, url: str) -> bool:
        pattern = re.compile(r"^(.+)\/([^/]+)$")
        if url.startswith("http://") or url.startswith("https://"):
            return True
        return not bool(pattern.findall(url))

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

    def check_details(self, with_checksum=False):
        """
        If the url argument is invalid, returns False and empty dictionary.
        Otherwise it returns True and a dictionary containing contentType and
        contentLength. File name remains empty.
        """

        url = self.get_download_url()

        try:
            if not is_safe_url(url):
                return False, {}
            status_code = None
            headers = None
            files_url = None
            for _ in range(int(os.getenv("REQUEST_RETRIES", 1))):
                result, extra_data = self._get_result_from_url(
                    with_checksum=with_checksum,
                )
                if result:
                    status_code = result.status_code
                    headers = copy.deepcopy(result.headers)
                    files_url = ""
                    # always close requests session, see https://requests.readthedocs.io/en/latest/user/advanced/#body-content-workflow
                    result.close()
                    if status_code == 200:
                        break

            if status_code == 200:
                content_type = headers.get("Content-Type")
                content_length = headers.get("Content-Length")
                content_range = headers.get("Content-Range")
                file_name = None

                if files_url:
                    file_name = urlparse(files_url).path.split("/")[-1]

                if not content_length and content_range:
                    # sometimes servers send content-range instead
                    try:
                        content_length = content_range.split("-")[1]
                    except IndexError:
                        pass

                if content_type:
                    try:
                        content_type = content_type.split(";")[0]
                    except IndexError:
                        pass

                if content_type or content_length or file_name:
                    details = {
                        "contentLength": content_length or "",
                        "contentType": content_type or "",
                        "filename": file_name or "",
                    }

                    if extra_data:
                        details.update(extra_data)

                    self.checked_details = details
                    return True, details
        except requests.exceptions.RequestException:
            pass

        return False, {}


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
        self.query = query
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
        if not self.query:
            return False, "missing graphql query"

        return True, self

    def get_download_url(self):
        return self.url

    @enforce_types
    def get_filename(self):
        return uuid4().hex
