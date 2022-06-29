from abc import abstractmethod
from cgi import parse_header
from flask import Response
import hashlib
import json
import logging
import mimetypes
import os
import requests
from typing import Any, Optional, Protocol, Tuple
from urllib.parse import urljoin

from enforce_typing import enforce_types

from ocean_provider.utils.url import is_safe_url

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 3
CHUNK_SIZE = 8192


class FilesType(Protocol):
    @enforce_types
    @abstractmethod
    def validate_dict(url_object) -> Tuple[bool, str]:
        raise NotImplementedError

    @abstractmethod
    def check_details(self, with_checksum=False):
        raise NotImplementedError

    # TODO: build_download_response?


class EndUrlType:
    def check_details(self, with_checksum=False):
        """
        If the url argument is invalid, returns False and empty dictionary.
        Otherwise it returns True and a dictionary containing contentType and
        contentLength. If the with_checksum flag is set to True, it also returns
        the file checksum and the checksumType (currently hardcoded to sha256)
        """
        url = self.get_download_url()
        try:
            if not is_safe_url(url):
                return False, {}

            for _ in range(int(os.getenv("REQUEST_RETRIES", 1))):
                result, extra_data = self._get_result_from_url(
                    with_checksum=with_checksum,
                )
                if result and result.status_code == 200:
                    break

            if result.status_code == 200:
                content_type = result.headers.get("Content-Type")
                content_length = result.headers.get("Content-Length")
                content_range = result.headers.get("Content-Range")

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

                if content_type or content_length:
                    details = {
                        "contentLength": content_length or "",
                        "contentType": content_type or "",
                    }

                    if extra_data:
                        details.update(extra_data)

                    self.checked_details = details
                    return True, details
        except requests.exceptions.RequestException:
            pass

        return False, {}

    def _get_result_from_url(self, with_checksum=False):
        url = self.get_download_url()

        lightweight_methods = [] if self.method == "post" else ["head", "options"]
        heavyweight_method = self.method

        for method in lightweight_methods:
            func = getattr(requests, method)
            result = func(
                url,
                timeout=REQUEST_TIMEOUT,
                headers=self.headers,
                params=self.format_userdata(),
            )

            if (
                not with_checksum
                and result.status_code == 200
                and (
                    result.headers.get("Content-Type")
                    or result.headers.get("Content-Range")
                )
                and result.headers.get("Content-Length")
            ):
                return result, {}

        func = getattr(requests, heavyweight_method)
        func_args = {"url": url, "stream": True, "headers": self.headers}

        if self.userdata:
            if heavyweight_method != "post":
                func_args["params"] = self.format_userdata()
            else:
                func_args["json"] = self.format_userdata()

        if not with_checksum:
            # fallback on GET request
            func_args["timeout"] = REQUEST_TIMEOUT
            return func(**func_args), {}

        sha = hashlib.sha256()

        with func(**func_args) as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                sha.update(chunk)

        return r, {"checksum": sha.hexdigest(), "checksumType": "sha256"}

    def format_userdata(self):
        if not self.userdata:
            return None

        if not isinstance(self.userdata, dict):
            try:
                return json.loads(self.userdata)
            except json.decoder.JSONDecodeError:
                logger.info(
                    "Can not decode sent userdata for asset, sending without extra parameters."
                )
                return {}

        return self.userdata

    def build_download_response(
        self,
        request,
        requests_session,
        validate_url=True,
    ):
        url = self.get_download_url()
        content_type = (
            self.checked_details.get("contentType")
            if hasattr(self, "checked_details")
            else None
        )

        try:
            if validate_url and not is_safe_url(url):
                raise ValueError(f"Unsafe url {url}")
            download_request_headers = {}
            download_response_headers = {}
            is_range_request = bool(request.range)

            if is_range_request:
                download_request_headers = {"Range": request.headers.get("range")}
                download_response_headers = download_request_headers

            download_request_headers.update(self.headers)

            func_method = getattr(requests_session, self.method)
            func_args = {
                "url": url,
                "headers": download_request_headers,
                "stream": True,
                "timeout": 3,
            }

            if self.userdata:
                if self.method.lower() != "post":
                    func_args["params"] = self.format_userdata()
                else:
                    func_args["json"] = self.format_userdata()

            response = func_method(**func_args)
            if not is_range_request:
                filename = url.split("/")[-1]

                content_disposition_header = response.headers.get("content-disposition")
                if content_disposition_header:
                    _, content_disposition_params = parse_header(
                        content_disposition_header
                    )
                    content_filename = content_disposition_params.get("filename")
                    if content_filename:
                        filename = content_filename

                content_type_header = response.headers.get("content-type")
                if content_type_header:
                    content_type = content_type_header

                file_ext = os.path.splitext(filename)[1]
                if file_ext and not content_type:
                    content_type = mimetypes.guess_type(filename)[0]
                elif not file_ext and content_type:
                    # add an extension to filename based on the content_type
                    extension = mimetypes.guess_extension(content_type)
                    if extension:
                        filename = filename + extension

                download_response_headers = {
                    "Content-Disposition": f"attachment;filename={filename}",
                    "Access-Control-Expose-Headers": "Content-Disposition",
                    "Connection": "close",
                }

            return Response(
                _generate(response),
                response.status_code,
                headers=download_response_headers,
                content_type=content_type,
            )
        except Exception as e:
            logger.error(f"Error preparing file download response: {str(e)}")
            raise


def _generate(_response):
    for chunk in _response.iter_content(chunk_size=4096):
        if chunk:
            yield chunk


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
