import copy
import hashlib
import json
import logging
import mimetypes
import os
from abc import abstractmethod
from cgi import parse_header
from typing import Protocol, Tuple
from urllib.parse import urlparse

import requests
from enforce_typing import enforce_types
from flask import Response
from ocean_provider.utils.url import is_safe_url

logger = logging.getLogger(__name__)

CHUNK_SIZE = 8192


class FilesType(Protocol):
    @enforce_types
    @abstractmethod
    def validate_dict(self) -> Tuple[bool, str]:
        raise NotImplementedError

    @abstractmethod
    def check_details(self, with_checksum=False):
        raise NotImplementedError

    @abstractmethod
    def build_download_response(
        self,
        request,
        validate_url=True,
    ):
        raise NotImplementedError


class EndUrlType:
    @abstractmethod
    def get_download_url(self):
        raise NotImplementedError

    @enforce_types
    @abstractmethod
    def get_filename(self):
        raise NotImplementedError

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
                    files_url = copy.deepcopy(result.url)
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

    def _get_result_from_url(self, with_checksum=False):
        func, func_args = self._get_func_and_args()

        # overwrite checksum flag if file is too large
        if with_checksum:
            max_length = int(os.getenv("MAX_CHECKSUM_LENGTH", "0"))
            with func(**func_args) as r:
                length = 0
                try:
                    length = int(r.headers.get("Content-Length", "0"))
                except Exception as e:
                    logger.warning(
                        f"Failed to parse Content-Length header {r.headers} {e}"
                    )
                logger.debug(f"File size {length} > {max_length}")
                if length > max_length:
                    # file size too large, bail out
                    logger.debug(
                        f"File size {length} > {max_length}, forcing with_checksum=False"
                    )
                    with_checksum = False

        if not with_checksum:
            return func(**func_args), {}

        sha = hashlib.sha256()
        done_bytes = 0
        with func(**func_args) as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                sha.update(chunk)
                done_bytes += len(chunk)
                # too much bytes already for hash, bail out
                if done_bytes > max_length:
                    logger.debug(f"Already done {done_bytes} of hash, bail out")
                    return r, {}
        return r, {"checksum": sha.hexdigest(), "checksumType": "sha256"}

    def _get_func_and_args(self):
        url = self.get_download_url()
        func = getattr(requests, self.method)
        func_args = {
            "url": url,
            "stream": True,
            "headers": self.headers,
            "timeout": int(os.getenv("REQUEST_TIMEOUT", 10)),
        }

        if self.userdata:
            if self.method != "post":
                func_args["params"] = self.format_userdata()
            else:
                func_args["json"] = self.format_userdata()

        return func, func_args

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

            download_response_headers = {}
            is_range_request = bool(request.range)

            if is_range_request and "Range" not in self.headers:
                # if headers exist in the DDO, they should stay put
                self.headers["Range"] = request.headers.get("Range")

            if "Range" in self.headers:
                download_response_headers = {"Range": self.headers.get("Range")}
                is_range_request = True

            func_method, func_args = self._get_func_and_args()

            response = func_method(**func_args)
            if not is_range_request:
                filename = self.get_filename()

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
