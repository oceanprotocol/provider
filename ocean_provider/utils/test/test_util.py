#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from copy import deepcopy
import json
import logging
import mimetypes
import pytest
from unittest.mock import MagicMock, Mock, patch

import ipfshttpclient
from web3.main import Web3
from werkzeug.utils import get_content_type

from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.encryption import do_encrypt
from ocean_provider.utils.services import Service
from ocean_provider.utils.util import (
    build_download_response,
    get_download_url,
    get_service_files_list,
    msg_hash,
    validate_url_object,
)

test_logger = logging.getLogger(__name__)


@pytest.mark.unit
def test_msg_hash():
    msg = "Hello World!"
    hashed = msg_hash(msg)
    expected = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    assert hashed == expected


@pytest.mark.unit
def test_build_download_response():
    request = Mock()
    request.range = None

    class Dummy:
        pass

    mocked_response = Dummy()
    mocked_response.content = b"asdsadf"
    mocked_response.status_code = 200
    mocked_response.headers = {}

    requests_session = Dummy()
    requests_session.get = MagicMock(return_value=mocked_response)

    filename = "<<filename>>.xml"
    content_type = mimetypes.guess_type(filename)[0]
    url = f"https://source-lllllll.cccc/{filename}"
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(request, requests_session, url, url, None)

    assert response.headers["content-type"] == content_type
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )

    filename = "<<filename>>"
    url = f"https://source-lllllll.cccc/{filename}"
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(request, requests_session, url, url, None)
    assert response.headers["content-type"] == get_content_type(
        response.default_mimetype, response.charset
    )
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )

    filename = "<<filename>>"
    url = f"https://source-lllllll.cccc/{filename}"
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(
            request, requests_session, url, url, content_type
        )
    assert response.headers["content-type"] == content_type

    matched_cd = (
        f"attachment;filename={filename + mimetypes.guess_extension(content_type)}"
    )
    assert response.headers.get_all("Content-Disposition")[0] == matched_cd

    mocked_response_with_attachment = deepcopy(mocked_response)
    attachment_file_name = "test.xml"
    mocked_response_with_attachment.headers = {
        "content-disposition": f"attachment;filename={attachment_file_name}"
    }

    requests_session_with_attachment = Dummy()
    requests_session_with_attachment.get = MagicMock(
        return_value=mocked_response_with_attachment
    )

    url = "https://source-lllllll.cccc/not-a-filename"
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(
            request, requests_session_with_attachment, url, url, None
        )
    assert (
        response.headers["content-type"]
        == mimetypes.guess_type(attachment_file_name)[0]
    )  # noqa

    matched_cd = f"attachment;filename={attachment_file_name}"
    assert response.headers.get_all("Content-Disposition")[0] == matched_cd

    mocked_response_with_content_type = deepcopy(mocked_response)
    response_content_type = "text/csv"
    mocked_response_with_content_type.headers = {"content-type": response_content_type}

    requests_session_with_content_type = Dummy()
    requests_session_with_content_type.get = MagicMock(
        return_value=mocked_response_with_content_type
    )

    filename = "filename.txt"
    url = f"https://source-lllllll.cccc/{filename}"
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(
            request, requests_session_with_content_type, url, url, None
        )
    assert response.headers["content-type"] == response_content_type
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )


@pytest.mark.unit
def test_download_ipfs_file():
    client = ipfshttpclient.connect("/dns/172.15.0.16/tcp/5001/http")
    cid = client.add("./tests/resources/ddo_sample_file.txt")["Hash"]
    url_object = {"type": "ipfs", "hash": cid}
    download_url = get_download_url(url_object)
    requests_session = get_requests_session()

    request = Mock()
    request.range = None

    print(f"got ipfs download url: {download_url}")
    assert download_url and download_url.endswith(f"ipfs/{cid}")
    response = build_download_response(
        request, requests_session, download_url, download_url, None
    )
    assert response.data, f"got no data {response.data}"


@pytest.mark.unit
def test_get_service_files_list(provider_wallet):
    service = Mock(template=Service)
    encrypted_files_str = json.dumps(["test1", "test2"], separators=(",", ":"))
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )
    assert ["test1", "test2"] == get_service_files_list(service, provider_wallet)

    # empty and raw
    service.encrypted_files = ""
    assert get_service_files_list(service, provider_wallet) is None

    # empty and encrypted
    encrypted_files_str = ""
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )
    assert get_service_files_list(service, provider_wallet) is None

    # not a list
    encrypted_files_str = json.dumps({"test": "test"}, separators=(",", ":"))
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )

    assert get_service_files_list(service, provider_wallet) is None


@pytest.mark.unit
def test_validate_url_object():
    result, message = validate_url_object({}, 1)
    assert result is False
    assert message == "cannot decrypt files for this service. id=1"

    result, message = validate_url_object({"type": "not_ipfs_or_url"}, 1)
    assert result is False
    assert message == "malformed or unsupported type for service files. id=1"

    result, message = validate_url_object({"type": "ipfs", "but_hash": "missing"}, 1)
    assert result is False
    assert message == "malformed service files, missing required keys. id=1"
