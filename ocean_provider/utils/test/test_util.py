#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import ipfshttpclient
import copy
import json
import logging
import mimetypes
import pytest
from unittest.mock import MagicMock, Mock, patch

from web3.main import Web3
from werkzeug.utils import get_content_type

from copy import deepcopy
from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.asset import Asset
from ocean_provider.utils.encryption import do_encrypt
from ocean_provider.utils.services import Service
from ocean_provider.utils.util import (
    build_download_response,
    get_download_url,
    get_service_files_list,
    get_service_files_list_old_structure,
    msg_hash,
    validate_url_object,
)
from tests.ddo.ddo_sample1_v4 import json_dict as ddo_sample1_v4

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
    url_object = {"url": f"https://source-lllllll.cccc/{filename}", "type": "url"}
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(request, requests_session, url_object, None)

    assert response.headers["content-type"] == content_type
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )

    filename = "<<filename>>"
    url_object = {"url": f"https://source-lllllll.cccc/{filename}", "type": "url"}
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(request, requests_session, url_object, None)
    assert response.headers["content-type"] == get_content_type(
        response.default_mimetype, response.charset
    )
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )

    filename = "<<filename>>"
    url_object = {"url": f"https://source-lllllll.cccc/{filename}", "type": "url"}
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(
            request, requests_session, url_object, content_type
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

    url_object = {"url": "https://source-lllllll.cccc/not-a-filename", "type": "url"}
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(
            request, requests_session_with_attachment, url_object, None
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
    url_object = {
        "url": f"https://source-lllllll.cccc/{filename}",
        "type": "url",
        "headers": {"APIKEY": "sample"},
    }
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        response = build_download_response(
            request, requests_session_with_content_type, url_object, None
        )
    assert response.headers["content-type"] == response_content_type
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )

    filename = "filename.txt"
    url_object = {
        "url": f"https://source-lllllll.cccc/{filename}",
        "type": "url",
        "method": "DELETE",
    }
    with patch(
        "ocean_provider.utils.util.is_safe_url",
        side_effect=[True],
    ):
        with pytest.raises(ValueError, match="Unsafe method DELETE"):
            response = build_download_response(
                request, requests_session_with_content_type, url_object
            )


@pytest.mark.unit
def test_get_service_files_list(provider_wallet):
    ddo_sample1 = copy.deepcopy(ddo_sample1_v4)
    ddo = Asset(ddo_sample1)
    service = Mock(template=Service)
    service.datatoken_address = "0x0000000000000000000000000000000000000000"
    service.type = "access"

    encrypted_files_str = json.dumps(
        {
            "nftAddress": "0x0000000000000000000000000000000000000000",
            "datatokenAddress": "0x0000000000000000000000000000000000000000",
            "files": ["test1", "test2"],
        },
        separators=(",", ":"),
    )
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )
    assert ["test1", "test2"] == get_service_files_list(service, provider_wallet, ddo)

    # empty and raw
    service.encrypted_files = ""
    assert get_service_files_list(service, provider_wallet, ddo) is None

    # empty and encrypted
    encrypted_files_str = ""
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )
    assert get_service_files_list(service, provider_wallet, ddo) is None

    # not a dict
    encrypted_files_str = json.dumps([], separators=(",", ":"))
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )

    assert get_service_files_list(service, provider_wallet, ddo) is None

    # files not a list
    encrypted_files_str = json.dumps(
        {
            "nftAddress": "0x0000000000000000000000000000000000000000",
            "datatokenAddress": "0x0000000000000000000000000000000000000000",
            "files": {"some_dict": "test"},
        },
        separators=(",", ":"),
    )
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )

    assert get_service_files_list(service, provider_wallet, ddo) is None

    # missing nftAddress
    encrypted_files_str = json.dumps(
        {
            "datatokenAddress": "0x0000000000000000000000000000000000000000",
            "files": {"some_dict": "test"},
        },
        separators=(",", ":"),
    )
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )

    assert get_service_files_list(service, provider_wallet, ddo) is None

    # wrong nftAddress
    encrypted_files_str = json.dumps(
        {
            "nftAddress": "0x0000000000000000000000000000000000000001",
            "datatokenAddress": "0x0000000000000000000000000000000000000000",
            "files": {"some_dict": "test"},
        },
        separators=(",", ":"),
    )
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )

    assert get_service_files_list(service, provider_wallet, ddo) is None


@pytest.mark.unit
def test_get_service_files_list_old_structure(provider_wallet):
    service = Mock(template=Service)
    encrypted_files_str = json.dumps(["test1", "test2"], separators=(",", ":"))
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )
    assert ["test1", "test2"] == get_service_files_list_old_structure(
        service, provider_wallet
    )

    # empty and raw
    service.encrypted_files = ""
    assert get_service_files_list(service, provider_wallet) is None

    # empty and encrypted
    encrypted_files_str = ""
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )
    assert get_service_files_list_old_structure(service, provider_wallet) is None

    # not a list
    encrypted_files_str = json.dumps({"test": "test"}, separators=(",", ":"))
    service.encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), provider_wallet
    )

    assert get_service_files_list_old_structure(service, provider_wallet) is None


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

    result, message = validate_url_object(
        {"type": "url", "url": "x", "headers": "not_a_dict"}, 1
    )
    assert result is False
    assert message == "malformed or unsupported type for headers. id=1"

    result, message = validate_url_object(
        {"type": "url", "url": "x", "headers": '{"dict": "but_stringified"}'}, 1
    )
    # we purposefully require a dictionary
    assert result is False
    assert message == "malformed or unsupported type for headers. id=1"

    result, message = validate_url_object(
        {"type": "url", "url": "x", "headers": {"dict": "dict_key"}}, 1
    )
    assert result is True


@pytest.mark.unit
def test_download_ipfs_file():
    client = ipfshttpclient.connect("/dns/172.15.0.16/tcp/5001/http")
    cid = client.add("./tests/resources/ddo_sample_file.txt")["Hash"]
    url_object = {"type": "ipfs", "hash": cid}
    requests_session = get_requests_session()

    request = Mock()
    request.range = None

    download_url = get_download_url(url_object)
    print(f"got ipfs download url: {download_url}")
    assert download_url and download_url.endswith(f"ipfs/{cid}")

    response = build_download_response(request, requests_session, url_object, None)
    assert response.data, f"got no data {response.data}"
