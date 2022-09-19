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
from unittest.mock import Mock, patch

from flask import Request
from web3.main import Web3
from werkzeug.utils import get_content_type

from copy import deepcopy
from ocean_provider.file_types.file_types_factory import FilesTypeFactory
from ocean_provider.utils.asset import Asset
from ocean_provider.utils.encryption import do_encrypt
from ocean_provider.utils.services import Service
from ocean_provider.utils.util import (
    get_service_files_list,
    get_service_files_list_old_structure,
    msg_hash,
)
from tests.ddo.ddo_sample1_v4 import json_dict as ddo_sample1_v4
from tests.helpers.constants import ARWEAVE_TRANSACTION_ID

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

    filename = "<<filename>>.xml"
    content_type = mimetypes.guess_type(filename)[0]
    url_object = {"url": f"https://source-lllllll.cccc/{filename}", "type": "url"}
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    with patch(
        "ocean_provider.file_types.definitions.is_safe_url",
        side_effect=[True],
    ):
        with patch(
            "requests.get",
            side_effect=[mocked_response],
        ):
            response = instance.build_download_response(request)

    assert response.headers["content-type"] == content_type
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )

    filename = "<<filename>>"
    url_object = {"url": f"https://source-lllllll.cccc/{filename}", "type": "url"}
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    with patch(
        "ocean_provider.file_types.definitions.is_safe_url",
        side_effect=[True],
    ):
        with patch(
            "requests.get",
            side_effect=[mocked_response],
        ):
            response = instance.build_download_response(request)
    assert response.headers["content-type"] == get_content_type(
        response.default_mimetype, response.charset
    )
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )

    filename = "<<filename>>"
    url_object = {"url": f"https://source-lllllll.cccc/{filename}", "type": "url"}
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    instance.checked_details = {"contentType": content_type}
    with patch(
        "ocean_provider.file_types.definitions.is_safe_url",
        side_effect=[True],
    ):
        with patch(
            "requests.get",
            side_effect=[mocked_response],
        ):
            response = instance.build_download_response(request)
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

    url_object = {"url": "https://source-lllllll.cccc/not-a-filename", "type": "url"}
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    with patch(
        "ocean_provider.file_types.definitions.is_safe_url",
        side_effect=[True],
    ):
        with patch(
            "requests.get",
            side_effect=[mocked_response_with_attachment],
        ):
            response = instance.build_download_response(request)
    assert (
        response.headers["content-type"]
        == mimetypes.guess_type(attachment_file_name)[0]
    )  # noqa

    matched_cd = f"attachment;filename={attachment_file_name}"
    assert response.headers.get_all("Content-Disposition")[0] == matched_cd

    mocked_response_with_content_type = deepcopy(mocked_response)
    response_content_type = "text/csv"
    mocked_response_with_content_type.headers = {"content-type": response_content_type}

    filename = "filename.txt"
    url_object = {
        "url": f"https://source-lllllll.cccc/{filename}",
        "type": "url",
        "headers": {"APIKEY": "sample"},
    }
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    with patch(
        "ocean_provider.file_types.definitions.is_safe_url",
        side_effect=[True],
    ):
        with patch(
            "requests.get",
            side_effect=[mocked_response_with_content_type],
        ):
            response = instance.build_download_response(request)
    assert response.headers["content-type"] == response_content_type
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )


@pytest.mark.unit
def test_httpbin():
    request = Mock(spec=Request)
    request.range = None
    request.headers = {}

    url_object = {
        "url": "https://httpbin.org/get",
        "type": "url",
        "method": "GET",
        "userdata": {"test_param": "OCEAN value"},
    }
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    response = instance.build_download_response(request)
    assert response.json["args"] == {"test_param": "OCEAN value"}

    url_object["url"] = "https://httpbin.org/headers"
    url_object["headers"] = {"test_header": "OCEAN header", "Range": "DDO range"}
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    response = instance.build_download_response(request)
    # no request range, but DDO range exists
    assert response.headers.get("Range") == "DDO range"

    url_object["headers"] = {}
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    response = instance.build_download_response(request)
    # no request range and no DDO range
    assert response.headers.get("Range") is None

    _, instance = FilesTypeFactory.validate_and_create(url_object)
    request.range = 200
    request.headers = {"Range": "200"}
    response = instance.build_download_response(request)
    # request range and no DDO range
    assert response.headers.get("Range") == "200"

    url_object["headers"] = {"test_header": "OCEAN header", "Range": "DDO range"}
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    request.range = 200
    request.headers = {"Range": "200"}
    response = instance.build_download_response(request)
    # request range and DDO range, will favor DDO range
    assert response.headers.get("Range") == "DDO range"

    request.range = None
    request.headers = {}
    url_object = {
        "url": "https://httpbin.org/post",
        "type": "url",
        "method": "POST",
        "userdata": {"test_param": "OCEAN POST value"},
    }
    _, instance = FilesTypeFactory.validate_and_create(url_object)
    response = instance.build_download_response(request)
    assert response.json["json"]["test_param"] == "OCEAN POST value"


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
    result, message = FilesTypeFactory.validate_and_create({})
    assert result is False
    assert message == "cannot decrypt files for this service."

    result, message = FilesTypeFactory.validate_and_create({"type": "invalid"})
    assert result is False
    assert message == "Unsupported type invalid"

    result, message = FilesTypeFactory.validate_and_create(
        {"type": "ipfs", "but_hash": "missing"}
    )
    assert result is False
    assert message == "malformed service files, missing required keys."

    result, message = FilesTypeFactory.validate_and_create(
        {"type": "arweave", "but_transactionId": "missing"}
    )
    assert result is False
    assert message == "malformed service files, missing transactionId."

    result, message = FilesTypeFactory.validate_and_create(
        {"type": "url", "url": "x", "headers": "not_a_dict"}
    )
    assert result is False
    assert message == "malformed file object."

    result, message = FilesTypeFactory.validate_and_create(
        {"type": "url", "url": "x", "headers": '{"dict": "but_stringified"}'}
    )
    # we purposefully require a dictionary
    assert result is False
    assert message == "malformed file object."

    result, message = FilesTypeFactory.validate_and_create(
        {"type": "url", "url": "x", "headers": {"dict": "dict_key"}}
    )
    assert result is True

    url_object = {
        "url": "x",
        "type": "url",
        "method": "DELETE",
    }
    result, message = FilesTypeFactory.validate_and_create(url_object)
    assert result is False
    assert message == "Unsafe method delete."


@pytest.mark.unit
def test_build_download_response_ipfs():
    client = ipfshttpclient.connect("/dns/172.15.0.16/tcp/5001/http")
    cid = client.add("./tests/resources/ddo_sample_file.txt")["Hash"]
    url_object = {"type": "ipfs", "hash": cid}

    request = Mock()
    request.range = None

    _, instance = FilesTypeFactory.validate_and_create(url_object)
    download_url = instance.get_download_url()
    print(f"got ipfs download url: {download_url}")
    assert download_url and download_url.endswith(f"ipfs/{cid}")

    response = instance.build_download_response(request)
    assert response.data, f"got no data {response.data}"

    # Assert that Content-Disposition header doesn't leak CID
    assert cid not in response.headers["Content-Disposition"]


@pytest.mark.unit
def test_build_download_response_arweave(monkeypatch):
    """Test the special cases relevant only to Arweave"""
    transaction_id = ARWEAVE_TRANSACTION_ID
    url_object = {
        "type": "arweave",
        "transactionId": ARWEAVE_TRANSACTION_ID,
    }

    request = Mock()
    request.range = None

    _, instance = FilesTypeFactory.validate_and_create(url_object)
    assert (
        instance.get_download_url() == f"https://arweave.net/{ARWEAVE_TRANSACTION_ID}"
    )

    response = instance.build_download_response(request)
    assert response.status == "200 OK"
    assert response.data, f"got no data {response.data}"

    # Assert that Content-Disposition header doesn't leak transaction ID
    assert transaction_id not in response.headers["Content-Disposition"]

    # Unset ARWEAVE_GATEWAY
    monkeypatch.delenv("ARWEAVE_GATEWAY")
    with pytest.raises(
        Exception,
        match="No ARWEAVE_GATEWAY defined, can not resolve arweave transaction id.",
    ):
        instance.get_download_url()
