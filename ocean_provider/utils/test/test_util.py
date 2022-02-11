#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
import mimetypes
from copy import deepcopy
from unittest.mock import MagicMock, Mock

import ipfshttpclient
import pytest
from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.asset import Asset
from ocean_provider.utils.encryption import do_encrypt
from ocean_provider.utils.util import (
    build_download_response,
    get_asset_files_list,
    get_asset_url_at_index,
    get_asset_urls,
    get_download_url,
    msg_hash,
)
from werkzeug.utils import get_content_type

test_logger = logging.getLogger(__name__)


def test_msg_hash():
    msg = "Hello World!"
    hashed = msg_hash(msg)
    expected = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    assert hashed == expected


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
    response = build_download_response(request, requests_session, url, url, None)
    assert response.headers["content-type"] == content_type
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )

    filename = "<<filename>>"
    url = f"https://source-lllllll.cccc/{filename}"
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
    response = build_download_response(
        request, requests_session_with_content_type, url, url, None
    )
    assert response.headers["content-type"] == response_content_type
    assert (
        response.headers.get_all("Content-Disposition")[0]
        == f"attachment;filename={filename}"
    )


def test_download_ipfs_file():
    client = ipfshttpclient.connect("/dns/172.15.0.16/tcp/5001/http")
    cid = client.add("./tests/resources/ddo_sample_file.txt")["Hash"]
    url = f"ipfs://{cid}"
    download_url = get_download_url(url)
    requests_session = get_requests_session()

    request = Mock()
    request.range = None

    print(f"got ipfs download url: {download_url}")
    assert download_url and download_url.endswith(f"ipfs/{cid}")
    response = build_download_response(
        request, requests_session, download_url, download_url, None
    )
    assert response.data, f"got no data {response.data}"


def test_get_assets_files_list(provider_wallet):
    asset = Mock(template=Asset)
    encr = do_encrypt(json.dumps(["test1", "test2"]), provider_wallet)
    asset.encrypted_files = json.dumps({"encryptedDocument": encr})
    assert ["test1", "test2"] == get_asset_files_list(asset, provider_wallet)

    # empty
    asset.encrypted_files = ""
    assert get_asset_files_list(asset, provider_wallet) is None

    # not a list
    encr = do_encrypt(json.dumps({"test": "test"}), provider_wallet)
    asset.encrypted_files = json.dumps({"encryptedDocument": encr})
    with pytest.raises(TypeError):
        get_asset_files_list(asset, provider_wallet)


def test_get_asset_urls(provider_wallet):
    # empty
    asset = Mock(template=Asset)
    asset.encrypted_files = ""
    assert get_asset_urls(asset, provider_wallet) == []
    assert get_asset_url_at_index(0, asset, provider_wallet) is None

    # not a list
    encr = do_encrypt(json.dumps({"test": "test"}), provider_wallet)
    asset.encrypted_files = json.dumps({"encryptedDocument": encr})
    with pytest.raises(TypeError):
        get_asset_urls(asset, provider_wallet)

    # does not have url there
    encr = do_encrypt(json.dumps([{"noturl": "test"}]), provider_wallet)
    asset.encrypted_files = json.dumps({"encryptedDocument": encr})
    with pytest.raises(ValueError):
        get_asset_urls(asset, provider_wallet)

    # correct with url
    encr = do_encrypt(json.dumps([{"url": "test"}]), provider_wallet)
    asset.encrypted_files = json.dumps({"encryptedDocument": encr})
    assert get_asset_urls(asset, provider_wallet) == ["test"]
    with pytest.raises(ValueError):
        get_asset_url_at_index(3, asset, provider_wallet)
