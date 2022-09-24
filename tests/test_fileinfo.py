#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import pytest

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.services import ServiceType
from tests.helpers.constants import ARWEAVE_TRANSACTION_ID
from tests.test_helpers import (
    get_dataset_with_invalid_url_ddo,
    get_first_service_by_type,
    get_registered_asset,
)

fileinfo_url = BaseURLs.SERVICES_URL + "/fileinfo"


@pytest.mark.integration
def test_asset_info(client, publisher_wallet):
    asset = get_registered_asset(publisher_wallet)
    service = get_first_service_by_type(asset, ServiceType.ACCESS)
    response = client.post(
        fileinfo_url,
        json={"did": asset.did, "serviceId": service.id, "checksum": "true"},
    )

    result = response.get_json()
    assert response.status == "200 OK"
    assert isinstance(result, list)
    assert len(result) == 1

    for file_info in result:
        assert file_info["contentLength"]
        assert file_info["contentType"] == "text/plain"
        assert file_info["valid"] is True
        assert (
            file_info["checksum"]
            == "1f7c17bed455f484f4d5ebc581cde6bc059977ef1e143b52a703f18b89c86a22"
        )
        assert file_info["checksumType"] == "sha256"

    asset = get_dataset_with_invalid_url_ddo(client, publisher_wallet)
    service = get_first_service_by_type(asset, ServiceType.ACCESS)
    response = client.post(
        fileinfo_url, json={"did": asset.did, "serviceId": service.id}
    )

    result = response.get_json()
    assert response.status == "200 OK"
    assert isinstance(result, list)
    assert len(result) == 1
    for file_info in result:
        assert "contentLength" not in file_info or not file_info["contentLength"]
        assert file_info["valid"] is False


@pytest.mark.unit
def test_check_url_good(client):
    response = client.post(
        fileinfo_url,
        json={
            "url": "https://s3.amazonaws.com/testfiles.oceanprotocol.com/info.0.json",
            "type": "url",
            "method": "GET",
        },
    )
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["contentLength"] == "1161"
        assert file_info["contentType"] == "application/json"
        assert file_info["valid"] is True


@pytest.mark.unit
def test_check_url_bad(client):
    data = {"url": "http://127.0.0.1/not_valid", "type": "url", "method": "GET"}
    response = client.post(fileinfo_url, json=data)
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["valid"] is False

    data = {"type": "invalid_type"}
    response = client.post(fileinfo_url, json=data)
    result = response.get_json()
    assert response.status == "400 BAD REQUEST"

    data = {"type": "ipfs"}  # no hash
    response = client.post(fileinfo_url, json=data)
    result = response.get_json()
    assert response.status == "400 BAD REQUEST"

    data = {"type": "url"}  # no url
    response = client.post(fileinfo_url, json=data)
    result = response.get_json()
    assert response.status == "400 BAD REQUEST"


@pytest.mark.unit
def test_check_arweave_good(client):
    payload = {
        "type": "arweave",
        "transactionId": ARWEAVE_TRANSACTION_ID,
    }
    response = client.post(fileinfo_url, json=payload)
    result = response.get_json()

    assert response.status == "200 OK", f"{result}"
    assert isinstance(result, list)
    assert len(result) == 1
    for file_info in result:
        assert file_info["contentLength"] == "5311"
        assert file_info["contentType"] == "application/octet-stream"
        assert file_info["valid"] is True


@pytest.mark.unit
def test_check_arweave_bad(client, monkeypatch):
    payload = {"type": "arweave", "transactionId": "invalid"}
    response = client.post(fileinfo_url, json=payload)
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["valid"] is False

    payload = {"type": "arweave"}  # No transactionId
    response = client.post(fileinfo_url, json=payload)
    result = response.get_json()
    assert response.status == "400 BAD REQUEST", f"{result}"

    monkeypatch.setenv("ARWEAVE_GATEWAY", "https://gateway_not_reachable")
    payload = {
        "type": "arweave",
        "transactionId": ARWEAVE_TRANSACTION_ID,
    }
    response = client.post(fileinfo_url, json=payload)
    result = response.get_json()
    assert response.status == "200 OK"
    assert result[0]["valid"] == False
