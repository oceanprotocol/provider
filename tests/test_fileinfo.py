#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.services import ServiceType
from tests.test_helpers import (
    get_dataset_with_invalid_url_ddo,
    get_registered_asset,
)

fileinfo_url = BaseURLs.SERVICES_URL + "/fileinfo"


def test_asset_info(client, publisher_wallet):
    asset = get_registered_asset(publisher_wallet)
    service = asset.get_service_by_type(ServiceType.ACCESS)
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
    service = asset.get_service_by_type(ServiceType.ACCESS)
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


def test_check_url_good(client):
    response = client.post(
        fileinfo_url,
        json={
            "url": "https://s3.amazonaws.com/testfiles.oceanprotocol.com/info.0.json"
        },
    )
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["contentLength"] == "1161"
        assert file_info["contentType"] == "application/json"
        assert file_info["valid"] is True


def test_check_url_bad(client):
    data = {"url": "http://127.0.0.1/not_valid"}
    response = client.post(fileinfo_url, json=data)
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["valid"] is False
