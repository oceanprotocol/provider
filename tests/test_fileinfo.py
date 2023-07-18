#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import os

import ipfshttpclient
import requests

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.address import get_contract_address
from ocean_provider.utils.services import ServiceType
from tests.helpers.constants import ARWEAVE_TRANSACTION_ID
from tests.test_helpers import (
    get_dataset_with_invalid_url_ddo,
    get_first_service_by_type,
    get_registered_asset,
)

logger = logging.getLogger(__name__)

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
        assert file_info["type"] == "url"


@pytest.mark.unit
def test_checksums(client):
    data = {
        "url": "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt",
        "type": "url",
        "method": "GET",
        "checksum": True,
    }
    response = client.post(fileinfo_url, json=data)
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["valid"] is True
        assert file_info["type"] == "url"
        assert (
            file_info["checksum"]
            == "1f7c17bed455f484f4d5ebc581cde6bc059977ef1e143b52a703f18b89c86a22"
        )
        assert file_info["checksumType"] == "sha256"

    # big file, we should not have a checksum
    response = requests.get(
        "https://raw.githubusercontent.com/oceanprotocol/c2d-examples/main/branin_and_gpr/branin.arff"
    )
    if response.status_code == 200:
        with open("./tests/resources/branin.arff", "wb") as file:
            file.write(response.content)

    ipfs_client = ipfshttpclient.connect("/dns/172.15.0.16/tcp/5001/http")
    cid = ipfs_client.add("./tests/resources/branin.arff")["Hash"]
    data = {
        "hash": cid,
        "type": "ipfs",
        "checksum": False,
    }
    response = client.post(fileinfo_url, json=data)
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["valid"] is True
        assert file_info["type"] == "ipfs"
        assert "checksum" not in file_info
        assert "checksumType" not in file_info


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
        assert file_info["type"] == "arweave"


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
    assert not result[0]["valid"]


@pytest.mark.integration
def test_check_smartcontract_simple(client, publisher_wallet, consumer_wallet):
    router_address = get_contract_address(os.getenv("ADDRESS_FILE"), "Router", 8996)
    abi = {
        "inputs": [],
        "name": "getApprovedTokens",
        "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
        "stateMutability": "view",
        "type": "function",
    }
    payload = {"type": "smartcontract", "address": router_address, "abi": abi}
    response = client.post(fileinfo_url, json=payload)
    result = response.get_json()

    assert response.status == "200 OK", f"{result}"
    assert isinstance(result, list)
    assert len(result) == 1


@pytest.mark.integration
def test_check_smartcontract_with_userdata(
    client, publisher_wallet, consumer_wallet, web3
):
    dummy_asset = get_registered_asset(publisher_wallet)
    dummy_service = get_first_service_by_type(dummy_asset, ServiceType.ACCESS)
    # create abi for getId
    abi = {
        "inputs": [{"internalType": "address", "name": "user", "type": "address"}],
        "name": "isERC20Deployer",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    }
    userdata = {"user": publisher_wallet.address}

    payload = {
        "type": "smartcontract",
        "address": dummy_service.datatoken_address,
        "abi": abi,
    }

    # try first without userdata, should fail
    response = client.post(fileinfo_url, json=payload)
    result = response.get_json()
    assert response.status == "400 BAD REQUEST", f"{result}"

    # try with userdata, should be fine
    payload_with_userdata = {
        "type": "smartcontract",
        "address": dummy_service.datatoken_address,
        "abi": abi,
        "userdata": userdata,
    }
    response = client.post(fileinfo_url, json=payload_with_userdata)
    result = response.get_json()
    assert response.status == "200 OK"
