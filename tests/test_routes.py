#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import json

from ocean_lib.web3_internal.transactions import sign_hash
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_provider.constants import BaseURLs
from ocean_provider.run import get_provider_address, get_services_endpoints
from ocean_provider.utils.basics import get_provider_wallet
from tests.test_helpers import (
    get_dataset_ddo_with_access_service,
    get_nonce,
    get_sample_ddo,
)


def test_get_provider_address(client):
    get_response = client.get("/")
    result = get_response.get_json()
    provider_address = get_provider_address()
    assert "providerAddress" in result
    assert provider_address == get_provider_wallet().address
    assert result["providerAddress"] == get_provider_wallet().address
    assert get_response.status == "200 OK"


def test_expose_endpoints(client):
    get_response = client.get("/")
    result = get_response.get_json()
    services_endpoints = get_services_endpoints()
    assert "serviceEndpoints" in result
    assert "software" in result
    assert "version" in result
    assert "network-url" in result
    assert "providerAddress" in result
    assert "computeAddress" in result
    assert get_response.status == "200 OK"
    assert len(result["serviceEndpoints"]) == len(services_endpoints)


def test_spec(client):
    response = client.get("/spec")
    assert response.status == "200 OK"


encrypt_endpoint = BaseURLs.ASSETS_URL + "/encrypt"


def test_empty_payload_encryption(client):
    publish = client.post(encrypt_endpoint, data=None, content_type="application/json")
    assert publish.status_code == 400


def test_encrypt_endpoint(client, provider_wallet, publisher_wallet):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    metadata = get_sample_ddo()["service"][0]["attributes"]
    files_list_str = json.dumps(metadata["main"]["files"])

    nonce = get_nonce(client, provider_wallet.address)
    msg_hash = add_ethereum_prefix_and_hash_msg(f"{ddo.did}{nonce}")
    signature = sign_hash(msg_hash, provider_wallet)

    payload = {
        "documentId": ddo.did,
        "signature": signature,
        "document": files_list_str,
        "publisherAddress": provider_wallet.address,
    }
    response = client.post(
        encrypt_endpoint, json=payload, content_type="application/json"
    )
    assert (
        response.status_code == 201 and response.data
    ), f"encrypt endpoint failed: response status {response.status}, data {response.data}"
    assert response.json["encryptedDocument"]


def test_malformed_encryption_without_RBAC(client):
    payload = {"document": "foo_doc", "publisherAddress": "foo_address"}
    response = client.post(
        encrypt_endpoint, json=payload, content_type="application/json"
    )

    assert response.status_code == 400


def test_malformed_encryption_with_RBAC(
    client, monkeypatch, publisher_wallet, provider_wallet
):
    monkeypatch.setenv("RBAC_SERVER_URL", "test_rbac")
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    metadata = get_sample_ddo()["service"][0]["attributes"]
    files_list_str = json.dumps(metadata["main"]["files"])

    nonce = get_nonce(client, provider_wallet.address)
    msg_hash = add_ethereum_prefix_and_hash_msg(f"{ddo.did}{nonce}")
    signature = sign_hash(msg_hash, provider_wallet)

    payload = {
        "documentId": ddo.did,
        "signature": signature,
        "document": files_list_str,
        "publisherAddress": provider_wallet.address,
    }
    response = client.post(
        encrypt_endpoint, json=payload, content_type="application/json"
    )
    assert (
        response.status_code == 201 and response.data
    ), f"encrypt endpoint failed: response status {response.status}, data {response.data}"
    assert response.json["encryptedDocument"]
