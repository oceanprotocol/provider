#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
from datetime import datetime

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.run import get_services_endpoints
from ocean_provider.user_nonce import get_nonce, update_nonce
from ocean_provider.utils.accounts import sign_message
from tests.test_helpers import get_registered_asset


@pytest.mark.unit
def test_expose_endpoints(client):
    get_response = client.get("/")
    result = get_response.get_json()
    services_endpoints = get_services_endpoints()
    assert "serviceEndpoints" in result
    assert "software" in result
    assert "version" in result
    assert "chainIds" in result
    assert "providerAddresses" in result
    assert get_response.status == "200 OK"
    assert len(result["serviceEndpoints"]) == len(services_endpoints)


@pytest.mark.unit
def test_spec(client):
    response = client.get("/spec")
    assert response.status == "200 OK"


@pytest.mark.unit
def test_root(client):
    response = client.get("/")
    assert response.status == "200 OK"


@pytest.mark.unit
def test_invalid_endpoint(client, caplog):
    response = client.get("invalid/endpoint", query_string={"hello": "world"})
    assert response.status == "404 NOT FOUND"
    # TODO: Capture and verify INFO log from log_incoming_request using caplog


@pytest.mark.unit
def test_empty_payload_encryption(client):
    encrypt_endpoint = BaseURLs.SERVICES_URL + "/encrypt"
    publish = client.post(encrypt_endpoint, data=None, content_type="application/json")
    assert publish.status_code == 400


@pytest.mark.integration
def test_encrypt_endpoint(client, provider_wallet, publisher_wallet):
    asset = get_registered_asset(publisher_wallet)
    files_list_str = '["https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"]'

    nonce = datetime.utcnow().timestamp()
    msg = f"{asset.did}{nonce}"
    signature = sign_message(msg, provider_wallet)

    payload = {
        "documentId": asset.did,
        "signature": signature,
        "document": files_list_str,
        "publisherAddress": provider_wallet.address,
    }
    encrypt_endpoint = BaseURLs.SERVICES_URL + "/encrypt?chainId=8996"
    response = client.post(
        encrypt_endpoint, json=payload, content_type="application/octet-stream"
    )
    assert response.content_type == "text/plain"
    assert response.data
    assert response.status_code == 201


@pytest.mark.unit
def test_get_nonce(client, publisher_wallet):
    address = publisher_wallet.address
    # Ensure address exists in database
    update_nonce(address, datetime.utcnow().timestamp())

    endpoint = BaseURLs.SERVICES_URL + "/nonce"
    response = client.get(
        endpoint + "?" + f"&userAddress={address}", content_type="application/json"
    )
    assert (
        response.status_code == 200 and response.data
    ), f"get nonce endpoint failed: response status {response.status}, data {response.data}"

    value = response.json if response.json else json.loads(response.data)
    assert value["nonce"] == get_nonce(address)


@pytest.mark.unit
def test_validate_container(client):
    endpoint = BaseURLs.SERVICES_URL + "/validateContainer"

    valid_payload = {
        "entrypoint": "node $ALGO",
        "image": "oceanprotocol/algo_dockers",
        "tag": "python-branin",
        "checksum": "sha256:8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
    }

    response = client.post(endpoint, json=valid_payload)
    assert response.status_code == 200

    invalid_payload = {
        "entrypoint": "node $ALGO",
        "checksum": "sha256:8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
    }

    response = client.post(endpoint, json=invalid_payload)
    assert response.status_code == 400
    assert response.json["error"] == "missing_entrypoint_image_checksum"

    another_valid_payload = {
        "entrypoint": "node $ALGO",
        "image": "node",  # missing library prefix
        "tag": "latest",
        "checksum": "sha256:5c918be3339c8460d13a38e2fc7c027af1cab382b36561f90d3c03342fa866a4",
    }
    response = client.post(endpoint, json=another_valid_payload)
    assert response.status_code == 200

    invalid_payload = {
        "entrypoint": "node $ALGO",
        "image": "doesntexist",
        "tag": "blabla",
        # doesn't start with sha256:
        "checksum": "8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
    }

    response = client.post(endpoint, json=invalid_payload)
    assert response.status_code == 400
    assert response.json["error"] == "checksum_prefix"
