#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime
import pytest

from ocean_provider.constants import BaseURLs
from ocean_provider.run import get_provider_address, get_services_endpoints
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.basics import get_provider_wallet
from tests.test_helpers import get_registered_asset


@pytest.mark.unit
def test_get_provider_address(client):
    get_response = client.get("/")
    result = get_response.get_json()
    provider_address = get_provider_address()
    assert "providerAddress" in result
    assert provider_address == get_provider_wallet().address
    assert result["providerAddress"] == get_provider_wallet().address
    assert get_response.status == "200 OK"


@pytest.mark.unit
def test_expose_endpoints(client):
    get_response = client.get("/")
    result = get_response.get_json()
    services_endpoints = get_services_endpoints()
    assert "serviceEndpoints" in result
    assert "software" in result
    assert "version" in result
    assert "chainId" in result
    assert "providerAddress" in result
    assert "computeAddress" in result
    assert get_response.status == "200 OK"
    assert len(result["serviceEndpoints"]) == len(services_endpoints)


@pytest.mark.unit
def test_spec(client):
    response = client.get("/spec")
    assert response.status == "200 OK"


encrypt_endpoint = BaseURLs.SERVICES_URL + "/encrypt"


@pytest.mark.unit
def test_empty_payload_encryption(client):
    publish = client.post(encrypt_endpoint, data=None, content_type="application/json")
    assert publish.status_code == 400


@pytest.mark.integration
def test_encrypt_endpoint(client, provider_wallet, publisher_wallet):
    asset = get_registered_asset(publisher_wallet)
    files_list_str = '["https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"]'

    nonce = datetime.now().timestamp()
    msg = f"{asset.did}{nonce}"
    signature = sign_message(msg, provider_wallet)

    payload = {
        "documentId": asset.did,
        "signature": signature,
        "document": files_list_str,
        "publisherAddress": provider_wallet.address,
    }
    response = client.post(
        encrypt_endpoint, json=payload, content_type="application/octet-stream"
    )
    assert response.content_type == "text/plain"
    assert response.data
    assert response.status_code == 201
