#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

from ocean_provider.run import get_provider_address, get_services_endpoints
from ocean_provider.utils.basics import get_provider_wallet


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
