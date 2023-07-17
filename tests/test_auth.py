#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import time
from datetime import datetime, timedelta, timezone

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.user_nonce import is_token_valid
from ocean_provider.utils.accounts import sign_message
from tests.helpers.nonce import build_nonce


def create_token(client, consumer_wallet, expiration=None):
    """Helper function to create a token using the API."""
    address = consumer_wallet.address
    if expiration is None:
        expiration = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())

    payload = {"address": address, "expiration": expiration}

    endpoint = BaseURLs.SERVICES_URL + "/createAuthToken"
    nonce = build_nonce(address)
    _msg = f"{address}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(endpoint, query_string=payload)

    assert response.status_code == 200, f"{response.data}"
    assert "token" in response.json, "token is missing from response"

    return response.json["token"]


@pytest.mark.unit
def test_create_auth_token(client, consumer_wallet, provider_wallet):
    """Test that tokens can be created and they are only valid for their creators' addresses."""
    consumer_token = create_token(client, consumer_wallet)
    provider_token = create_token(client, provider_wallet)
    assert is_token_valid(consumer_token, consumer_wallet.address)[0]
    assert not is_token_valid(provider_token, consumer_wallet.address)[0]


@pytest.mark.unit
def test_delete_auth_token_sqlite(client, consumer_wallet, monkeypatch):
    """Tests token deletion and recreation with the sqlite backend."""
    monkeypatch.delenv("REDIS_CONNECTION")
    expiration = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    address = consumer_wallet.address
    token = create_token(client, consumer_wallet, expiration)
    assert is_token_valid(token, address)[0]

    payload = {"address": address, "token": token}

    endpoint = BaseURLs.SERVICES_URL + "/deleteAuthToken"
    nonce = build_nonce(address)
    _msg = f"{address}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.delete(endpoint, query_string=payload)

    assert response.status_code == 200, f"{response.data}"
    assert not is_token_valid(token, address)[0]

    # create with same parameters restores the token
    token2 = create_token(client, consumer_wallet, expiration)
    assert token == token2
    assert is_token_valid(token, address)[0]


@pytest.mark.unit
def test_delete_auth_token_redis(client, consumer_wallet):
    """Tests token deletion and recreation with the redis backend."""
    address = consumer_wallet.address
    expiration = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = create_token(client, consumer_wallet, expiration)
    assert is_token_valid(token, address)[0]

    payload = {"address": address, "token": token}

    endpoint = BaseURLs.SERVICES_URL + "/deleteAuthToken"
    nonce = build_nonce(address)
    _msg = f"{address}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.delete(endpoint, query_string=payload)

    assert response.status_code == 200, f"{response.data}"
    assert response.json["success"] == "Token has been deactivated."
    assert not is_token_valid(token, address)[0]
    assert is_token_valid(token, address)[1] == "Token is deleted."

    # can not delete again
    nonce = build_nonce(address)
    _msg = f"{address}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.delete(endpoint, query_string=payload)
    assert response.status_code == 400
    assert response.json["error"] == "Token is deleted."

    # create with same parameters restores the token
    token2 = create_token(client, consumer_wallet, expiration)
    assert token == token2
    assert is_token_valid(token, address)[0]


@pytest.mark.unit
def test_expiration(client, consumer_wallet):
    """Tests token expiration."""
    address = consumer_wallet.address
    expiration = int((datetime.now(timezone.utc) + timedelta(seconds=5)).timestamp())
    token = create_token(client, consumer_wallet, expiration)
    time.sleep(6)
    valid, message = is_token_valid(token, address)
    assert not valid
    assert message == "Token is expired."
