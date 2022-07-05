#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime, timedelta
import time

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.user_nonce import is_token_valid


def create_token(client, consumer_wallet, expiration_interval=None):
    address = consumer_wallet.address
    if expiration_interval is None:
        expiration_interval = timedelta(hours=1)

    payload = {
        "address": address,
        "expiration": int((datetime.utcnow() + expiration_interval).timestamp()),
    }

    endpoint = BaseURLs.SERVICES_URL + "/createAuthToken"
    nonce = str(datetime.utcnow().timestamp())
    _msg = f"{address}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(endpoint, query_string=payload)

    assert response.status_code == 200, f"{response.data}"
    assert "token" in response.json, "token is missing from response"

    return response.json["token"]


@pytest.mark.unit
def test_create_auth_token(client, consumer_wallet):
    create_token(client, consumer_wallet)


@pytest.mark.unit
def test_delete_auth_token_sqlite(client, consumer_wallet, monkeypatch):
    monkeypatch.delenv("REDIS_CONNECTION")
    address = consumer_wallet.address
    token = create_token(client, consumer_wallet)
    assert is_token_valid(token, address)[0]

    payload = {"address": address, "token": token}

    endpoint = BaseURLs.SERVICES_URL + "/deleteAuthToken"
    nonce = str(datetime.utcnow().timestamp())
    _msg = f"{address}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.delete(endpoint, query_string=payload)

    assert response.status_code == 200, f"{response.data}"
    assert not is_token_valid(token, address)[0]


@pytest.mark.unit
def test_delete_auth_token_redis(client, consumer_wallet):
    address = consumer_wallet.address
    token = create_token(client, consumer_wallet)
    assert is_token_valid(token, address)[0]

    payload = {"address": address, "token": token}

    endpoint = BaseURLs.SERVICES_URL + "/deleteAuthToken"
    nonce = str(datetime.utcnow().timestamp())
    _msg = f"{address}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.delete(endpoint, query_string=payload)

    assert response.status_code == 200, f"{response.data}"
    assert response.json["success"] == "Token has been deactivated."
    assert not is_token_valid(token, address)[0]
    assert is_token_valid(token, address)[1] == "Token is deleted."

    # can not delete again
    nonce = str(datetime.utcnow().timestamp())
    _msg = f"{address}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.delete(endpoint, query_string=payload)
    assert response.status_code == 400
    assert response.json["error"] == "Token is deleted."


@pytest.mark.unit
def test_expiration(client, consumer_wallet):
    address = consumer_wallet.address
    token = create_token(
        client, consumer_wallet, expiration_interval=timedelta(seconds=1)
    )
    time.sleep(2)
    valid, message = is_token_valid(token, address)
    assert not valid
    assert message == "Token is expired."
