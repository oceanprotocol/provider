#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime
from flask_caching import Cache
import os
from unittest.mock import patch

import pytest
import sqlalchemy
from ocean_provider import models, user_nonce
from ocean_provider.myapp import app
from ocean_provider.user_nonce import (
    get_nonce,
    update_nonce,
    get_or_create_user_nonce_object,
)

cache = Cache(
    app,
    config={
        "CACHE_TYPE": "redis",
        "CACHE_KEY_PREFIX": "ocean_provider",
        "CACHE_REDIS_URL": os.getenv("REDIS_CONNECTION"),
    },
)


@pytest.mark.unit
def test_get_and_update_nonce(monkeypatch, publisher_address, consumer_address):
    # pass through sqlite
    monkeypatch.delenv("REDIS_CONNECTION")

    # get_nonce can be used on addresses that are not in the user_nonce table
    assert get_nonce("0x0000000000000000000000000000000000000000") is None
    assert get_or_create_user_nonce_object(
        "0x0000000000000000000000000000000000000000", datetime.utcnow().timestamp()
    )

    # update two times because, if we just pruned, we start from None
    update_nonce(publisher_address, datetime.utcnow().timestamp())
    publisher_nonce = get_nonce(publisher_address)
    update_nonce(publisher_address, datetime.utcnow().timestamp())
    new_publisher_nonce = get_nonce(publisher_address)

    assert new_publisher_nonce >= publisher_nonce

    # get_nonce doesn't affect the value of nonce
    publisher_nonce = get_nonce(publisher_address)
    assert get_nonce(publisher_address) == publisher_nonce


@pytest.mark.unit
def test_get_and_update_nonce_redis(publisher_address, consumer_address):
    # get_nonce can be used on addresses that are not in the user_nonce table
    cache.delete("0x0000000000000000000000000000000000000000")
    assert get_nonce("0x0000000000000000000000000000000000000000") is None
    assert get_or_create_user_nonce_object(
        "0x0000000000000000000000000000000000000000", datetime.utcnow().timestamp()
    )

    # update two times because, if we just pruned, we start from None
    update_nonce(publisher_address, datetime.utcnow().timestamp())
    publisher_nonce = get_nonce(publisher_address)
    update_nonce(publisher_address, datetime.utcnow().timestamp())
    new_publisher_nonce = get_nonce(publisher_address)

    assert new_publisher_nonce >= publisher_nonce

    # get_nonce doesn't affect the value of nonce
    publisher_nonce = get_nonce(publisher_address)
    assert get_nonce(publisher_address) == publisher_nonce


@pytest.mark.unit
def test_update_nonce_exception(monkeypatch, publisher_address):
    # pass through sqlite
    monkeypatch.delenv("REDIS_CONNECTION")

    # Ensure address exists in database
    update_nonce(publisher_address, datetime.utcnow().timestamp())

    # Create duplicate nonce_object
    with patch.object(
        user_nonce,
        "get_or_create_user_nonce_object",
        return_value=models.UserNonce(address=publisher_address, nonce="0"),
    ):
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            update_nonce(publisher_address, datetime.utcnow().timestamp())

    publisher_nonce = get_nonce(publisher_address)
    update_nonce(publisher_address, None)
    # no effect
    assert publisher_nonce == get_nonce(publisher_address)
