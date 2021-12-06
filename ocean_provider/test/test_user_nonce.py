#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime
from unittest.mock import patch

import pytest
import sqlalchemy
from ocean_provider import models, user_nonce
from ocean_provider.user_nonce import get_nonce, update_nonce


def test_get_and_update_nonce(publisher_address, consumer_address):

    # get_nonce can be used on addresses that are not in the user_nonce table
    assert get_nonce("0x0000000000000000000000000000000000000000") is None

    # get_nonce doesn't affect the value of nonce
    publisher_nonce = get_nonce(publisher_address)
    assert get_nonce(publisher_address) == publisher_nonce

    update_nonce(publisher_address, datetime.now().timestamp())
    new_publisher_nonce = get_nonce(publisher_address)
    assert new_publisher_nonce >= publisher_nonce


def test_update_nonce_exception(publisher_address):
    # Ensure address exists in database
    update_nonce(publisher_address, datetime.now().timestamp())

    # Create duplicate nonce_object
    with patch.object(
        user_nonce,
        "get_or_create_user_nonce_object",
        return_value=models.UserNonce(
            address=publisher_address, nonce="0"
        ),
    ):
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            update_nonce(publisher_address, datetime.now().timestamp())
