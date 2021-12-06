#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from unittest.mock import patch

import pytest
import sqlalchemy
from ocean_provider import models, user_nonce
from ocean_provider.user_nonce import get_nonce, increment_nonce


def test_get_and_increment_nonce(publisher_address, consumer_address):

    # get_nonce can be used on addresses that are not in the user_nonce table
    assert get_nonce("0x0000000000000000000000000000000000000000") == "0"

    # get_nonce doesn't affect the value of nonce
    publisher_nonce = get_nonce(publisher_address)
    publisher_nonce_int = int(publisher_nonce)
    assert get_nonce(publisher_address) == publisher_nonce

    # increment_nonce increases the nonce by 1
    increment_nonce(publisher_address)
    assert int(get_nonce(publisher_address)) == publisher_nonce_int + 1

    # increment_nonce can be used twice in a row
    increment_nonce(publisher_address)
    assert int(get_nonce(publisher_address)) == publisher_nonce_int + 2


def test_increment_nonce_exception(publisher_address):
    # Ensure address exists in database
    increment_nonce(publisher_address)

    # Create duplicate nonce_object
    with patch.object(
        user_nonce,
        "get_or_create_user_nonce_object",
        return_value=models.UserNonce(
            address=publisher_address, nonce=models.UserNonce.FIRST_NONCE
        ),
    ):
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            increment_nonce(publisher_address)
