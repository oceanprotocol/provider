#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

from ocean_provider.user_nonce import get_nonce, increment_nonce


def test_get_and_increment_nonce(publisher_address, consumer_address):

    assert get_nonce("0x0000000000000000000000000000000000000000") == 0

    publisher_nonce = get_nonce(publisher_address)

    assert publisher_nonce == get_nonce(publisher_nonce)

    increment_nonce(publisher_address)
    assert get_nonce(publisher_address) == publisher_nonce + 1
    increment_nonce(publisher_address)
    assert get_nonce(publisher_address) == publisher_nonce + 2
