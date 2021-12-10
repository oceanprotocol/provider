#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import pytest

from ocean_provider.utils.basics import (
    get_web3,
    get_web3_connection_provider,
    send_ether,
)
from ocean_provider.utils.currency import to_wei


@pytest.mark.unit
def test_get_web3_connection_provider(monkeypatch):
    # typical http uri "http://foo.com"
    provider = get_web3_connection_provider("http://foo.com")
    assert provider.endpoint_uri == "http://foo.com"

    # typical https uri "https://bar.com"
    provider = get_web3_connection_provider("https://bar.com")
    assert provider.endpoint_uri == "https://bar.com"

    # non-supported name
    with pytest.raises(AssertionError):
        get_web3_connection_provider("not_network_name")

    # typical websockets uri "wss://foo.com"
    provider = get_web3_connection_provider("wss://bah.com")
    assert provider.endpoint_uri == "wss://bah.com"


@pytest.mark.unit
def test_send_ether(publisher_wallet, consumer_address):
    assert send_ether(
        get_web3(), publisher_wallet, consumer_address, to_wei(1)
    ), "Send ether was unsuccessful."
