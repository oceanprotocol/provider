#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import pytest
from ocean_provider.utils.basics import get_web3_connection_provider


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
