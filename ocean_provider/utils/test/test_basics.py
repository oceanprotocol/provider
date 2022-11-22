#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime, timedelta

import pytest
from ocean_provider.utils.basics import (
    decode_keyed,
    get_configured_chains,
    get_provider_addresses,
    get_value_from_decoded_env,
    get_web3,
    get_web3_connection_provider,
    send_ether,
    validate_timestamp,
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
        get_web3(8996), publisher_wallet, consumer_address, to_wei(1)
    ), "Send ether was unsuccessful."


@pytest.mark.unit
def test_validate_timestamp():
    timestamp_future = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    assert validate_timestamp(timestamp_future)
    assert validate_timestamp(1644831664000) is False
    assert validate_timestamp(str(timestamp_future))

    timestamp_past = (datetime.utcnow() - timedelta(hours=1)).timestamp()
    assert validate_timestamp(timestamp_past) is False


@pytest.mark.unit
def test_decode_keyed(monkeypatch):
    monkeypatch.setenv("TEST_ENV", '{"valid": "json"}')
    assert decode_keyed("TEST_ENV") == {"valid": "json"}
    monkeypatch.setenv("TEST_ENV", '{"invalid json"}')
    assert not decode_keyed("TEST_ENV")
    monkeypatch.setenv("TEST_ENV", "simple string")
    assert not decode_keyed("TEST_ENV")


@pytest.mark.unit
def test_get_configured_chains(monkeypatch):
    monkeypatch.setenv("NETWORK_URL", '{"3": "http://127.0.0.1:8545", "15": "fifteen"}')
    assert get_configured_chains() == [3, 15]

    monkeypatch.setenv("NETWORK_URL", "http://127.0.0.1:8545")
    assert get_configured_chains() == [8996]

    monkeypatch.delenv("NETWORK_URL")
    with pytest.raises(Exception, match="No chains configured"):
        get_configured_chains()


@pytest.mark.unit
def test_get_value_from_decoded_env(monkeypatch):
    monkeypatch.setenv("SOME_ENV", '{"3": "three", "15": "fifteen"}')
    assert get_value_from_decoded_env(3, "SOME_ENV") == "three"

    with pytest.raises(Exception, match="Unconfigured chain_id"):
        get_value_from_decoded_env(7, "SOME_ENV")

    with pytest.raises(Exception, match="Unconfigured chain_id"):
        get_value_from_decoded_env(None, "SOME_ENV")

    monkeypatch.setenv("SOME_ENV", "simple string")
    assert get_value_from_decoded_env(3, "SOME_ENV") == "simple string"


@pytest.mark.unit
def test_get_provider_addresses(monkeypatch):
    monkeypatch.setenv("NETWORK_URL", '{"3": "http://127.0.0.1:8545"}')
    monkeypatch.setenv(
        "PROVIDER_PRIVATE_KEY",
        '{"3": "0xfd5c1ccea015b6d663618850824154a3b3fb2882c46cefb05b9a93fea8c3d215"}',
    )
    assert 3 in get_provider_addresses()

    monkeypatch.setenv("NETWORK_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv(
        "PROVIDER_PRIVATE_KEY",
        "0xfd5c1ccea015b6d663618850824154a3b3fb2882c46cefb05b9a93fea8c3d215",
    )
    assert 8996 in get_provider_addresses()

    monkeypatch.setenv("NETWORK_URL", '{"3": "http://127.0.0.1:8545"}')
    monkeypatch.setenv(
        "PROVIDER_PRIVATE_KEY",
        "0xfd5c1ccea015b6d663618850824154a3b3fb2882c46cefb05b9a93fea8c3d215",
    )
    with pytest.raises(Exception, match="must both be single or both json encoded"):
        get_provider_addresses()

    monkeypatch.setenv(
        "PROVIDER_PRIVATE_KEY",
        '{"3": "0xfd5c1ccea015b6d663618850824154a3b3fb2882c46cefb05b9a93fea8c3d215"}',
    )
    monkeypatch.setenv("NETWORK_URL", "http://127.0.0.1:8545")
    with pytest.raises(Exception, match="must both be single or both json encoded"):
        get_provider_addresses()
