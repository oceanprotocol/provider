#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import os

import pytest
from ocean_lib.web3_internal.transactions import send_ether
from ocean_lib.web3_internal.utils import get_ether_balance
from ocean_lib.web3_internal.wallet import Wallet

from ocean_provider.run import app
from ocean_provider.utils.basics import get_web3

app = app


@pytest.fixture
def client():
    client = app.test_client()
    yield client


@pytest.fixture
def publisher_wallet():
    return Wallet(
        get_web3(), private_key=os.getenv("TEST_PRIVATE_KEY1"), block_confirmations=0
    )


@pytest.fixture
def publisher_address(publisher_wallet):
    return publisher_wallet.address


@pytest.fixture
def consumer_wallet():
    return Wallet(
        get_web3(), private_key=os.getenv("TEST_PRIVATE_KEY2"), block_confirmations=0
    )


@pytest.fixture
def consumer_address(consumer_wallet):
    return consumer_wallet.address


@pytest.fixture
def ganache_wallet():
    web3 = get_web3()
    if (
        web3.eth.accounts
        and web3.eth.accounts[0].lower()
        == "0xe2DD09d719Da89e5a3D0F2549c7E24566e947260".lower()
    ):
        return Wallet(
            web3,
            private_key="0xfd5c1ccea015b6d663618850824154a3b3fb2882c46cefb05b9a93fea8c3d215",
            block_confirmations=0,
        )

    return None


@pytest.fixture
def provider_wallet():
    pk = os.environ.get("PROVIDER_PRIVATE_KEY")
    return Wallet(get_web3(), private_key=pk, block_confirmations=0)


@pytest.fixture
def provider_address(provider_wallet):
    return provider_wallet.address


@pytest.fixture(autouse=True)
def setup_all(provider_address, consumer_address):
    web3 = get_web3()
    if (
        web3.eth.accounts
        and web3.eth.accounts[0].lower()
        == "0xe2DD09d719Da89e5a3D0F2549c7E24566e947260".lower()
    ):
        wallet = Wallet(
            web3,
            private_key="0xfd5c1ccea015b6d663618850824154a3b3fb2882c46cefb05b9a93fea8c3d215",
            block_confirmations=0,
        )

        if web3.fromWei(get_ether_balance(web3, provider_address), "ether") < 10:
            send_ether(wallet, provider_address, 25)

        if web3.fromWei(get_ether_balance(web3, consumer_address), "ether") < 10:
            send_ether(wallet, consumer_address, 25)


@pytest.fixture
def web3():
    return get_web3()
