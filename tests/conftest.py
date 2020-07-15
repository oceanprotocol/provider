#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import pytest

from ocean_provider.run import app
from ocean_provider.utils.accounts import get_provider_account
from ocean_provider.utils.basics import setup_network
from ocean_provider.web3_internal import Web3Helper
from ocean_provider.web3_internal.account import Account
from ocean_provider.web3_internal.web3_provider import Web3Provider
from tests.test_helpers import get_consumer_account

app = app


@pytest.fixture
def client():
    client = app.test_client()
    yield client


@pytest.fixture(autouse=True)
def setup_all():
    setup_network()
    web3 = Web3Provider.get_web3()
    if web3.eth.accounts and web3.eth.accounts[0].lower() == '0xe2DD09d719Da89e5a3D0F2549c7E24566e947260'.lower():
        account = Account(web3.eth.accounts[0], private_key='0xc594c6e5def4bab63ac29eed19a134c130388f74f019bc74b8f4389df2837a58')

        provider = get_provider_account()
        if web3.fromWei(Web3Helper.get_ether_balance(provider.address), 'ether') < 10:
            Web3Helper.send_ether(account, provider.address, web3.toWei(25, 'ether'))

        consumer = get_consumer_account()
        if web3.fromWei(Web3Helper.get_ether_balance(consumer.address), 'ether') < 10:
            Web3Helper.send_ether(account, consumer.address, web3.toWei(25, 'ether'))
