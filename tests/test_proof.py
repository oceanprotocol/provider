#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
from unittest.mock import Mock, patch

import pytest
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.proof import send_proof
from ocean_provider.utils.provider_fees import get_provider_fees
from ocean_provider.utils.services import ServiceType
from requests.models import Response
from tests.helpers.nonce import build_nonce
from tests.test_helpers import (
    get_first_service_by_type,
    get_registered_asset,
    mint_100_datatokens,
    start_order,
)


@pytest.mark.unit
def test_no_proof_setup(client):
    assert send_proof(None, None, None, None, None, None, None) is None


@pytest.mark.unit
def test_http_proof(client, monkeypatch):
    monkeypatch.setenv("USE_HTTP_PROOF", "http://test.com")
    provider_data = json.dumps({"test_data": "test_value"})

    with patch("requests.post") as mock:
        response = Mock(spec=Response)
        response.json.return_value = {"a valid response": ""}
        response.status_code = 200
        mock.return_value = response

        assert send_proof(8996, b"1", provider_data, None, None, None, None) is True

    mock.assert_called_once()

    with patch("requests.post") as mock:
        mock.side_effect = Exception("Boom!")

        assert send_proof(8996, b"1", provider_data, None, None, None, None) is None

    mock.assert_called_once()


@pytest.mark.integration
def test_chain_proof(client, monkeypatch, web3, publisher_wallet, consumer_wallet):
    monkeypatch.setenv("USE_CHAIN_PROOF", "1")
    provider_data = json.dumps({"test_data": "test_value"})

    asset = get_registered_asset(publisher_wallet)
    service = get_first_service_by_type(asset, ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )
    tx_id, receipt = start_order(
        web3,
        service.datatoken_address,
        consumer_wallet.address,
        service.index,
        get_provider_fees(asset, service, consumer_wallet.address, 0),
        consumer_wallet,
    )

    nonce = build_nonce(consumer_wallet.address)

    consumer_data = _msg = f"{asset.did}{nonce}"
    signature = sign_message(_msg, consumer_wallet)

    assert send_proof(
        8996,
        receipt.transactionHash,
        provider_data,
        consumer_data,
        signature,
        consumer_wallet.address,
        service.datatoken_address,
    )
