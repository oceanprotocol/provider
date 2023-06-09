#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
import time
from datetime import datetime
from unittest.mock import patch

import ipfshttpclient
import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.provider_fees import get_provider_fees
from ocean_provider.utils.services import ServiceType
from tests.helpers.compute_helpers import (
    build_and_send_ddo_with_compute_service,
    get_future_valid_until,
)
from tests.test_helpers import (
    get_dataset_ddo_disabled,
    get_dataset_ddo_unlisted,
    get_dataset_ddo_with_denied_consumer,
    get_dataset_ddo_with_multiple_files,
    get_dataset_with_invalid_url_ddo,
    get_first_service_by_type,
    get_registered_asset,
    initialize_service,
    mint_100_datatokens,
    start_order,
)

logger = logging.getLogger(__name__)


@pytest.mark.integration
def test_initialize_on_bad_url(client, publisher_wallet, consumer_wallet, web3):
    asset = get_dataset_with_invalid_url_ddo(client, publisher_wallet)
    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    response = initialize_service(
        client, asset.did, service, consumer_wallet, raw_response=True
    )
    assert "error" in response.json
    assert "Asset URL not found, not available or invalid." in response.json["error"]


@pytest.mark.integration
def test_initialize_on_ipfs_url(client, publisher_wallet, consumer_wallet, web3):
    ipfs_client = ipfshttpclient.connect("/dns/172.15.0.16/tcp/5001/http")
    cid = ipfs_client.add("./tests/resources/ddo_sample_file.txt")["Hash"]
    url_object = {"type": "ipfs", "hash": cid}
    asset = get_registered_asset(
        publisher_wallet,
        unencrypted_files_list=[url_object],
    )
    service = get_first_service_by_type(asset, ServiceType.ACCESS)
    datatoken, nonce, computeAddress, providerFees = initialize_service(
        client, asset.did, service, consumer_wallet
    )

    assert datatoken == service.datatoken_address


@pytest.mark.integration
def test_initialize_on_disabled_asset(client, publisher_wallet, consumer_wallet, web3):
    asset, real_asset = get_dataset_ddo_disabled(client, publisher_wallet)
    assert real_asset
    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    response = initialize_service(
        client, asset.did, service, consumer_wallet, raw_response=True
    )
    assert "error" in response.json
    assert response.json["error"] == "Asset malformed or disabled."


@pytest.mark.integration
def test_initialize_on_unlisted_asset(client, publisher_wallet, consumer_wallet, web3):
    asset, real_asset = get_dataset_ddo_unlisted(client, publisher_wallet)
    assert real_asset
    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    datatoken, nonce, computeAddress, providerFees = initialize_service(
        client, asset.did, service, consumer_wallet
    )

    assert datatoken == service.datatoken_address


@pytest.mark.integration
def test_initialize_on_asset_with_custom_credentials(
    client, publisher_wallet, consumer_wallet, web3
):
    asset = get_dataset_ddo_with_denied_consumer(
        client, publisher_wallet, consumer_wallet.address
    )

    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    response = initialize_service(
        client, asset.did, service, consumer_wallet, raw_response=True
    )
    assert "error" in response.json
    assert (
        response.json["error"]
        == f"Error: Access to asset {asset.did} was denied with code: ConsumableCodes.CREDENTIAL_IN_DENY_LIST."
    )


@pytest.mark.integration
def test_initialize_reuse(client, publisher_wallet, consumer_wallet, web3):
    asset = get_dataset_ddo_with_multiple_files(client, publisher_wallet)

    service = get_first_service_by_type(asset, ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    tx_id, _ = start_order(
        web3,
        service.datatoken_address,
        consumer_wallet.address,
        service.index,
        get_provider_fees(asset, service, consumer_wallet.address, 0),
        consumer_wallet,
    )

    response = initialize_service(
        client,
        asset.did,
        service,
        consumer_wallet,
        raw_response=True,
        reuse_order=tx_id,
    )

    assert "datatoken" not in response.json
    assert response.json["validOrder"] == tx_id

    with patch("web3.eth.wait_for_transaction_receipt") as mock:
        # speed up with mocks, otherwise this test waits a lot until reaching the Exception
        mock.side_effect = Exception("Boom!")
        response = initialize_service(
            client,
            asset.did,
            service,
            consumer_wallet,
            raw_response=True,
            reuse_order=tx_id,
        )

    assert response.json["datatoken"] == service.datatoken_address
    assert "validOrder" not in response.json
