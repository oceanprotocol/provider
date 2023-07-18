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


@pytest.mark.integration
def test_can_not_initialize_compute_service_with_simple_initialize(
    client, publisher_wallet, consumer_wallet, web3
):
    asset_w_compute_service = get_registered_asset(
        publisher_wallet, custom_services="vanilla_compute", custom_services_args=[]
    )
    service = get_first_service_by_type(asset_w_compute_service, ServiceType.COMPUTE)

    response = initialize_service(
        client, asset_w_compute_service.did, service, consumer_wallet, raw_response=True
    )
    assert "error" in response.json
    assert (
        response.json["error"]
        == "Use the initializeCompute endpoint to initialize compute jobs."
    )


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
def test_initialize_compute_works(
    client, publisher_wallet, consumer_wallet, free_c2d_env
):
    """Call `initializeCompute` when there are NO reusable orders
    Assert response contains `datatoken` and `providerFee` and does not contain
    `validOrder` for both dataset and algorithm.
    """
    ddo, alg_ddo = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        None,
        free_c2d_env["consumerAddress"],
        do_send=False,
        timeout=3600,
    )
    service = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)

    response = client.post(
        BaseURLs.SERVICES_URL + "/initializeCompute",
        data=json.dumps(
            {
                "datasets": [
                    {
                        "documentId": ddo.did,
                        "serviceId": service.id,
                        "userdata": '{"dummy_userdata":"XXX", "age":12}',
                    }
                ],
                "algorithm": {"documentId": alg_ddo.did, "serviceId": sa_compute.id},
                "consumerAddress": consumer_wallet.address,
                "compute": {
                    "env": free_c2d_env["id"],
                    "validUntil": get_future_valid_until(),
                },
            }
        ),
        content_type="application/json",
    )

    assert response.status_code == 200, f"{response.data}"
    assert response.json["datasets"][0]["providerFee"]["providerFeeAmount"] == "0"
    assert "datatoken" in response.json["datasets"][0]
    assert "providerFee" in response.json["datasets"][0]
    assert "validOrder" not in response.json["datasets"][0]
    assert "datatoken" in response.json["algorithm"]
    assert "providerFee" in response.json["algorithm"]
    assert "validOrder" not in response.json["algorithm"]


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
def test_initialize_compute_order_reused(
    client, publisher_wallet, consumer_wallet, free_c2d_env
):
    """Call `initializeCompute` when there ARE reusable orders

    Enumerate all cases:

    Case 1:
        valid orders
        valid provider fees

    Case 2:
        valid orders
        expired provider fees

    Case 3:
        expired orders
        expired provider fees

    Case 4:
        wrong tx id for dataset order
    """
    # Order asset, valid for 30 seconds
    valid_until = get_future_valid_until(short=True)
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        None,
        free_c2d_env["consumerAddress"],
        valid_until,
        timeout=60,
        c2d_environment=free_c2d_env["id"],
    )
    service = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)

    payload = {
        "datasets": [
            {
                "documentId": ddo.did,
                "serviceId": service.id,
                "transferTxId": tx_id,
                "userdata": '{"dummy_userdata":"XXX", "age":12}',
            }
        ],
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
        },
        "consumerAddress": consumer_wallet.address,
        "compute": {
            "env": free_c2d_env["id"],
            "validUntil": valid_until,
        },
    }

    response = client.post(
        BaseURLs.SERVICES_URL + "/initializeCompute",
        data=json.dumps(payload),
        content_type="application/json",
    )

    # Case 1: valid orders, valid provider fees
    assert response.status_code == 200
    assert response.json["algorithm"] == {"validOrder": alg_tx_id}
    assert response.json["datasets"] == [{"validOrder": tx_id}]
    assert "providerFee" not in response.json["datasets"][0]
    assert "providerFee" not in response.json["algorithm"]

    # Sleep long enough for provider fees to expire
    timeout = time.time() + (30 * 5)
    while True:
        payload["compute"]["validUntil"] = get_future_valid_until(short=True) + 30
        response = client.post(
            BaseURLs.SERVICES_URL + "/initializeCompute",
            data=json.dumps(payload),
            content_type="application/json",
        )
        if "providerFee" in response.json["algorithm"] or time.time() > timeout:
            break
        time.sleep(1)

    # Case 2: valid orders, expired provider fees
    assert response.status_code == 200
    assert response.json["algorithm"]["validOrder"] == alg_tx_id
    assert response.json["datasets"][0]["validOrder"] == tx_id
    assert "providerFee" in response.json["datasets"][0]
    assert "providerFee" in response.json["algorithm"]

    # Sleep long enough for orders to expire
    timeout = time.time() + (30 * 3)
    while True:
        payload["compute"]["validUntil"] = get_future_valid_until(short=True) + 30
        response = client.post(
            BaseURLs.SERVICES_URL + "/initializeCompute",
            data=json.dumps(payload),
            content_type="application/json",
        )
        if "validOrder" not in response.json["algorithm"] or time.time() > timeout:
            break
        time.sleep(1)

    # Case 3: expired orders, expired provider fees
    assert response.status_code == 200
    assert "datatoken" in response.json["datasets"][0]
    assert "providerFee" in response.json["datasets"][0]
    assert "validOrder" not in response.json["datasets"][0]
    assert "datatoken" in response.json["algorithm"]
    assert "providerFee" in response.json["algorithm"]
    assert "validOrder" not in response.json["algorithm"]

    # Case 4: wrong tx id for dataset order
    payload["datasets"][0]["transferTxId"] = "wrong_tx_id"
    response = client.post(
        BaseURLs.SERVICES_URL + "/initializeCompute",
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert "datatoken" in response.json["datasets"][0].keys()
    assert "providerFee" in response.json["datasets"][0].keys()


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
def test_initialize_compute_paid_env(
    client, publisher_wallet, consumer_wallet, paid_c2d_env
):
    ddo, alg_ddo = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        None,
        paid_c2d_env,
        do_send=False,
        timeout=3600,
    )
    service = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)

    response = client.post(
        BaseURLs.SERVICES_URL + "/initializeCompute",
        data=json.dumps(
            {
                "datasets": [
                    {
                        "documentId": ddo.did,
                        "serviceId": service.id,
                        "userdata": '{"dummy_userdata":"XXX", "age":12}',
                    }
                ],
                "algorithm": {"documentId": alg_ddo.did, "serviceId": sa_compute.id},
                "consumerAddress": consumer_wallet.address,
                "compute": {
                    "env": paid_c2d_env["id"],
                    "validUntil": get_future_valid_until(),
                },
            }
        ),
        content_type="application/json",
    )

    assert response.status_code == 200, f"{response.data}"
    assert int(
        response.json["datasets"][0]["providerFee"]["providerFeeAmount"]
    ) >= to_wei(7)
