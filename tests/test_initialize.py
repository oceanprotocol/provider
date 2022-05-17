#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import time

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.provider_fees import get_c2d_environments
from ocean_provider.utils.services import ServiceType
from tests.helpers.compute_helpers import (
    build_and_send_ddo_with_compute_service,
    get_future_valid_until,
)
from tests.test_helpers import (
    get_dataset_ddo_disabled,
    get_dataset_ddo_with_denied_consumer,
    get_dataset_with_invalid_url_ddo,
    get_dataset_with_ipfs_url_ddo,
    get_first_service_by_type,
    get_registered_asset,
    initialize_service,
    mint_100_datatokens,
)


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
    assert response.json["error"] == "Asset URL not found or not available."


@pytest.mark.integration
def test_initialize_on_ipfs_url(client, publisher_wallet, consumer_wallet, web3):
    asset = get_dataset_with_ipfs_url_ddo(client, publisher_wallet)
    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    datatoken, nonce, computeAddress, providerFees = initialize_service(
        client, asset.did, service, consumer_wallet
    )

    assert datatoken == service.datatoken_address


@pytest.mark.integration
def test_initialize_on_disabled_asset(client, publisher_wallet, consumer_wallet, web3):
    asset, real_asset = get_dataset_ddo_disabled(client, publisher_wallet)
    assert real_asset
    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    response = initialize_service(
        client, asset.did, service, consumer_wallet, raw_response=True
    )
    assert "error" in response.json
    assert response.json["error"] == "Asset is not consumable."


@pytest.mark.integration
def test_initialize_on_asset_with_custom_credentials(
    client, publisher_wallet, consumer_wallet, web3
):
    asset = get_dataset_ddo_with_denied_consumer(
        client, publisher_wallet, consumer_wallet.address
    )

    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    response = initialize_service(
        client, asset.did, service, consumer_wallet, raw_response=True
    )
    assert "error" in response.json
    assert (
        response.json["error"]
        == f"Error: Access to asset {asset.did} was denied with code: ConsumableCodes.CREDENTIAL_IN_DENY_LIST."
    )


@pytest.mark.integration
def test_can_not_initialize_compute_service_with_simple_initialize(
    client, publisher_wallet, consumer_wallet, web3
):
    asset_w_compute_service = get_registered_asset(
        publisher_wallet, custom_services="vanilla_compute", custom_services_args=[]
    )
    service = get_first_service_by_type(asset_w_compute_service, ServiceType.COMPUTE)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    response = initialize_service(
        client, asset_w_compute_service.did, service, consumer_wallet, raw_response=True
    )
    assert "error" in response.json
    assert (
        response.json["error"]
        == "Use the initializeCompute endpoint to initialize compute jobs."
    )


@pytest.mark.integration
def test_initialize_compute_works(client, publisher_wallet, consumer_wallet):
    """Call `initializeCompute` when there are NO reusable orders
    Assert response contains `datatoken` and `providerFee` and does not contain
    `validOrder` for both dataset and algorithm.
    """
    environments = get_c2d_environments()
    ddo, alg_ddo = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        None,
        environments[0]["consumerAddress"],
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
                    "env": environments[0]["id"],
                    "validUntil": get_future_valid_until(),
                },
            }
        ),
        content_type="application/json",
    )

    assert response.status_code == 200, f"{response.data}"
    assert "datatoken" in response.json["datasets"][0]
    assert "providerFee" in response.json["datasets"][0]
    assert "validOrder" not in response.json["datasets"][0]
    assert "datatoken" in response.json["algorithm"]
    assert "providerFee" in response.json["algorithm"]
    assert "validOrder" not in response.json["algorithm"]


@pytest.mark.integration
def test_initialize_compute_order_reused(client, publisher_wallet, consumer_wallet):
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
    environments = get_c2d_environments()

    # Order asset, valid for 60 seconds
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        None,
        environments[0]["consumerAddress"],
        short_valid_until=True,
        timeout=60,
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
            "env": environments[0]["id"],
            "validUntil": get_future_valid_until(short=True),
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
    time.sleep(30)

    payload["compute"]["validUntil"] = get_future_valid_until()
    response = client.post(
        BaseURLs.SERVICES_URL + "/initializeCompute",
        data=json.dumps(payload),
        content_type="application/json",
    )

    # Case 2: valid orders, expired provider fees
    assert response.status_code == 200
    assert response.json["algorithm"]["validOrder"] == alg_tx_id
    assert response.json["datasets"][0]["validOrder"] == tx_id
    assert "providerFee" in response.json["datasets"][0]
    assert "providerFee" in response.json["algorithm"]

    # Sleep long enough for orders to expire
    time.sleep(60)

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
