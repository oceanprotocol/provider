#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import pytest

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.provider_fees import get_c2d_environments
from ocean_provider.utils.services import ServiceType
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
from tests.helpers.compute_helpers import (
    build_and_send_ddo_with_compute_service,
    get_future_valid_until,
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
def test_initialize_compute_works(client, publisher_wallet, consumer_wallet, web3):
    environments = get_c2d_environments()
    ddo, alg_ddo = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        None,
        environments[0]["consumerAddress"],
        do_send=False,
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
                    },
                ],
                "algorithm": {
                    "documentId": alg_ddo.did,
                    "serviceId": sa_compute.id,
                },
                "consumerAddress": consumer_wallet.address,
                "compute": {
                    "env": environments[0]["id"],
                    "validUntil": get_future_valid_until(),
                },
            }
        ),
        content_type="application/json",
    )

    assert response.status_code == 200

    assert "datatoken" in response.json["datasets"][0].keys()
    assert "providerFee" in response.json["datasets"][0].keys()
    assert "datatoken" in response.json["algorithm"].keys()
    assert "providerFee" in response.json["algorithm"].keys()


@pytest.mark.integration
def test_initialize_compute_order_reused(
    client, publisher_wallet, consumer_wallet, web3
):
    environments = get_c2d_environments()
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        None,
        environments[0]["consumerAddress"],
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
            },
        ],
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
        },
        "consumerAddress": consumer_wallet.address,
        "compute": {
            "env": environments[0]["id"],
            "validUntil": get_future_valid_until(),
        },
    }

    response = client.post(
        BaseURLs.SERVICES_URL + "/initializeCompute",
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json["algorithm"] == {"validOrder": alg_tx_id}
    assert response.json["datasets"] == [{"validOrder": tx_id}]

    payload["datasets"][0]["transferTxId"] = "wrong_tx_id"
    response = client.post(
        BaseURLs.SERVICES_URL + "/initializeCompute",
        data=json.dumps(payload),
        content_type="application/json",
    )

    assert response.status_code == 200
    assert "datatoken" in response.json["datasets"][0].keys()
    assert "providerFee" in response.json["datasets"][0].keys()
