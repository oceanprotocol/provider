#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.services import ServiceType
from ocean_provider.utils.provider_fees import get_provider_fees
from tests.test_helpers import (
    BLACK_HOLE_ADDRESS,
    get_dataset_ddo_disabled,
    get_dataset_ddo_with_denied_consumer,
    get_dataset_ddo_with_multiple_files,
    get_dataset_with_invalid_url_ddo,
    get_dataset_with_ipfs_url_ddo,
    get_registered_asset,
    initialize_service,
    mint_100_datatokens,
    start_order,
)


@pytest.mark.integration
@pytest.mark.parametrize("userdata", [False, "valid", "invalid"])
def test_download_service(client, publisher_wallet, consumer_wallet, web3, userdata):
    asset = get_registered_asset(publisher_wallet)
    service = asset.get_service_by_type(ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )
    tx_id, _ = start_order(
        web3,
        service.datatoken_address,
        consumer_wallet.address,
        service.index,
        get_provider_fees(asset.did, service, consumer_wallet.address),
        consumer_wallet,
    )

    payload = {
        "documentId": asset.did,
        "serviceId": service.id,
        "serviceType": service.type,
        "dataToken": service.datatoken_address,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    if userdata:
        payload["userdata"] = (
            '{"surname":"XXX", "age":12}' if userdata == "valid" else "cannotdecode"
        )

    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    # Consume using url index and signature (withOUT nonce), should fail
    payload["signature"] = sign_message(asset.did, consumer_wallet)
    print(">>>> Expecting request error from the download endpoint <<<<")

    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 400, f"{response.data}"

    # Consume using url index and signature (with nonce)
    nonce = str(datetime.now().timestamp())
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"


@pytest.mark.unit
def test_empty_payload(client):
    consume = client.get(
        BaseURLs.SERVICES_URL + "/download", data=None, content_type="application/json"
    )
    assert consume.status_code == 400


@pytest.mark.integration
def test_initialize_on_bad_url(client, publisher_wallet, consumer_wallet, web3):
    asset = get_dataset_with_invalid_url_ddo(client, publisher_wallet)
    service = asset.get_service_by_type(ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    response = initialize_service(
        client,
        asset.did,
        service.id,
        service.type,
        service.datatoken_address,
        consumer_wallet,
        raw_response=True,
    )
    assert "error" in response.json
    assert response.json["error"] == "Asset URL not found or not available."


@pytest.mark.integration
def test_initialize_on_ipfs_url(client, publisher_wallet, consumer_wallet, web3):
    asset = get_dataset_with_ipfs_url_ddo(client, publisher_wallet)
    service = asset.get_service_by_type(ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    datatoken, nonce, computeAddress, providerFees = initialize_service(
        client,
        asset.did,
        service.id,
        service.type,
        service.datatoken_address,
        consumer_wallet,
    )

    assert datatoken == service.datatoken_address


@pytest.mark.integration
def test_initialize_on_disabled_asset(client, publisher_wallet, consumer_wallet, web3):
    asset, real_asset = get_dataset_ddo_disabled(client, publisher_wallet)
    assert real_asset
    service = asset.get_service_by_type(ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    response = initialize_service(
        client,
        asset.did,
        service.id,
        service.type,
        service.datatoken_address,
        consumer_wallet,
        raw_response=True,
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

    service = asset.get_service_by_type(ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    response = initialize_service(
        client,
        asset.did,
        service.id,
        service.type,
        service.datatoken_address,
        consumer_wallet,
        raw_response=True,
    )
    assert "error" in response.json
    assert (
        response.json["error"]
        == f"Error: Access to asset {asset.did} was denied with code: ConsumableCodes.CREDENTIAL_IN_DENY_LIST."
    )


@pytest.mark.integration
def test_download_multiple_files(client, publisher_wallet, consumer_wallet, web3):
    asset = get_dataset_ddo_with_multiple_files(client, publisher_wallet)
    service = asset.get_service_by_type(ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    tx_id, _ = start_order(
        web3,
        service.datatoken_address,
        consumer_wallet.address,
        service.index,
        get_provider_fees(asset.did, service, consumer_wallet.address),
        consumer_wallet,
    )

    nonce = str(datetime.now().timestamp())
    _msg = f"{asset.did}{nonce}"

    # Consume using url index and auth token
    # (let the provider do the decryption)
    payload = {
        "documentId": asset.did,
        "serviceId": service.id,
        "serviceType": service.type,
        "dataToken": service.datatoken_address,
        "consumerAddress": consumer_wallet.address,
        "signature": sign_message(_msg, consumer_wallet),
        "transferTxId": tx_id,
        "fileIndex": 0,
        "nonce": nonce,
    }
    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"

    nonce = str(datetime.now().timestamp())
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["fileIndex"] = 1
    payload["nonce"] = nonce
    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"

    nonce = str(datetime.now().timestamp())
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["fileIndex"] = 2
    payload["nonce"] = nonce
    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"


@pytest.mark.integration
def test_asset_urls(client, publisher_wallet, consumer_wallet, web3):
    ddo = get_dataset_ddo_with_multiple_files(client, publisher_wallet)
    service = ddo.get_service_by_type(ServiceType.ACCESS)

    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    payload = {
        "documentId": ddo.did,
        "serviceId": service.id,
        "publisherAddress": publisher_wallet.address,
    }

    download_endpoint = BaseURLs.SERVICES_URL + "/assetUrls"

    # Consume using url index and signature (with nonce)
    nonce = str(datetime.now().timestamp())
    _msg = f"{ddo.did}{nonce}"
    payload["signature"] = sign_message(_msg, publisher_wallet)
    payload["nonce"] = nonce
    payload["publisherAddress"] = publisher_wallet.address
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"
    assert len(response.json) == 3
    assert (
        response.json[0]["url"]
        == "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"
    )
    assert response.json[0]["method"] == "GET"
    assert response.json[0]["type"] == "url"

    # use a different wallet, not the minter
    nonce = str(datetime.now().timestamp())
    _msg = f"{ddo.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    payload["publisherAddress"] = consumer_wallet.address
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 400, f"{response.data}"
    assert response.json["error"] == "Publisher address does not match minter."
