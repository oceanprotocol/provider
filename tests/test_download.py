#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import pytest

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import generate_auth_token, sign_message
from ocean_provider.utils.datatoken import get_dt_contract
from tests.test_helpers import (
    get_dataset_ddo_disabled,
    get_dataset_ddo_with_access_service,
    get_dataset_ddo_with_denied_consumer,
    get_dataset_ddo_with_multiple_files,
    get_dataset_with_invalid_url_ddo,
    get_dataset_with_ipfs_url_ddo,
    get_nonce,
    mint_tokens_and_wait,
    send_order,
)


@pytest.mark.parametrize("userdata", [False, "valid", "invalid"])
def test_download_service(client, publisher_wallet, consumer_wallet, web3, userdata):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_token = get_dt_contract(web3, ddo.data_token_address)

    mint_tokens_and_wait(dt_token, consumer_wallet, publisher_wallet)

    sa = ddo.get_service("access")
    tx_id = send_order(client, ddo, dt_token, sa, consumer_wallet)

    # Consume using url index and auth token
    # (let the provider do the decryption)
    payload = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "dataToken": ddo.data_token_address,
        "consumerAddress": consumer_wallet.address,
        "signature": generate_auth_token(consumer_wallet),
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    if userdata:
        payload["userdata"] = (
            '{"surname":"XXX", "age":12}' if userdata == "valid" else "cannotdecode"
        )

    download_endpoint = BaseURLs.ASSETS_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"

    # Consume using url index and signature (withOUT nonce), should fail
    payload["signature"] = sign_message(ddo.did, consumer_wallet)
    print(">>>> Expecting InvalidSignatureError from the download endpoint <<<<")

    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 400, f"{response.data}"

    # Consume using url index and signature (with nonce)
    nonce = get_nonce(client, consumer_wallet.address)
    _msg = f"{ddo.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"


def test_empty_payload(client):
    consume = client.get(
        BaseURLs.ASSETS_URL + "/download", data=None, content_type="application/json"
    )
    assert consume.status_code == 400


def test_initialize_on_bad_url(client, publisher_wallet, consumer_wallet, web3):
    ddo = get_dataset_with_invalid_url_ddo(client, publisher_wallet)
    dt_contract = get_dt_contract(web3, ddo.data_token_address)
    sa = ddo.get_service("access")

    send_order(client, ddo, dt_contract, sa, consumer_wallet, expect_failure=True)


def test_initialize_on_ipfs_url(client, publisher_wallet, consumer_wallet, web3):
    ddo = get_dataset_with_ipfs_url_ddo(client, publisher_wallet)
    dt_contract = get_dt_contract(web3, ddo.data_token_address)
    sa = ddo.get_service("access")

    send_order(client, ddo, dt_contract, sa, consumer_wallet)


def test_initialize_on_disabled_asset(client, publisher_wallet, consumer_wallet, web3):
    ddo = get_dataset_ddo_disabled(client, publisher_wallet)
    assert ddo.is_disabled
    dt_contract = get_dt_contract(web3, ddo.data_token_address)
    sa = ddo.get_service("access")
    mint_tokens_and_wait(dt_contract, consumer_wallet, publisher_wallet)

    send_order(client, ddo, dt_contract, sa, consumer_wallet, expect_failure=True)


def test_initialize_on_asset_with_custom_credentials(
    client, publisher_wallet, consumer_wallet, web3
):
    ddo = get_dataset_ddo_with_denied_consumer(
        client, publisher_wallet, consumer_wallet.address
    )

    assert ddo.requires_address_credential
    assert consumer_wallet.address not in ddo.allowed_addresses
    dt_contract = get_dt_contract(web3, ddo.data_token_address)
    sa = ddo.get_service("access")
    mint_tokens_and_wait(dt_contract, consumer_wallet, publisher_wallet)

    send_order(client, ddo, dt_contract, sa, consumer_wallet, expect_failure=True)


def test_download_multiple_files(client, publisher_wallet, consumer_wallet, web3):
    ddo = get_dataset_ddo_with_multiple_files(client, publisher_wallet)
    dt_token = get_dt_contract(web3, ddo.data_token_address)

    mint_tokens_and_wait(dt_token, consumer_wallet, publisher_wallet)

    sa = ddo.get_service("access")
    tx_id = send_order(client, ddo, dt_token, sa, consumer_wallet)

    # Consume using url index and auth token
    # (let the provider do the decryption)
    payload = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "dataToken": ddo.data_token_address,
        "consumerAddress": consumer_wallet.address,
        "signature": generate_auth_token(consumer_wallet),
        "transferTxId": tx_id,
        "fileIndex": 0,
    }
    download_endpoint = BaseURLs.ASSETS_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"

    payload["signature"] = generate_auth_token(consumer_wallet)
    payload["fileIndex"] = 1
    download_endpoint = BaseURLs.ASSETS_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"

    payload["signature"] = generate_auth_token(consumer_wallet)
    payload["fileIndex"] = 2
    download_endpoint = BaseURLs.ASSETS_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"


def test_asset_urls(client, publisher_wallet, consumer_wallet, web3):
    ddo = get_dataset_ddo_with_multiple_files(client, publisher_wallet)
    dt_token = get_dt_contract(web3, ddo.data_token_address)

    mint_tokens_and_wait(dt_token, consumer_wallet, publisher_wallet)

    sa = ddo.get_service("access")

    payload = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "publisherAddress": publisher_wallet.address,
    }

    download_endpoint = BaseURLs.ASSETS_URL + "/assetUrls"

    # Consume using url index and signature (with nonce)
    nonce = get_nonce(client, publisher_wallet.address)
    _msg = f"{ddo.did}{nonce}"
    payload["signature"] = sign_message(_msg, publisher_wallet)
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"
    assert len(response.json) == 3
    assert (
        "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"
        in response.json
    )

    # use a different wallet, not the minter
    nonce = get_nonce(client, consumer_wallet.address)
    _msg = f"{ddo.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["publisherAddress"] = consumer_wallet.address
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 400, f"{response.data}"
    assert response.json["error"] == "Publisher address does not match minter."
