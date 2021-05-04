#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

from ocean_lib.common.agreements.service_types import ServiceTypes
from ocean_lib.models.data_token import DataToken
from ocean_lib.web3_internal.transactions import sign_hash
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import generate_auth_token
from tests.test_helpers import (
    get_dataset_ddo_with_access_service,
    get_dataset_with_invalid_url_ddo,
    get_dataset_with_ipfs_url_ddo,
    get_nonce,
    mint_tokens_and_wait,
    send_order,
)


def test_download_service(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_token = DataToken(ddo.data_token_address)

    mint_tokens_and_wait(dt_token, consumer_wallet, publisher_wallet)

    sa = ddo.get_service(ServiceTypes.ASSET_ACCESS)
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

    # Consume using url index and signature (withOUT nonce), should fail
    _hash = add_ethereum_prefix_and_hash_msg(ddo.did)
    payload["signature"] = sign_hash(_hash, consumer_wallet)
    print(">>>> Expecting InvalidSignatureError from the download endpoint <<<<")

    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 400, f"{response.data}"

    # Consume using url index and signature (with nonce)
    nonce = get_nonce(client, consumer_wallet.address)
    _hash = add_ethereum_prefix_and_hash_msg(f"{ddo.did}{nonce}")
    payload["signature"] = sign_hash(_hash, consumer_wallet)
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"


def test_empty_payload(client):
    consume = client.get(
        BaseURLs.ASSETS_URL + "/download", data=None, content_type="application/json"
    )
    assert consume.status_code == 400


def test_initialize_on_bad_url(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_with_invalid_url_ddo(client, publisher_wallet)
    dt_contract = DataToken(ddo.data_token_address)
    sa = ddo.get_service(ServiceTypes.ASSET_ACCESS)

    send_order(client, ddo, dt_contract, sa, consumer_wallet, expect_failure=True)


def test_initialize_on_ipfs_url(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_with_ipfs_url_ddo(client, publisher_wallet)
    dt_contract = DataToken(ddo.data_token_address)
    sa = ddo.get_service(ServiceTypes.ASSET_ACCESS)

    send_order(client, ddo, dt_contract, sa, consumer_wallet)
