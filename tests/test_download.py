#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

from ocean_lib.common.agreements.service_agreement import ServiceAgreement
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


def dummy_callback(*_):
    pass


def test_download_service(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_address = ddo.as_dictionary()["dataToken"]
    dt_token = DataToken(dt_address)
    mint_tokens_and_wait(dt_token, consumer_wallet, publisher_wallet)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    tx_id = send_order(client, ddo, dt_token, sa, consumer_wallet)
    index = 0
    download_endpoint = BaseURLs.ASSETS_URL + "/download"
    # Consume using url index and auth token
    # (let the provider do the decryption)
    payload = dict(
        {
            "documentId": ddo.did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "dataToken": dt_address,
            "consumerAddress": consumer_wallet.address,
        }
    )
    payload["signature"] = generate_auth_token(consumer_wallet)
    payload["transferTxId"] = tx_id
    payload["fileIndex"] = index
    request_url = (
        download_endpoint + "?" + "&".join([f"{k}={v}" for k, v in payload.items()])
    )
    response = client.get(request_url)
    assert response.status_code == 200, f"{response.data}"

    # Consume using url index and signature (withOUT nonce), should fail
    _hash = add_ethereum_prefix_and_hash_msg(ddo.did)
    payload["signature"] = sign_hash(_hash, consumer_wallet)
    request_url = (
        download_endpoint + "?" + "&".join([f"{k}={v}" for k, v in payload.items()])
    )
    print(
        ">>>> Expecting InvalidSignatureError from the download endpoint <<<<"
    )  # noqa
    response = client.get(request_url)
    assert response.status_code == 400, f"{response.data}"

    # Consume using url index and signature (with nonce)
    nonce = get_nonce(client, consumer_wallet.address)
    _hash = add_ethereum_prefix_and_hash_msg(f"{ddo.did}{nonce}")
    payload["signature"] = sign_hash(_hash, consumer_wallet)
    request_url = (
        download_endpoint + "?" + "&".join([f"{k}={v}" for k, v in payload.items()])
    )
    response = client.get(request_url)
    assert response.status_code == 200, f"{response.data}"


def test_empty_payload(client):
    consume = client.get(
        BaseURLs.ASSETS_URL + "/download", data=None, content_type="application/json"
    )
    assert consume.status_code == 400

    publish = client.post(
        BaseURLs.ASSETS_URL + "/encrypt", data=None, content_type="application/json"
    )
    assert publish.status_code == 400


def test_exec_endpoint():
    pass


def test_asset_info(client, publisher_wallet):
    asset = get_dataset_ddo_with_access_service(client, publisher_wallet)
    request_url = BaseURLs.ASSETS_URL + "/fileinfo"
    data = {"did": asset.did, "checksum": "true"}
    response = client.post(request_url, json=data)
    result = response.get_json()
    assert response.status == "200 OK"
    assert isinstance(result, list)
    assert len(result) == 1
    for file_info in result:
        assert file_info["contentLength"]
        assert file_info["contentType"] == "text/plain; charset=utf-8"
        assert file_info["valid"] is True
        assert (
            file_info["checksum"]
            == "1f7c17bed455f484f4d5ebc581cde6bc059977ef1e143b52a703f18b89c86a22"
        )  # noqa
        assert file_info["checksumType"] == "sha256"

    asset = get_dataset_with_invalid_url_ddo(client, publisher_wallet)
    request_url = BaseURLs.ASSETS_URL + "/fileinfo"
    data = {"did": asset.did}
    response = client.post(request_url, json=data)
    result = response.get_json()
    assert response.status == "200 OK"
    assert isinstance(result, list)
    assert len(result) == 1
    for file_info in result:
        assert (
            "contentLength" not in file_info or not file_info["contentLength"]
        )  # noqa
        assert file_info["valid"] is False


def test_check_url_good(client):
    request_url = BaseURLs.ASSETS_URL + "/fileinfo"
    data = {
        "url": "https://s3.amazonaws.com/testfiles.oceanprotocol.com/info.0.json"
    }  # noqa
    response = client.post(request_url, json=data)
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["contentLength"] == "1161"
        assert file_info["contentType"] == "application/json"
        assert file_info["valid"] is True


def test_check_url_bad(client):
    request_url = BaseURLs.ASSETS_URL + "/fileinfo"
    data = {"url": "http://127.0.0.1/not_valid"}
    response = client.post(request_url, json=data)
    result = response.get_json()
    assert response.status == "200 OK"
    for file_info in result:
        assert file_info["valid"] is False


def test_initialize_on_bad_url(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_with_invalid_url_ddo(client, publisher_wallet)
    data_token = ddo.data_token_address
    dt_contract = DataToken(data_token)
    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)

    send_order(client, ddo, dt_contract, sa, consumer_wallet, expect_failure=True)


def test_initialize_on_ipfs_url(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_with_ipfs_url_ddo(client, publisher_wallet)
    data_token = ddo.data_token_address
    dt_contract = DataToken(data_token)
    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)

    send_order(client, ddo, dt_contract, sa, consumer_wallet)
