#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json

import pytest

from ocean_provider.constants import BaseURLs
from ocean_provider.exceptions import RequestNotFound
from ocean_provider.utils.accounts import generate_auth_token
from ocean_provider.utils.datatoken import get_dt_contract
from ocean_provider.validation.algo import build_stage_output_dict
from ocean_provider.validation.provider_requests import RBACValidator
from tests.helpers.compute_helpers import build_and_send_ddo_with_compute_service
from tests.test_helpers import (
    get_dataset_ddo_with_access_service,
    mint_tokens_and_wait,
    send_order,
)


def test_invalid_request_name():
    req = dict()
    with pytest.raises(RequestNotFound) as err:
        RBACValidator(request_name="MyRequest", request=req)
    assert err.value.args[0] == "Request name is not valid!"


encrypt_endpoint = BaseURLs.ASSETS_URL + "/encrypt"


def test_encrypt_request_payload(consumer_wallet, publisher_wallet):
    document = {
        "url": "http://localhost:8030" + encrypt_endpoint,
        "index": 0,
        "checksum": "foo_checksum",
        "contentLength": "4535431",
        "contentType": "text/csv",
        "encoding": "UTF-8",
        "compression": "zip",
    }
    req = {
        "document": json.dumps(document),
        "publisherAddress": publisher_wallet.address,
    }
    validator = RBACValidator(request_name="EncryptRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "encryptUrl"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": publisher_wallet.address,
    }


def test_initialize_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address, web3
):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_contract = get_dt_contract(web3, ddo.data_token_address)
    sa = ddo.get_service("access")
    mint_tokens_and_wait(dt_contract, consumer_wallet, publisher_wallet)

    req = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "dataToken": ddo.data_token_address,
        "consumerAddress": consumer_wallet.address,
    }

    validator = RBACValidator(request_name="InitializeRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "initialize"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == ddo.did
    assert payload["dids"][0]["serviceId"] == sa.index


def test_access_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address, web3
):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_token = get_dt_contract(web3, ddo.data_token_address)

    mint_tokens_and_wait(dt_token, consumer_wallet, publisher_wallet)

    sa = ddo.get_service("access")
    tx_id = send_order(client, ddo, dt_token, sa, consumer_wallet)

    req = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "dataToken": ddo.data_token_address,
        "consumerAddress": consumer_wallet.address,
        "signature": generate_auth_token(consumer_wallet),
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    validator = RBACValidator(request_name="DownloadRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "access"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == ddo.did
    assert payload["dids"][0]["serviceId"] == sa.index


def test_compute_payload_without_additional_inputs(
    client, publisher_wallet, consumer_wallet, provider_address
):
    dataset, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    did = dataset.did
    sa = dataset.get_service("compute")
    alg_data_token = alg_ddo.data_token_address

    req = {
        "signature": generate_auth_token(consumer_wallet),
        "documentId": did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "dataToken": dataset.data_token_address,
        "output": build_stage_output_dict(
            dict(), sa.service_endpoint, consumer_wallet.address, publisher_wallet
        ),
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = RBACValidator(request_name="ComputeStartRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "compute"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == dataset.did
    assert payload["dids"][0]["serviceId"] == sa.index
    assert payload["algos"][0]["did"] == alg_ddo.did
    assert payload["algos"][0]["serviceId"] == sa.index


def test_compute_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address
):
    dataset, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    did = dataset.did
    sa = dataset.get_service("compute")
    alg_data_token = alg_ddo.data_token_address

    ddo2, tx_id2, _, _ = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa2 = ddo2.get_service("compute")

    req = {
        "signature": generate_auth_token(consumer_wallet),
        "documentId": did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "dataToken": dataset.data_token_address,
        "output": build_stage_output_dict(
            dict(), sa.service_endpoint, consumer_wallet.address, publisher_wallet
        ),
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInputs": [
            {"documentId": ddo2.did, "transferTxId": tx_id2, "serviceId": sa2.index}
        ],
    }
    validator = RBACValidator(request_name="ComputeRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "compute"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == dataset.did
    assert payload["dids"][0]["serviceId"] == sa.index
    assert payload["algos"][0]["did"] == alg_ddo.did
    assert payload["algos"][0]["serviceId"] == sa.index
    assert payload["additionalDids"][0]["did"] == ddo2.did
    assert payload["additionalDids"][0]["serviceId"] == sa2.index


def test_fails(
    monkeypatch,
    client,
    provider_wallet,
    consumer_wallet,
    consumer_address,
    publisher_wallet,
):
    """Tests possible failures of the compute request."""
    monkeypatch.setenv("RBAC_SERVER_URL", "http://172.15.0.8:3000")
    dataset, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    did = dataset.did
    sa = dataset.get_service("compute")
    alg_data_token = alg_ddo.data_token_address

    # output key is invalid
    req = {
        "signature": generate_auth_token(consumer_wallet),
        "documentId": did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "output": "this can not be decoded",
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = RBACValidator(request_name="ComputeRequest", request=req)
    assert validator.fails() is False
