#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json

import pytest
from ocean_lib.common.agreements.service_types import ServiceTypes
from ocean_lib.models.data_token import DataToken

from ocean_provider.constants import BaseURLs
from ocean_provider.exceptions import RequestNotFound
from ocean_provider.utils.accounts import generate_auth_token
from ocean_provider.validation.algo import build_stage_output_dict
from ocean_provider.validation.requests import RBACValidator
from tests.helpers.compute_helpers import build_and_send_ddo_with_compute_service
from tests.test_helpers import (
    get_dataset_ddo_with_access_service,
    mint_tokens_and_wait,
    send_order,
)


def test_invalid_request_name():
    req = {"document": "My Doc"}
    with pytest.raises(RequestNotFound) as err:
        RBACValidator(request_name="MyRequest", request=req)
    assert err.value.args[0] == "Request name is not valid!"


encrypt_endpoint = BaseURLs.ASSETS_URL + "/encrypt"


def test_encrypt_request_payload():
    document = {
        "url": "http://localhost:8030" + encrypt_endpoint,
        "index": 0,
        "checksum": "foo_checksum",
        "contentLength": "4535431",
        "contentType": "text/csv",
        "encoding": "UTF-8",
        "compression": "zip",
    }
    req = {"document": json.dumps(document)}
    validator = RBACValidator(request_name="EncryptRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "encryptUrl"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": validator.provider_address,
    }


def test_initialize_request_payload(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_contract = DataToken(ddo.data_token_address)
    sa = ddo.get_service(ServiceTypes.ASSET_ACCESS)
    mint_tokens_and_wait(dt_contract, consumer_wallet, publisher_wallet)

    document = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "dataToken": ddo.data_token_address,
        "consumerAddress": consumer_wallet.address,
    }

    req = {"document": json.dumps(document)}
    validator = RBACValidator(request_name="InitializeRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "initialize"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": validator.provider_address,
    }
    assert payload["dids"][0]["did"] == validator.get_dids(sa.index)[0]["did"]
    assert (
        payload["dids"][0]["serviceId"] == validator.get_dids(sa.index)[0]["serviceId"]
    )


def test_access_request_payload(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_token = DataToken(ddo.data_token_address)

    mint_tokens_and_wait(dt_token, consumer_wallet, publisher_wallet)

    sa = ddo.get_service(ServiceTypes.ASSET_ACCESS)
    tx_id = send_order(client, ddo, dt_token, sa, consumer_wallet)

    document = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "dataToken": ddo.data_token_address,
        "consumerAddress": consumer_wallet.address,
        "signature": generate_auth_token(consumer_wallet),
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    req = {"document": json.dumps(document)}
    validator = RBACValidator(request_name="DownloadRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "access"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": validator.provider_address,
    }
    assert payload["dids"][0]["did"] == validator.get_dids(sa.index)[0]["did"]
    assert (
        payload["dids"][0]["serviceId"] == validator.get_dids(sa.index)[0]["serviceId"]
    )


def test_compute_payload_without_additional_inputs(
    client, publisher_wallet, consumer_wallet
):
    dataset, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    did = dataset.did
    sa = dataset.get_service(ServiceTypes.CLOUD_COMPUTE)
    alg_data_token = alg_ddo.data_token_address

    document = {
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

    req = {"document": json.dumps(document)}
    validator = RBACValidator(request_name="ComputeStartRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "compute"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": validator.provider_address,
    }
    assert payload["dids"][0]["did"] == validator.get_dids(sa.index)[0]["did"]
    assert (
        payload["dids"][0]["serviceId"] == validator.get_dids(sa.index)[0]["serviceId"]
    )
    assert payload["algos"][0]["did"] == validator.get_algos()[0]["did"]
    assert payload["algos"][0]["serviceId"] == validator.get_algos()[0]["serviceId"]


def test_compute_request_payload(client, publisher_wallet, consumer_wallet):
    dataset, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    did = dataset.did
    sa = dataset.get_service(ServiceTypes.CLOUD_COMPUTE)
    alg_data_token = alg_ddo.data_token_address

    ddo2, tx_id2, _, _ = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa2 = ddo2.get_service(ServiceTypes.CLOUD_COMPUTE)

    document = {
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
    req = {"document": json.dumps(document)}
    validator = RBACValidator(request_name="ComputeRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "compute"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "address": validator.provider_address,
    }
    assert payload["dids"][0]["did"] == validator.get_dids(sa.index)[0]["did"]
    assert (
        payload["dids"][0]["serviceId"] == validator.get_dids(sa.index)[0]["serviceId"]
    )
    assert payload["algos"][0]["did"] == validator.get_algos()[0]["did"]
    assert payload["algos"][0]["serviceId"] == validator.get_algos()[0]["serviceId"]
    assert (
        payload["additionalDids"][0]["did"] == validator.get_additional_dids()[0]["did"]
    )
    assert payload["additionalDids"][0]["serviceId"] == sa2.index
