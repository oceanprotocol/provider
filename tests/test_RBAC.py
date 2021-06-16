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
from ocean_provider.validation.requests import RBACValidator
from tests.test_helpers import (
    mint_tokens_and_wait,
    get_dataset_ddo_with_access_service,
    send_order,
)


def test_null_validator():
    with pytest.raises(RequestNotFound):
        RBACValidator(request=None)


encrypt_endpoint = BaseURLs.ASSETS_URL + "/encrypt"
init_endpoint = BaseURLs.ASSETS_URL + "/initialize"
download_endpoint = BaseURLs.ASSETS_URL + "/download"


def test_encrypt_request_payload():
    document = [
        {
            "url": "http://localhost:8030" + encrypt_endpoint,
            "index": 0,
            "checksum": "foo_checksum",
            "contentLength": "4535431",
            "contentType": "text/csv",
            "encoding": "UTF-8",
            "compression": "zip",
        }
    ]
    req = {"document": json.dumps(document[0])}
    validator = RBACValidator(request_name="EncryptRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload
    assert payload["eventType"] == validator.action
    assert payload["component"] == validator.component
    assert payload["credentials"] == validator.credentials


def test_initialize_request_payload(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_contract = DataToken(ddo.data_token_address)
    sa = ddo.get_service(ServiceTypes.ASSET_ACCESS)
    mint_tokens_and_wait(dt_contract, consumer_wallet, publisher_wallet)

    payload = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "dataToken": ddo.data_token_address,
        "consumerAddress": consumer_wallet.address,
    }

    request_url = (
        init_endpoint + "?" + "&".join([f"{k}={v}" for k, v in payload.items()])
    )
    document = {
        "url": request_url,
        "index": 0,
        "checksum": "foo_checksum",
        "contentLength": "4535431",
        "contentType": "text/csv",
        "encoding": "UTF-8",
        "compression": "zip",
    }
    req = {"document": json.dumps(document)}
    validator = RBACValidator(
        request_name="InitializeRequest", request=req, assets=[ddo]
    )
    validator_payload = validator.build_payload()
    assert validator.request == req
    assert validator_payload
    assert validator_payload["eventType"] == validator.action
    assert validator_payload["component"] == validator.component
    assert validator_payload["credentials"] == validator.credentials
    assert validator.assets[0].did == ddo.did
    assert validator_payload["dids"][0]["did"] == validator.assets[0].did
    assert validator_payload["dids"][0]["serviceId"] == sa.index


def test_access_request_payload(client, publisher_wallet, consumer_wallet):
    ddo = get_dataset_ddo_with_access_service(client, publisher_wallet)
    dt_token = DataToken(ddo.data_token_address)

    mint_tokens_and_wait(dt_token, consumer_wallet, publisher_wallet)

    sa = ddo.get_service(ServiceTypes.ASSET_ACCESS)
    tx_id = send_order(client, ddo, dt_token, sa, consumer_wallet)

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
    request_url = (
        download_endpoint + "?" + "&".join([f"{k}={v}" for k, v in payload.items()])
    )
    document = {
        "url": request_url,
        "index": 0,
        "checksum": "foo_checksum",
        "contentLength": "4535431",
        "contentType": "text/csv",
        "encoding": "UTF-8",
        "compression": "zip",
    }
    req = {"document": json.dumps(document)}
    validator = RBACValidator(request_name="DownloadRequest", request=req, assets=[ddo])
    validator_payload = validator.build_payload()
    assert validator.request == req
    assert validator_payload
    assert validator_payload["eventType"] == validator.action
    assert validator_payload["component"] == validator.component
    assert validator_payload["credentials"] == validator.credentials
    assert validator.assets[0].did == ddo.did
    assert validator_payload["dids"][0]["did"] == validator.assets[0].did
    assert validator_payload["dids"][0]["serviceId"] == sa.index
