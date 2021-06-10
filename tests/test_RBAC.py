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
from ocean_provider.validation.requests import RBACValidator
from tests.test_helpers import mint_tokens_and_wait, get_dataset_ddo_with_access_service


def test_null_validator():
    with pytest.raises(RequestNotFound):
        RBACValidator()


encrypt_endpoint = BaseURLs.ASSETS_URL + "/encrypt"
init_endpoint = BaseURLs.ASSETS_URL + "/initialize"


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

    payload = dict(
        {
            "documentId": ddo.did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "dataToken": ddo.data_token_address,
            "consumerAddress": consumer_wallet.address,
        }
    )

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
