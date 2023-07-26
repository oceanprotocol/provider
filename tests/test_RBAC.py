#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
import json

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.exceptions import RequestNotFound
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.asset import Asset
from ocean_provider.utils.services import Service, ServiceType
from ocean_provider.validation.provider_requests import RBACValidator
from tests.ddo.ddo_sample1_v4 import json_dict as ddo_sample1_v4
from tests.ddo.ddo_sample_algorithm_v4 import algorithm_ddo_sample
from tests.helpers.compute_helpers import get_compute_signature
from tests.helpers.ddo_dict_builders import get_compute_service
from tests.helpers.nonce import build_nonce
from tests.test_helpers import get_first_service_by_type


@pytest.mark.unit
def test_invalid_request_name():
    req = dict()
    with pytest.raises(RequestNotFound) as err:
        RBACValidator(request_name="MyRequest", request=req)
    assert err.value.args[0] == "Request name is not valid!"


encrypt_endpoint = BaseURLs.SERVICES_URL + "/encrypt"


@pytest.mark.unit
def test_encrypt_request_payload(consumer_wallet, publisher_wallet, monkeypatch):
    monkeypatch.setenv("PRIVATE_PROVIDER", "1")
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
        "data": json.dumps(document),
        "publisherAddress": publisher_wallet.address,
    }
    validator = RBACValidator(request_name="EncryptRequest", request=req)
    payload = validator.build_payload()

    assert validator.request == req
    assert payload["eventType"] == "encryptUrl"
    assert payload["providerAccess"] == "private"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "value": publisher_wallet.address,
    }


@pytest.mark.unit
def test_wrong_encrypt_request_payload(consumer_wallet, publisher_wallet, monkeypatch):
    monkeypatch.setenv("PRIVATE_PROVIDER", "1")
    req = {
        "publisherAddress": publisher_wallet.address,
    }
    validator = RBACValidator(request_name="EncryptRequest", request=req)
    with pytest.raises(Exception) as err:
        validator.build_payload()
    assert err.value.args[0] == "Data to encrypt is empty."


@pytest.mark.unit
def test_initialize_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address, web3
):
    asset = Asset(ddo_sample1_v4)
    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    req = {
        "documentId": asset.did,
        "serviceId": service.id,
        "datatoken": service.datatoken_address,
        "consumerAddress": consumer_wallet.address,
    }

    validator = RBACValidator(request_name="InitializeRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "initialize"
    assert payload["providerAccess"] == "public"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "value": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == asset.did
    assert payload["dids"][0]["serviceId"] == service.id


@pytest.mark.unit
def test_access_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address, web3
):
    asset = Asset(ddo_sample1_v4)
    service = get_first_service_by_type(asset, ServiceType.ACCESS)

    req = {
        "documentId": asset.did,
        "serviceId": service.id,
        "datatoken": service.datatoken_address,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": "0xsometx",
        "fileIndex": 0,
    }

    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"
    req["signature"] = sign_message(_msg, consumer_wallet)
    req["nonce"] = nonce

    validator = RBACValidator(request_name="DownloadRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "access"
    assert payload["providerAccess"] == "public"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "value": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == asset.did
    assert payload["dids"][0]["serviceId"] == service.id


@pytest.mark.unit
def test_compute_payload_without_additional_inputs(
    client, publisher_wallet, consumer_wallet, provider_address
):
    ddo_sample1 = copy.deepcopy(ddo_sample1_v4)
    ddo = Asset(ddo_sample1)
    ddo.services.append(
        Service.from_json(1, get_compute_service(None, None, "0x0", "0x0"))
    )

    alg_ddo = Asset(algorithm_ddo_sample)
    sa = get_first_service_by_type(alg_ddo, ServiceType.COMPUTE)
    sa_compute = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)
    req = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": "0xsometx",
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": "0xsomeothertx",
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
    }

    validator = RBACValidator(request_name="ComputeStartRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "compute"
    assert payload["providerAccess"] == "public"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "value": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == ddo.did
    assert payload["dids"][0]["serviceId"] == sa.id
    assert payload["algos"][0]["did"] == alg_ddo.did
    assert payload["algos"][0]["serviceId"] == sa_compute.id


@pytest.mark.unit
def test_compute_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address
):
    ddo_sample1 = copy.deepcopy(ddo_sample1_v4)
    ddo = Asset(ddo_sample1)
    ddo.services.append(
        Service.from_json(
            1,
            get_compute_service(
                None,
                None,
                "0x0000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000",
            ),
        )
    )

    alg_ddo = Asset(algorithm_ddo_sample)
    sa = get_first_service_by_type(alg_ddo, ServiceType.COMPUTE)
    sa_compute = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    ddo_sample2 = copy.deepcopy(ddo_sample1_v4)
    ddo_sample2["did"] = "0xsomeotherdid"
    ddo2 = Asset(ddo_sample2)
    sa2 = get_first_service_by_type(ddo2, ServiceType.ACCESS)

    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    req = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": "0xsometx",
        },
        "algorithm": {
            "documentId": alg_ddo.did,
            "transferTxId": "0xsomeothertx",
            "serviceId": sa_compute.id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
        "additionalDatasets": [
            {
                "documentId": ddo2.did,
                "transferTxId": "0xsomeevenothertx",
                "serviceId": sa2.id,
            }
        ],
    }
    validator = RBACValidator(request_name="ComputeRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "compute"
    assert payload["providerAccess"] == "public"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "value": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == ddo.did
    assert payload["dids"][0]["serviceId"] == sa.id
    assert payload["algos"][0]["did"] == alg_ddo.did
    assert payload["algos"][0]["serviceId"] == sa_compute.id
    assert payload["additionalDids"][0]["did"] == ddo2.did
    assert payload["additionalDids"][0]["serviceId"] == sa2.id
