#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json

import pytest

from ocean_provider.constants import BaseURLs
from ocean_provider.exceptions import RequestNotFound
from ocean_provider.utils.accounts import generate_auth_token
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.services import ServiceType
from ocean_provider.validation.algo import build_stage_output_dict
from ocean_provider.validation.provider_requests import RBACValidator
from tests.helpers.compute_helpers import (
    build_and_send_ddo_with_compute_service,
    get_registered_asset,
    get_web3,
)
from tests.test_helpers import (
    BLACK_HOLE_ADDRESS,
    get_dataset_asset_with_access_service,
    mint_100_datatokens,
    start_order,
)


def test_invalid_request_name():
    req = dict()
    with pytest.raises(RequestNotFound) as err:
        RBACValidator(request_name="MyRequest", request=req)
    assert err.value.args[0] == "Request name is not valid!"


encrypt_endpoint = BaseURLs.SERVICES_URL + "/encrypt"


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
        "value": publisher_wallet.address,
    }


def test_initialize_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address, web3
):
    asset = get_dataset_asset_with_access_service(client, publisher_wallet)
    service = asset.get_service_by_type(ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    req = {
        "documentId": asset.did,
        "serviceId": service.index,
        "serviceType": service.type,
        "dataToken": service.datatoken_address,
        "consumerAddress": consumer_wallet.address,
    }

    validator = RBACValidator(request_name="InitializeRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "initialize"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "value": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == asset.did
    assert payload["dids"][0]["serviceId"] == service.index


def test_access_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address, web3
):
    asset = get_dataset_asset_with_access_service(client, publisher_wallet)
    service = asset.get_service_by_type(ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    tx_id, _ = start_order(
        web3,
        service.datatoken_address,
        consumer_wallet.address,
        to_wei(1),
        service.index,
        BLACK_HOLE_ADDRESS,
        BLACK_HOLE_ADDRESS,
        0,
        consumer_wallet,
    )

    req = {
        "documentId": asset.did,
        "serviceId": service.index,
        "serviceType": service.type,
        "dataToken": service.datatoken_address,
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
        "value": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == asset.did
    assert payload["dids"][0]["serviceId"] == service.index


def test_compute_payload_without_additional_inputs(
    client, publisher_wallet, consumer_wallet, provider_address
):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa_compute = ddo.get_service_by_type(ServiceType.COMPUTE)

    req = {
        "signature": generate_auth_token(consumer_wallet),
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "dataToken": sa.datatoken_address,
        "output": build_stage_output_dict(
            dict(), sa.service_endpoint, consumer_wallet.address, publisher_wallet
        ),
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": sa_compute.datatoken_address,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = RBACValidator(request_name="ComputeStartRequest", request=req)
    payload = validator.build_payload()
    assert validator.request == req
    assert payload["eventType"] == "compute"
    assert payload["component"] == "provider"
    assert payload["credentials"] == {
        "type": "address",
        "value": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == ddo.did
    assert payload["dids"][0]["serviceId"] == sa.index
    assert payload["algos"][0]["did"] == alg_ddo.did
    assert payload["algos"][0]["serviceId"] == sa_compute.index


def test_compute_request_payload(
    client, publisher_wallet, consumer_wallet, provider_address
):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa_compute = ddo.get_service_by_type(ServiceType.COMPUTE)

    ddo2 = get_registered_asset(
        publisher_wallet,
        custom_services="vanilla_compute",
        custom_services_args=[
            {
                "did": alg_ddo.did,
                "filesChecksum": "TODO",
                "containerSectionChecksum": "TODO",
            }
        ],
    )

    web3 = get_web3()
    sa2 = ddo2.get_service_by_type(ServiceType.COMPUTE)
    mint_100_datatokens(
        web3, sa2.datatoken_address, consumer_wallet.address, publisher_wallet
    )
    tx_id2, _ = start_order(
        web3,
        sa2.datatoken_address,
        consumer_wallet.address,
        to_wei(1),
        sa2.index,
        BLACK_HOLE_ADDRESS,
        BLACK_HOLE_ADDRESS,
        0,
        consumer_wallet,
    )

    req = {
        "signature": generate_auth_token(consumer_wallet),
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "dataToken": sa.datatoken_address,
        "output": build_stage_output_dict(
            dict(), sa.service_endpoint, consumer_wallet.address, publisher_wallet
        ),
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": sa_compute.datatoken_address,
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
        "value": consumer_wallet.address,
    }
    assert payload["dids"][0]["did"] == ddo.did
    assert payload["dids"][0]["serviceId"] == sa.index
    assert payload["algos"][0]["did"] == alg_ddo.did
    assert payload["algos"][0]["serviceId"] == sa_compute.index
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
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa_compute = ddo.get_service_by_type(ServiceType.COMPUTE)

    req = {
        "signature": generate_auth_token(consumer_wallet),
        "documentId": ddo.did,
        "serviceId": sa.index,
        "serviceType": sa.type,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "output": build_stage_output_dict(
            dict(), sa.service_endpoint, consumer_wallet.address, publisher_wallet
        ),
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": sa_compute.datatoken_address,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = RBACValidator(request_name="ComputeRequest", request=req)
    assert validator.fails() is False
