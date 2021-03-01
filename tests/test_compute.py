#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import json

from ocean_lib.models.data_token import DataToken
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_lib.web3_internal.web3helper import Web3Helper
from ocean_provider.constants import BaseURLs
from ocean_provider.run import get_provider_address, get_services_endpoints
from ocean_provider.util import build_stage_output_dict
from ocean_provider.utils.basics import get_provider_wallet
from ocean_utils.agreements.service_agreement import ServiceAgreement
from ocean_utils.agreements.service_types import ServiceTypes
from tests.test_helpers import (
    build_and_send_ddo_with_compute_service,
    comp_ds_no_rawalgo,
    get_compute_job_info,
    get_consumer_wallet,
    get_nonce,
    get_possible_compute_job_status_text,
    get_publisher_wallet,
    mint_tokens_and_wait,
    send_order,
)


def test_get_provider_address(client):
    get_response = client.get("/")
    result = get_response.get_json()
    provider_address = get_provider_address()
    assert "providerAddress" in result
    assert provider_address == get_provider_wallet().address
    assert result["providerAddress"] == get_provider_wallet().address
    assert get_response.status == "200 OK"


def test_compute_expose_endpoints(client):
    get_response = client.get("/")
    result = get_response.get_json()
    services_endpoints = get_services_endpoints()
    assert "serviceEndpoints" in result
    assert "software" in result
    assert "version" in result
    assert "network-url" in result
    assert "providerAddress" in result
    assert "computeAddress" in result
    assert get_response.status == "200 OK"
    assert len(result["serviceEndpoints"]) == len(services_endpoints)


def test_compute_norawalgo_allowed(client):
    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()

    # publish a dataset asset
    dataset_ddo_w_compute_service = comp_ds_no_rawalgo(client, pub_wallet)
    did = dataset_ddo_w_compute_service.did
    ddo = dataset_ddo_w_compute_service

    data_token = dataset_ddo_w_compute_service.data_token_address
    dt_contract = DataToken(data_token)
    mint_tokens_and_wait(dt_contract, cons_wallet, pub_wallet)

    # CHECKPOINT 1
    algorithm_meta = {
        "rawcode": "console.log('Hello world'!)",
        "format": "docker-image",
        "version": "0.1",
        "container": {"entrypoint": "node $ALGO", "image": "node", "tag": "10"},
    }
    # prepare parameter values for the compute endpoint
    # signature, documentId, consumerAddress, and algorithmDid or algorithmMeta

    sa = ServiceAgreement.from_ddo(
        ServiceTypes.CLOUD_COMPUTE, dataset_ddo_w_compute_service
    )
    tx_id = send_order(client, ddo, dt_contract, sa, cons_wallet)
    nonce = get_nonce(client, cons_wallet.address)

    # prepare consumer signature on did
    msg = f"{cons_wallet.address}{did}{nonce}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_wallet)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": cons_wallet.address,
            "transferTxId": tx_id,
            "dataToken": data_token,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, cons_wallet.address, pub_wallet
            ),
            "algorithmMeta": algorithm_meta,
            "algorithmDataToken": "",
        }
    )

    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    response = client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )
    assert (
        response.status == "400 BAD REQUEST"
    ), f"start compute job failed: {response.status} , {response.data}"


def test_compute_specific_algo_dids(client):
    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()

    (
        _,
        did,
        tx_id,
        sa,
        data_token,
        alg_ddo,
        alg_data_token,
        _,
        _,
    ) = build_and_send_ddo_with_compute_service(client, asset_type="specific_algo_dids")
    nonce = get_nonce(client, cons_wallet.address)

    # prepare consumer signature on did
    msg = f"{cons_wallet.address}{did}{nonce}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_wallet)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": cons_wallet.address,
            "transferTxId": tx_id,
            "dataToken": data_token,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, cons_wallet.address, pub_wallet
            ),
            "algorithmDid": alg_ddo.did,
            "algorithmDataToken": alg_data_token,
        }
    )

    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    response = client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )

    assert (
        response.status == "400 BAD REQUEST"
    ), f"start compute job failed: {response.status} , {response.data}"


def test_compute(client):
    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()

    (
        _,
        did,
        tx_id,
        sa,
        data_token,
        alg_ddo,
        alg_data_token,
        _,
        alg_tx_id,
    ) = build_and_send_ddo_with_compute_service(client)

    nonce = get_nonce(client, cons_wallet.address)
    # prepare consumer signature on did
    msg = f"{cons_wallet.address}{did}{str(nonce)}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_wallet)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": cons_wallet.address,
            "transferTxId": tx_id,
            "dataToken": data_token,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, cons_wallet.address, pub_wallet
            ),
            "algorithmDid": alg_ddo.did,
            "algorithmDataToken": alg_data_token,
            "algorithmTransferTxId": alg_tx_id,
        }
    )

    # Start compute using invalid signature (withOUT nonce), should fail
    msg = f"{cons_wallet.address}{did}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    payload["signature"] = Web3Helper.sign_hash(_hash, cons_wallet)
    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    response = client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )

    assert response.status_code == 400, f"{response.data}"

    # Start compute with valid signature
    payload["signature"] = signature
    response = client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )
    assert response.status == "200 OK", f"start compute job failed: {response.data}"
    job_info = response.json[0]
    print(f"got response from starting compute job: {job_info}")
    job_id = job_info.get("jobId", "")

    nonce = get_nonce(client, cons_wallet.address)
    msg = f"{cons_wallet.address}{job_id}{did}{nonce}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_wallet)

    payload = dict(
        {
            "signature": signature,
            "documentId": did,
            "consumerAddress": cons_wallet.address,
            "jobId": job_id,
        }
    )

    job_info = get_compute_job_info(client, compute_endpoint, payload)
    assert job_info, f"Failed to get job info for jobId {job_id}"
    print(f"got info for compute job {job_id}: {job_info}")
    assert job_info["statusText"] in get_possible_compute_job_status_text()

    # get compute job status without signature should return limited status info
    payload.pop("signature")
    job_info = get_compute_job_info(client, compute_endpoint, payload)
    assert job_info, f"Failed to get job status without signature: payload={payload}"
    assert "owner" not in job_info, "owner should not be in this status response"
    assert (
        "resultsUrl" not in job_info
    ), "resultsUrl should not be in this status response"
    assert (
        "algorithmLogUrl" not in job_info
    ), "algorithmLogUrl should not be in this status response"
    assert (
        "resultsDid" not in job_info
    ), "resultsDid should not be in this status response"

    payload["signature"] = ""
    job_info = get_compute_job_info(client, compute_endpoint, payload)
    assert job_info, f"Failed to get job status without signature: payload={payload}"
    assert "owner" not in job_info, "owner should not be in this status response"
    assert (
        "resultsUrl" not in job_info
    ), "resultsUrl should not be in this status response"
    assert (
        "algorithmLogUrl" not in job_info
    ), "algorithmLogUrl should not be in this status response"
    assert (
        "resultsDid" not in job_info
    ), "resultsDid should not be in this status response"


def test_compute_diff_provider(client):
    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()

    (
        _,
        did,
        tx_id,
        sa,
        data_token,
        alg_ddo,
        alg_data_token,
        _,
        alg_tx_id,
    ) = build_and_send_ddo_with_compute_service(client, alg_diff=True)

    nonce = get_nonce(client, cons_wallet.address)
    # prepare consumer signature on did
    msg = f"{cons_wallet.address}{did}{str(nonce)}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_wallet)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": cons_wallet.address,
            "transferTxId": tx_id,
            "dataToken": data_token,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, cons_wallet.address, pub_wallet
            ),
            "algorithmDid": alg_ddo.did,
            "algorithmDataToken": alg_data_token,
            "algorithmTransferTxId": alg_tx_id,
        }
    )

    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    response = client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )

    assert response.status == "200 OK", f"start compute job failed: {response.data}"


def test_compute_allow_all_published(client):
    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()

    (
        _,
        did,
        tx_id,
        sa,
        data_token,
        alg_ddo,
        alg_data_token,
        _,
        alg_tx_id,
    ) = build_and_send_ddo_with_compute_service(
        client, asset_type="allow_all_published"
    )

    nonce = get_nonce(client, cons_wallet.address)
    # prepare consumer signature on did
    msg = f"{cons_wallet.address}{did}{str(nonce)}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_wallet)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": cons_wallet.address,
            "transferTxId": tx_id,
            "dataToken": data_token,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, cons_wallet.address, pub_wallet
            ),
            "algorithmDid": alg_ddo.did,
            "algorithmDataToken": alg_data_token,
            "algorithmTransferTxId": alg_tx_id,
        }
    )

    # Start compute with valid signature
    payload["signature"] = signature
    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    response = client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )
    assert response.status == "200 OK"


def test_compute_not_an_algo(client):
    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()

    (
        _,
        did,
        tx_id,
        sa,
        data_token,
        _,
        alg_data_token,
        _,
        alg_tx_id,
    ) = build_and_send_ddo_with_compute_service(
        client, asset_type="allow_all_published"
    )

    nonce = get_nonce(client, cons_wallet.address)
    # prepare consumer signature on did
    msg = f"{cons_wallet.address}{did}{str(nonce)}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_wallet)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": cons_wallet.address,
            "transferTxId": tx_id,
            "dataToken": data_token,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, cons_wallet.address, pub_wallet
            ),
            "algorithmDid": did,  # intentionally, should not be an algo did
            "algorithmDataToken": alg_data_token,
            "algorithmTransferTxId": alg_tx_id,
        }
    )

    # Start compute with valid signature
    payload["signature"] = signature
    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    response = client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )
    assert response.status == "400 BAD REQUEST"
    error = response.get_json()["error"]
    assert "is not a valid algorithm" in error


def test_compute_additional_input(client):
    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()

    (
        _,
        did,
        tx_id,
        sa,
        data_token,
        alg_ddo,
        alg_data_token,
        _,
        alg_tx_id,
    ) = build_and_send_ddo_with_compute_service(client)

    _, did2, tx_id2, sa2, _, _, _, _, _ = build_and_send_ddo_with_compute_service(
        client
    )

    nonce = get_nonce(client, cons_wallet.address)
    # prepare consumer signature on did
    msg = f"{cons_wallet.address}{did}{str(nonce)}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_wallet)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": cons_wallet.address,
            "transferTxId": tx_id,
            "dataToken": data_token,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, cons_wallet.address, pub_wallet
            ),
            "algorithmDid": alg_ddo.did,
            "algorithmDataToken": alg_data_token,
            "algorithmTransferTxId": alg_tx_id,
            "additionalInputs": [
                {"documentId": did2, "transferTxId": tx_id2, "serviceId": sa2.index}
            ],
        }
    )

    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    response = client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )
    assert response.status == "200 OK", f"start compute job failed: {response.data}"
