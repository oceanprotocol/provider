#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import json

from ocean_lib.common.agreements.service_agreement import ServiceAgreement
from ocean_lib.common.agreements.service_types import ServiceTypes
from ocean_lib.models.data_token import DataToken
from ocean_lib.web3_internal.transactions import sign_hash
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_provider.constants import BaseURLs
from ocean_provider.validation.algo import build_stage_output_dict
from tests.test_helpers import (
    build_and_send_ddo_with_compute_service,
    comp_ds,
    get_compute_job_info,
    get_compute_signature,
    get_nonce,
    get_possible_compute_job_status_text,
    mint_tokens_and_wait,
    post_to_compute,
    send_order,
)


def test_compute_norawalgo_allowed(
    client, publisher_wallet, consumer_wallet, consumer_address
):
    # publish a dataset asset
    dataset = comp_ds(client, publisher_wallet, "no_rawalgo")
    dt_contract = DataToken(dataset.data_token_address)
    mint_tokens_and_wait(dt_contract, consumer_wallet, publisher_wallet)

    algorithm_meta = {
        "rawcode": "console.log('Hello world'!)",
        "format": "docker-image",
        "version": "0.1",
        "container": {"entrypoint": "node $ALGO", "image": "node", "tag": "10"},
    }

    sa = ServiceAgreement.from_ddo(ServiceTypes.CLOUD_COMPUTE, dataset)
    tx_id = send_order(client, dataset, dt_contract, sa, consumer_wallet)
    signature = get_compute_signature(client, consumer_wallet, dataset.did)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": dataset.did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": consumer_address,
            "transferTxId": tx_id,
            "dataToken": dataset.data_token_address,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, consumer_address, publisher_wallet
            ),
            "algorithmMeta": algorithm_meta,
            "algorithmDataToken": "",
        }
    )

    response = post_to_compute(client, payload)

    assert (
        response.status == "400 BAD REQUEST"
    ), f"start compute job failed: {response.status} , {response.data}"


def test_compute_specific_algo_dids(
    client, publisher_wallet, consumer_wallet, consumer_address
):
    ddo, tx_id, alg_ddo, _ = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet, asset_type="specific_algo_dids"
    )
    sa = ddo.get_service(ServiceTypes.CLOUD_COMPUTE)
    signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": ddo.did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": consumer_address,
            "transferTxId": tx_id,
            "dataToken": ddo.data_token_address,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, consumer_address, publisher_wallet
            ),
            "algorithmDid": alg_ddo.did,
            "algorithmDataToken": alg_ddo.data_token_address,
        }
    )

    response = post_to_compute(client, payload)

    assert (
        response.status == "400 BAD REQUEST"
    ), f"start compute job failed: {response.status} , {response.data}"


def test_compute(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(client)
    sa = ddo.get_service(ServiceTypes.CLOUD_COMPUTE)
    signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": ddo.did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": consumer_wallet.address,
            "transferTxId": tx_id,
            "dataToken": ddo.data_token_address,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, consumer_wallet.address, publisher_wallet
            ),
            "algorithmDid": alg_ddo.did,
            "algorithmDataToken": alg_ddo.data_token_address,
            "algorithmTransferTxId": alg_tx_id,
        }
    )

    # Start compute using invalid signature (withOUT nonce), should fail
    msg = f"{consumer_wallet.address}{ddo.did}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    payload["signature"] = sign_hash(_hash, consumer_wallet)

    response = post_to_compute(payload)
    assert response.status_code == 400, f"{response.data}"

    # Start compute with valid signature
    payload["signature"] = signature
    response = post_to_compute(payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"

    job_info = response.json[0]
    print(f"got response from starting compute job: {job_info}")
    job_id = job_info.get("jobId", "")

    # get a new signature
    signature = get_compute_signature(client, consumer_wallet, ddo.did)
    payload = dict(
        {
            "signature": signature,
            "documentId": ddo.did,
            "consumerAddress": consumer_wallet.address,
            "jobId": job_id,
        }
    )

    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
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
    signature = sign_hash(_hash, cons_wallet)

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
    signature = sign_hash(_hash, cons_wallet)

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
    signature = sign_hash(_hash, cons_wallet)

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
    signature = sign_hash(_hash, cons_wallet)

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
