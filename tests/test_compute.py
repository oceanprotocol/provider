#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import time

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.datatoken import get_datatoken_contract
from ocean_provider.utils.services import ServiceType
from ocean_provider.validation.algo import build_stage_output_dict
from tests.helpers.compute_helpers import (
    build_and_send_ddo_with_compute_service,
    comp_ds,
    get_compute_job_info,
    get_compute_result,
    get_compute_signature,
    get_possible_compute_job_status_text,
    post_to_compute,
    get_registered_asset,
    mint_100_datatokens,
    BLACK_HOLE_ADDRESS,
    start_order
)
from tests.test_helpers import mint_tokens_and_wait, send_order


def test_compute_norawalgo_allowed(
    client, publisher_wallet, consumer_wallet, consumer_address, web3
):
    # publish a dataset asset
    dataset_ddo_w_compute_service = get_registered_asset(
        publisher_wallet,
        custom_services="norawalgo",
    )

    sa = dataset_ddo_w_compute_service.get_service_by_type(ServiceType.COMPUTE)
    datatoken = sa.datatoken_address
    mint_100_datatokens(web3, datatoken, consumer_wallet.address, publisher_wallet)

    algorithm_meta = {
        "rawcode": "console.log('Hello world'!)",
        "format": "docker-image",
        "version": "0.1",
        "container": {"entrypoint": "node $ALGO", "image": "node", "tag": "10"},
    }

    tx_id, _ = start_order(
        web3,
        datatoken,
        consumer_wallet.address,
        to_wei(1),
        sa.index,
        BLACK_HOLE_ADDRESS,
        BLACK_HOLE_ADDRESS,
        0,
        consumer_wallet,
    )
    signature = get_compute_signature(client, consumer_wallet, dataset_ddo_w_compute_service.did)

    # Start the compute job
    payload = dict(
        {
            "signature": signature,
            "documentId": dataset_ddo_w_compute_service.did,
            "serviceId": sa.index,
            "serviceType": sa.type,
            "consumerAddress": consumer_address,
            "transferTxId": tx_id,
            "dataToken": sa.datatoken_address,
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
    sa = ddo.get_service("compute")
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
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa_compute = ddo.get_service_by_type(ServiceType.COMPUTE)
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
            "dataToken": sa.datatoken_address,
            "output": build_stage_output_dict(
                dict(), sa.service_endpoint, consumer_wallet.address, publisher_wallet
            ),
            "algorithmDid": alg_ddo.did,
            "algorithmDataToken": sa_compute.datatoken_address,
            "algorithmTransferTxId": alg_tx_id,
        }
    )

    # Start compute using invalid signature (withOUT nonce), should fail
    msg = f"{consumer_wallet.address}{ddo.did}"
    payload["signature"] = sign_message(msg, consumer_wallet)

    response = post_to_compute(client, payload)
    assert response.status_code == 400, f"{response.data}"

    # Start compute with valid signature
    payload["signature"] = signature
    response = post_to_compute(client, payload)
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

    compute_endpoint = BaseURLs.SERVICES_URL + "/compute"
    job_info = get_compute_job_info(client, compute_endpoint, payload)
    assert job_info, f"Failed to get job info for jobId {job_id}"
    print(f"got info for compute job {job_id}: {job_info}")
    assert job_info["statusText"] in get_possible_compute_job_status_text()

    # get compute job status without signature should return limited status info
    payload.pop("signature")
    job_info = get_compute_job_info(client, compute_endpoint, payload)
    assert job_info, f"Failed to get job status without signature: payload={payload}"
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
    assert (
        "resultsUrl" not in job_info
    ), "resultsUrl should not be in this status response"
    assert (
        "algorithmLogUrl" not in job_info
    ), "algorithmLogUrl should not be in this status response"
    assert (
        "resultsDid" not in job_info
    ), "resultsDid should not be in this status response"

    # wait until job is done, see:
    # https://github.com/oceanprotocol/operator-service/blob/main/API.md#status-description
    tries = 0
    while tries < 200:
        job_info = get_compute_job_info(client, compute_endpoint, payload)
        if job_info["status"] > 60:
            break
        tries = tries + 1
        time.sleep(5)

    assert tries <= 200, "Timeout waiting for the job to be completed"
    index = 0
    payload = {
        "index": index,
        "consumerAddress": consumer_wallet.address,
        "jobId": job_id,
    }

    result_without_signature = get_compute_result(
        client, BaseURLs.SERVICES_URL + "/computeResult", payload, raw_response=True
    )
    assert result_without_signature.status_code == 400
    assert (
        result_without_signature.json["errors"]["signature"][0]
        == "The signature field is required."
    ), "Signature should be required"

    signature = get_compute_signature(client, consumer_wallet, index, job_id)
    payload["signature"] = signature
    result_data = get_compute_result(
        client, BaseURLs.SERVICES_URL + "/computeResult", payload
    )
    assert result_data, "We should have a result"


def test_compute_diff_provider(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet, alg_diff=True
    )
    sa = ddo.get_service("compute")
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

    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"


def test_compute_allow_all_published(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet, asset_type="allow_all_published"
    )
    sa = ddo.get_service("compute")
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

    response = post_to_compute(client, payload)
    assert response.status == "200 OK"


def test_compute_not_an_algo(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet, asset_type="allow_all_published"
    )
    sa = ddo.get_service("compute")
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
            "algorithmDid": ddo.did,  # intentionally, should not be an algo did
            "algorithmDataToken": alg_ddo.data_token_address,
            "algorithmTransferTxId": alg_tx_id,
        }
    )

    response = post_to_compute(client, payload)
    assert response.status == "400 BAD REQUEST"
    error = response.get_json()["error"]
    assert "is not a valid algorithm" in error


def test_compute_additional_input(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa = ddo.get_service("compute")
    ddo2, tx_id2, _, _ = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa2 = ddo2.get_service("compute")

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
            "additionalInputs": [
                {
                    "documentId": ddo2.did,
                    "transferTxId": tx_id2,
                    "serviceId": sa2.index,
                    "userdata": {"test_key": "test_value"},
                }
            ],
            "userdata": '{"surname":"XXX", "age":12}',
            "algouserdata": '{"surname":"YYY", "age":21}',
        }
    )

    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"


def test_compute_delete_job(
    client, publisher_wallet, consumer_wallet, consumer_address
):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa = ddo.get_service("compute")
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
            "algorithmTransferTxId": alg_tx_id,
        }
    )

    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"

    job_id = response.json[0]["jobId"]
    compute_endpoint = BaseURLs.SERVICES_URL + "/compute"
    signature = get_compute_signature(client, consumer_wallet, ddo.did, job_id)

    query_string = {
        "consumerAddress": consumer_address,
        "jobId": job_id,
        "documentId": ddo.did,
        "signature": signature,
    }

    # stop job
    response = client.put(
        compute_endpoint, query_string=query_string, content_type="application/json"
    )
    assert response.status == "200 OK", f"delete compute job failed: {response.data}"

    # delete job
    signature = get_compute_signature(client, consumer_wallet, ddo.did, job_id)
    query_string["signature"] = signature

    response = client.delete(
        compute_endpoint, query_string=query_string, content_type="application/json"
    )
    assert response.status == "200 OK", f"delete compute job failed: {response.data}"
