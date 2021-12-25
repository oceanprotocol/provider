#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime
import pytest
import time

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.services import ServiceType
from ocean_provider.validation.algo import build_stage_output_dict
from ocean_provider.utils.provider_fees import get_provider_fees
from tests.helpers.compute_helpers import (
    BLACK_HOLE_ADDRESS,
    build_and_send_ddo_with_compute_service,
    get_compute_job_info,
    get_compute_result,
    get_compute_signature,
    get_possible_compute_job_status_text,
    get_registered_asset,
    get_web3,
    mint_100_datatokens,
    post_to_compute,
    start_order,
)
from tests.helpers.ddo_dict_builders import build_metadata_dict_type_algorithm


@pytest.mark.integration
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
        sa.index,
        get_provider_fees(
            dataset_ddo_w_compute_service.did, sa, consumer_wallet.address
        ),
        consumer_wallet,
    )
    nonce, signature = get_compute_signature(
        client, consumer_wallet, dataset_ddo_w_compute_service.did
    )

    # Start the compute job
    payload = {
        "dataset": {
            "documentId": dataset_ddo_w_compute_service.did,
            "serviceId": sa.id,
            "transferTxId": tx_id,
        },
        "algorithm": {"meta": algorithm_meta},
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_address,
    }

    response = post_to_compute(client, payload)

    assert (
        response.status == "400 BAD REQUEST"
    ), f"start compute job failed: {response.status} , {response.data}"
    assert "cannot run raw algorithm on this did" in response.json["error"]


@pytest.mark.integration
def test_compute_specific_algo_dids(
    client, publisher_wallet, consumer_wallet, consumer_address
):
    ddo, tx_id, alg_ddo, _ = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    algo_metadata = build_metadata_dict_type_algorithm()
    another_alg_ddo = get_registered_asset(
        publisher_wallet, custom_metadata=algo_metadata
    )
    not_sa_compute = another_alg_ddo.get_service_by_type(ServiceType.ACCESS)

    # Start the compute job
    payload = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": tx_id,
        },
        "algorithm": {
            "serviceId": not_sa_compute.id,
            "documentId": another_alg_ddo.did,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_address,
    }

    response = post_to_compute(client, payload)

    assert (
        response.status == "400 BAD REQUEST"
    ), f"start compute job failed: {response.status} , {response.data}"
    assert (
        response.json["error"]
        == f"this algorithm did {another_alg_ddo.did} is not trusted."
    )


@pytest.mark.integration
def test_compute(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": tx_id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
    }

    # TODO
    # Start compute using invalid signature (withOUT nonce), should fail
    # msg = f"{consumer_wallet.address}{ddo.did}"
    # payload["signature"] = sign_message(msg, consumer_wallet)

    # response = post_to_compute(client, payload)
    # assert response.status_code == 400, f"{response.data}"

    # Start compute with valid signature
    payload["signature"] = signature
    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"

    job_info = response.json[0]
    print(f"got response from starting compute job: {job_info}")
    job_id = job_info.get("jobId", "")

    # get a new signature
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)
    payload = dict(
        {
            "signature": signature,
            "nonce": nonce,
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

    payload["nonce"] = str(datetime.now().timestamp())
    result_without_signature = get_compute_result(
        client, BaseURLs.SERVICES_URL + "/computeResult", payload, raw_response=True
    )
    assert result_without_signature.status_code == 400
    assert (
        result_without_signature.json["errors"]["signature"][0]
        == "The signature field is required."
    ), "Signature should be required"

    nonce, signature = get_compute_signature(client, consumer_wallet, index, job_id)
    payload["signature"] = signature
    payload["nonce"] = nonce
    result_data = get_compute_result(
        client, BaseURLs.SERVICES_URL + "/computeResult", payload
    )
    assert result_data is not None, "We should have a result"


@pytest.mark.integration
def test_compute_diff_provider(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet, alg_diff=True
    )
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": tx_id,
        },
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
    }

    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"


@pytest.mark.integration
def test_compute_allow_all_published(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet, asset_type="allow_all_published"
    )
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": tx_id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
    }

    response = post_to_compute(client, payload)
    assert response.status == "200 OK"


@pytest.mark.integration
def test_compute_additional_input(client, publisher_wallet, consumer_wallet):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)

    # same trusted algo
    ddo2 = get_registered_asset(
        publisher_wallet,
        custom_services="vanilla_compute",
        custom_services_args=ddo.services[0].compute_dict["publisherTrustedAlgorithms"],
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
        sa2.index,
        get_provider_fees(ddo2.did, sa2, consumer_wallet.address),
        consumer_wallet,
    )

    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": tx_id,
            "userdata": '{"surname":"XXX", "age":12}',
        },
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
            "userdata": '{"surname":"YYY", "age":21}',
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
        "additionalDatasets": [
            {
                "documentId": ddo2.did,
                "transferTxId": tx_id2,
                "serviceId": sa2.id,
                "userdata": {"test_key": "test_value"},
            }
        ],
    }

    # TODO: algo custom data

    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"


@pytest.mark.integration
def test_compute_delete_job(
    client, publisher_wallet, consumer_wallet, consumer_address
):
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": tx_id,
        },
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
    }

    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"

    job_id = response.json[0]["jobId"]
    compute_endpoint = BaseURLs.SERVICES_URL + "/compute"
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did, job_id)

    query_string = {
        "consumerAddress": consumer_address,
        "jobId": job_id,
        "documentId": ddo.did,
        "signature": signature,
        "nonce": nonce,
    }

    # stop job
    response = client.put(
        compute_endpoint, query_string=query_string, content_type="application/json"
    )
    assert response.status == "200 OK", f"delete compute job failed: {response.data}"

    # delete job
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did, job_id)
    query_string["signature"] = signature
    query_string["nonce"] = nonce

    response = client.delete(
        compute_endpoint, query_string=query_string, content_type="application/json"
    )
    assert response.status == "200 OK", f"delete compute job failed: {response.data}"
