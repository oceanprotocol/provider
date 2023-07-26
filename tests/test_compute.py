#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import os
import time

import pytest
from eth_account import Account
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.compute_environments import get_c2d_environments
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.datatoken import get_datatoken_contract
from ocean_provider.utils.provider_fees import get_provider_fees
from ocean_provider.utils.services import ServiceType
from ocean_provider.validation.provider_requests import RBACValidator
from tests.helpers.compute_helpers import (
    build_and_send_ddo_with_compute_service,
    get_compute_job_info,
    get_compute_result,
    get_compute_signature,
    get_future_valid_until,
    get_possible_compute_job_status_text,
    get_registered_asset,
    mint_100_datatokens,
    post_to_compute,
    start_order,
)
from tests.helpers.ddo_dict_builders import build_metadata_dict_type_algorithm
from tests.helpers.nonce import build_nonce
from tests.test_auth import create_token
from tests.test_helpers import get_first_service_by_type, get_ocean_token_address


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.unit
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_rejected(client, monkeypatch):
    monkeypatch.delenv("OPERATOR_SERVICE_URL")
    response = post_to_compute(client, {})
    assert response.status_code == 404


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.parametrize("allow_raw_algos", [True, False])
def test_compute_raw_algo(
    client,
    publisher_wallet,
    consumer_wallet,
    consumer_address,
    web3,
    allow_raw_algos,
    free_c2d_env,
):
    custom_services = "vanilla_compute" if allow_raw_algos else "norawalgo"
    valid_until = get_future_valid_until()
    # publish a dataset asset
    dataset_ddo_w_compute_service = get_registered_asset(
        publisher_wallet, custom_services=custom_services, service_type="compute"
    )

    sa = get_first_service_by_type(dataset_ddo_w_compute_service, ServiceType.COMPUTE)
    datatoken = sa.datatoken_address
    mint_100_datatokens(web3, datatoken, consumer_wallet.address, publisher_wallet)

    algorithm_meta = {
        "rawcode": "console.log('Hello world'!)",
        "format": "docker-image",
        "version": "0.1",
        "container": {
            "entrypoint": "node $ALGO",
            "image": "oceanprotocol/algo_dockers",
            "tag": "python-branin",
            "checksum": "sha256:8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
        },
    }
    tx_id, _ = start_order(
        web3,
        datatoken,
        free_c2d_env["consumerAddress"],
        sa.index,
        get_provider_fees(
            dataset_ddo_w_compute_service,
            sa,
            consumer_wallet.address,
            valid_until,
            free_c2d_env["id"],
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
        "environment": free_c2d_env["id"],
    }

    response = post_to_compute(client, payload)

    if allow_raw_algos:
        assert response.status == "200 OK", f"start compute job failed: {response.data}"
    else:
        assert (
            response.status == "400 BAD REQUEST"
        ), f"start compute job failed: {response.status} , {response.data}"
        assert "no_raw_algo_allowed" == response.json["error"]["dataset"]


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_specific_algo_dids(
    client, publisher_wallet, consumer_wallet, consumer_address, free_c2d_env
):
    valid_until = get_future_valid_until()
    ddo, tx_id, alg_ddo, _ = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        False,
        None,
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
    )
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    algo_metadata = build_metadata_dict_type_algorithm()
    another_alg_ddo = get_registered_asset(
        publisher_wallet, custom_metadata=algo_metadata
    )
    not_sa_compute = get_first_service_by_type(another_alg_ddo, ServiceType.ACCESS)

    # Start the compute job
    payload = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": tx_id},
        "algorithm": {
            "serviceId": not_sa_compute.id,
            "documentId": another_alg_ddo.did,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_address,
        "environment": free_c2d_env["id"],
    }

    response = post_to_compute(client, payload)

    assert (
        response.status == "400 BAD REQUEST"
    ), f"start compute job failed: {response.status} , {response.data}"
    assert response.json["error"]["dataset"] == "not_trusted_algo"


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute(client, publisher_wallet, consumer_wallet, free_c2d_env):
    valid_until = get_future_valid_until()
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        False,
        None,
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": tx_id},
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
        "environment": free_c2d_env["id"],
    }

    # Start compute using invalid signature (withOUT nonce), should fail
    msg = f"{consumer_wallet.address}{ddo.did}"
    payload["signature"] = sign_message(msg, consumer_wallet)

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
        if job_info["dateFinished"] and float(job_info["dateFinished"]) > 0:
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

    payload["nonce"] = build_nonce(consumer_wallet.address)
    result_without_signature = get_compute_result(
        client, BaseURLs.SERVICES_URL + "/computeResult", payload, raw_response=True
    )
    assert result_without_signature.status_code == 400
    assert (
        "Invalid signature provided."
        in result_without_signature.json["errors"]["signature"][0]
    ), "Signature should be required"

    nonce, signature = get_compute_signature(client, consumer_wallet, index, job_id)
    payload["signature"] = signature
    payload["nonce"] = nonce
    result_data = get_compute_result(
        client, BaseURLs.SERVICES_URL + "/computeResult", payload
    )
    assert result_data is not None, "We should have a result"


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_arweave(client, publisher_wallet, consumer_wallet, free_c2d_env):
    valid_until = get_future_valid_until()
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        alg_diff=False,
        asset_type="stored_in_arweave",
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": tx_id},
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
        "environment": free_c2d_env["id"],
    }

    # Start compute with valid signature
    payload["signature"] = signature
    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_diff_provider(client, publisher_wallet, consumer_wallet, free_c2d_env):
    valid_until = get_future_valid_until()
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        None,
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": tx_id},
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
        "environment": free_c2d_env["id"],
    }

    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_allow_all_published(
    client, publisher_wallet, consumer_wallet, free_c2d_env
):
    valid_until = get_future_valid_until()
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        False,
        "allow_all_published",
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": tx_id},
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
    }

    # Start the compute job on a bad environment
    payload["environment"] = "some inexistent env"
    response = post_to_compute(client, payload)

    assert (
        response.status == "400 BAD REQUEST"
    ), f"start compute job failed: {response.status} , {response.data}"
    assert "order_invalid" in response.json["error"]["dataset.serviceId"]

    # Start on the correct environment
    payload["environment"] = free_c2d_env["id"]
    response = post_to_compute(client, payload)
    assert response.status == "200 OK"


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_additional_input(
    client, publisher_wallet, consumer_wallet, monkeypatch, free_c2d_env, web3
):
    valid_until = get_future_valid_until()
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        False,
        None,
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    # same trusted algo
    ddo2 = get_registered_asset(
        publisher_wallet,
        custom_services="vanilla_compute",
        custom_services_args=ddo.services[0].compute_dict["publisherTrustedAlgorithms"],
    )

    sa2 = get_first_service_by_type(ddo2, ServiceType.COMPUTE)
    mint_100_datatokens(
        web3, sa2.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    tx_id2, _ = start_order(
        web3,
        sa2.datatoken_address,
        free_c2d_env["consumerAddress"],
        sa2.index,
        get_provider_fees(
            ddo2,
            sa2,
            consumer_wallet.address,
            valid_until,
            free_c2d_env["id"],
            force_zero=True,
        ),
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
            "algocustomdata": '{"cpus":"1 billion", "memory":"none"}',
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
        "environment": free_c2d_env["id"],
    }

    monkeypatch.setenv("RBAC_SERVER_URL", "http://172.15.0.8:3000")
    validator = RBACValidator(request_name="ComputeRequest", request=payload)
    assert validator.fails() is False

    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_delete_job(
    client, publisher_wallet, consumer_wallet, consumer_address, free_c2d_env
):
    valid_until = get_future_valid_until()
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        False,
        None,
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": tx_id},
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
        "environment": free_c2d_env["id"],
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


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.unit
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_environments():
    environments = get_c2d_environments()

    for env in environments[8996]:
        if env["priceMin"] == 0:
            assert env["id"] == "ocean-compute"


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_paid_env(
    client, publisher_wallet, consumer_wallet, paid_c2d_env, web3
):
    valid_until = get_future_valid_until()
    deployer_wallet = Account.from_key(os.getenv("FACTORY_DEPLOYER_PRIVATE_KEY"))
    fee_token = get_datatoken_contract(web3, get_ocean_token_address(web3))
    fee_token.functions.mint(consumer_wallet.address, to_wei(80)).transact(
        {"from": deployer_wallet.address}
    )

    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        False,
        None,
        c2d_address=paid_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=paid_c2d_env["id"],
        fee_token_args=(fee_token, to_wei(80)),
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": tx_id},
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": alg_tx_id,
        },
        "signature": signature,
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
        "environment": paid_c2d_env["id"],
    }

    # Start compute with valid signature
    response = post_to_compute(client, payload)
    assert response.status == "200 OK", f"start compute job failed: {response.data}"

    job_info = response.json[0]
    print(f"got response from starting compute job: {job_info}")
    _ = job_info.get("jobId", "")


@pytest.mark.skip("C2D connection needs fixing.")
@pytest.mark.integration
@pytest.mark.skip("C2D connection needs fixing.")
def test_compute_auth_token(client, publisher_wallet, consumer_wallet, free_c2d_env):
    valid_until = get_future_valid_until()
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        False,
        None,
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    nonce, signature = get_compute_signature(client, consumer_wallet, ddo.did)

    # Start the compute job
    payload = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": tx_id},
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": alg_tx_id,
        },
        # "signature": NO SIGNATURE
        "nonce": nonce,
        "consumerAddress": consumer_wallet.address,
        "environment": free_c2d_env["id"],
    }

    # Start compute with auth token
    token = create_token(client, consumer_wallet)
    response = post_to_compute(client, payload, headers={"AuthToken": token})
    assert response.status_code == 200, f"{response.data}"
