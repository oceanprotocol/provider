import itertools
import json
import uuid

from ocean_lib.common.agreements.service_agreement import ServiceAgreement
from ocean_lib.common.agreements.service_types import ServiceTypes
from ocean_lib.models.data_token import DataToken

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from tests.helpers.service_descriptors import (
    get_compute_service_descriptor,
    get_compute_service_descriptor_allow_all_published,
    get_compute_service_descriptor_no_rawalgo,
    get_compute_service_descriptor_specific_algo_dids,
    get_compute_service_descriptor_specific_algo_publishers,
)
from tests.test_helpers import (
    get_algorithm_ddo,
    get_algorithm_ddo_different_provider,
    get_nonce,
    get_registered_ddo,
    get_sample_ddo_with_compute_service,
    get_web3,
    mint_tokens_and_wait,
    send_order,
)


def build_and_send_ddo_with_compute_service(
    client, publisher_wallet, consumer_wallet, alg_diff=False, asset_type=None
):
    web3 = get_web3()
    # publish an algorithm asset (asset with metadata of type `algorithm`)
    alg_ddo = (
        get_algorithm_ddo_different_provider(client, consumer_wallet)
        if alg_diff
        else get_algorithm_ddo(client, consumer_wallet)
    )
    alg_data_token = alg_ddo.as_dictionary()["dataToken"]
    alg_dt_contract = DataToken(web3, alg_data_token)

    mint_tokens_and_wait(alg_dt_contract, consumer_wallet, consumer_wallet)

    # publish a dataset asset
    if asset_type == "allow_all_published":
        dataset_ddo_w_compute_service = comp_ds(
            client, publisher_wallet, "allow_all_published"
        )
    elif asset_type == "specific_algo_dids":
        algos = []

        for _ in itertools.repeat(None, 2):
            alg_ddo = get_algorithm_ddo(client, consumer_wallet)
            alg_data_token = alg_ddo.as_dictionary()["dataToken"]
            alg_dt_contract = DataToken(web3, alg_data_token)
            mint_tokens_and_wait(alg_dt_contract, consumer_wallet, consumer_wallet)
            algos.append(alg_ddo)

        dataset_ddo_w_compute_service = comp_ds(
            client, publisher_wallet, "specific_algo_dids", algos
        )
    elif asset_type == "specific_algo_publishers":
        alg_ddo = get_algorithm_ddo(client, consumer_wallet)
        alg_data_token = alg_ddo.as_dictionary()["dataToken"]
        alg_dt_contract = DataToken(web3, alg_data_token)
        mint_tokens_and_wait(alg_dt_contract, consumer_wallet, consumer_wallet)

        dataset_ddo_w_compute_service = comp_ds(
            client,
            publisher_wallet,
            "specific_algo_publishers",
            publishers=[alg_ddo.publisher],
        )
    else:
        dataset_ddo_w_compute_service = comp_ds(client, publisher_wallet)

    ddo = dataset_ddo_w_compute_service
    data_token = dataset_ddo_w_compute_service.data_token_address
    dt_contract = DataToken(web3, data_token)
    mint_tokens_and_wait(dt_contract, consumer_wallet, publisher_wallet)

    sa = ServiceAgreement.from_ddo(
        ServiceTypes.CLOUD_COMPUTE, dataset_ddo_w_compute_service
    )

    tx_id = send_order(client, ddo, dt_contract, sa, consumer_wallet)
    alg_service = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, alg_ddo)
    alg_tx_id = send_order(
        client, alg_ddo, alg_dt_contract, alg_service, consumer_wallet
    )

    return (dataset_ddo_w_compute_service, tx_id, alg_ddo, alg_tx_id)


def get_compute_signature(client, consumer_wallet, did, job_id=None):
    nonce = get_nonce(client, consumer_wallet.address)

    # prepare consumer signature on did
    if job_id:
        msg = f"{consumer_wallet.address}{job_id}{did}{nonce}"
    else:
        msg = f"{consumer_wallet.address}{did}{nonce}"
    signature = sign_message(msg, consumer_wallet)

    return signature


def post_to_compute(client, payload):
    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    return client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )


def get_possible_compute_job_status_text():
    return {
        1: "Warming up",
        10: "Job started",
        20: "Configuring volumes",
        30: "Provisioning success",
        31: "Data provisioning failed",
        32: "Algorithm provisioning failed",
        40: "Running algorithm",
        50: "Filtering results",
        60: "Publishing results",
        70: "Job completed",
    }.values()


def get_compute_job_info(client, endpoint, params):
    response = client.get(
        endpoint + "?" + "&".join([f"{k}={v}" for k, v in params.items()]),
        data=json.dumps(params),
        content_type="application/json",
    )
    assert (
        response.status_code == 200 and response.data
    ), f"get compute job info failed: status {response.status}, data {response.data}"

    job_info = response.json if response.json else json.loads(response.data)
    if not job_info:
        print(f"There is a problem with the job info response: {response.data}")
        return None, None

    return dict(job_info[0])


def comp_ds(
    client, wallet, compute_service_descriptor=None, algos=None, publishers=None
):
    metadata = get_sample_ddo_with_compute_service()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())

    if compute_service_descriptor == "no_rawalgo":
        service_descriptor = get_compute_service_descriptor_no_rawalgo(
            wallet.address, metadata["main"]["cost"], metadata
        )
    elif compute_service_descriptor == "specific_algo_dids":
        service_descriptor = get_compute_service_descriptor_specific_algo_dids(
            wallet.address, metadata["main"]["cost"], metadata, algos
        )
    elif compute_service_descriptor == "specific_algo_publishers":
        service_descriptor = get_compute_service_descriptor_specific_algo_publishers(
            wallet.address, metadata["main"]["cost"], metadata, publishers
        )
    elif compute_service_descriptor == "allow_all_published":
        service_descriptor = get_compute_service_descriptor_allow_all_published(
            wallet.address, metadata["main"]["cost"], metadata
        )
    else:
        service_descriptor = get_compute_service_descriptor(
            wallet.address, metadata["main"]["cost"], metadata
        )

    metadata["main"].pop("cost")
    return get_registered_ddo(client, wallet, metadata, service_descriptor)
