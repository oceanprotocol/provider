import itertools
import json
import uuid

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.datatoken import get_datatoken_contract
from ocean_provider.utils.services import ServiceType
from ocean_provider.utils.currency import to_wei
from tests.helpers.ddo_dict_builders import (
    get_compute_service,
    get_compute_service_allow_all_published,
    get_compute_service_no_rawalgo,
    get_compute_service_specific_algo_dids,
    get_compute_service_specific_algo_publishers,
    build_metadata_dict_type_algorithm,
)
from tests.test_helpers import (
    BLACK_HOLE_ADDRESS,
    get_algorithm_ddo,
    get_algorithm_ddo_different_provider,
    get_nonce,
    get_registered_asset,
    get_sample_ddo_with_compute_service,
    get_web3,
    mint_tokens_and_wait,
    mint_100_datatokens,
    send_order,
    get_ocean_token_address,
    deploy_datatoken,
    start_order,
)


def build_and_send_ddo_with_compute_service(
    client, publisher_wallet, consumer_wallet, alg_diff=False, asset_type=None
):
    web3 = get_web3()
    algo_metadata = build_metadata_dict_type_algorithm()

    alg_ddo = get_registered_asset(publisher_wallet, custom_metadata=algo_metadata)

    # TODO: diff provider and remove get_algorithm_ddo_different_provider

    # publish an algorithm asset (asset with metadata of type `algorithm`)
    service = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    alg_data_token = service.datatoken_address
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    # TODO: remove comp_ds, move these ifs to build_custom_services

    # publish a dataset asset
    if asset_type == "allow_all_published":
        dataset_ddo_w_compute_service = get_registered_asset(
            publisher_wallet, "allow_all_published"
        )
    elif asset_type == "specific_algo_dids":
        algos = []

        for _ in itertools.repeat(None, 2):
            alg_ddo = get_algorithm_ddo(client, consumer_wallet)
            alg_data_token = alg_ddo.data_token_address
            alg_dt_contract = get_datatoken_contract(web3, alg_data_token)
            mint_tokens_and_wait(alg_dt_contract, consumer_wallet, consumer_wallet)
            algos.append(alg_ddo)

        dataset_ddo_w_compute_service = comp_ds(
            client, publisher_wallet, "specific_algo_dids", algos
        )
    elif asset_type == "specific_algo_publishers":
        alg_ddo = get_algorithm_ddo(client, consumer_wallet)
        alg_data_token = alg_ddo.data_token_address
        alg_dt_contract = get_datatoken_contract(web3, alg_data_token)
        mint_tokens_and_wait(alg_dt_contract, consumer_wallet, consumer_wallet)

        dataset_ddo_w_compute_service = comp_ds(
            client,
            publisher_wallet,
            "specific_algo_publishers",
            publishers=[alg_ddo.publisher],
        )
    else:
        dataset_ddo_w_compute_service = get_registered_asset(
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

    service = dataset_ddo_w_compute_service.get_service_by_type(ServiceType.COMPUTE)
    datatoken = service.datatoken_address
    mint_100_datatokens(web3, datatoken, consumer_wallet.address, publisher_wallet)

    tx_id, _ = start_order(
        web3,
        datatoken,
        consumer_wallet.address,
        to_wei(1),
        service.index,
        BLACK_HOLE_ADDRESS,
        BLACK_HOLE_ADDRESS,
        0,
        consumer_wallet,
    )

    alg_service = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    alg_tx_id, _ = start_order(
        web3,
        alg_service.datatoken_address,
        consumer_wallet.address,
        to_wei(1),
        alg_service.index,
        BLACK_HOLE_ADDRESS,
        BLACK_HOLE_ADDRESS,
        0,
        consumer_wallet,
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
    compute_endpoint = BaseURLs.SERVICES_URL + "/compute"
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


def get_compute_result(client, endpoint, params, raw_response=False):
    # not possible to use PrepparedRequest here,
    # since we don't have the full url (schema, host) in the tests
    response = client.get(
        endpoint + "?" + "&".join([f"{k}={v}" for k, v in params.items()])
    )

    if raw_response:
        return response

    assert (
        response.status_code == 200
    ), f"get compute result failed: status {response.status}, data {response.data}"

    return response.data


def comp_ds(client, wallet, compute_service=None, algos=None, publishers=None):
    metadata = get_sample_ddo_with_compute_service()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())

    if compute_service == "no_rawalgo":
        service = get_compute_service_no_rawalgo(
            wallet.address, metadata["main"]["cost"], metadata
        )
    elif compute_service == "specific_algo_dids":
        service = get_compute_service_specific_algo_dids(
            wallet.address, metadata["main"]["cost"], metadata, algos
        )
    elif compute_service == "specific_algo_publishers":
        service = get_compute_service_specific_algo_publishers(
            wallet.address, metadata["main"]["cost"], metadata, publishers
        )
    elif compute_service == "allow_all_published":
        service = get_compute_service_allow_all_published(
            wallet.address, metadata["main"]["cost"], metadata
        )
    else:
        service = get_compute_service(
            wallet.address, metadata["main"]["cost"], metadata
        )

    metadata["main"].pop("cost")
    return get_registered_asset(client, wallet, metadata, service)
