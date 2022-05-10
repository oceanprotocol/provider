import json
from datetime import datetime, timedelta

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.provider_fees import get_c2d_environments, get_provider_fees
from ocean_provider.utils.services import ServiceType
from ocean_provider.utils.util import msg_hash
from tests.helpers.ddo_dict_builders import build_metadata_dict_type_algorithm
from tests.test_helpers import (
    get_registered_asset,
    get_first_service_by_type,
    get_web3,
    mint_100_datatokens,
    start_order,
)


def build_and_send_ddo_with_compute_service(
    client,
    publisher_wallet,
    consumer_wallet,
    alg_diff=False,
    asset_type=None,
    c2d_address=None,
    do_send=True,
    short_valid_until=True,
):
    web3 = get_web3()
    algo_metadata = build_metadata_dict_type_algorithm()
    if c2d_address is None:
        c2d_address = consumer_wallet.address
    if alg_diff:
        alg_ddo = get_registered_asset(
            publisher_wallet,
            custom_metadata=algo_metadata,
            custom_service_endpoint="http://172.15.0.7:8030",
        )
    else:
        alg_ddo = get_registered_asset(publisher_wallet, custom_metadata=algo_metadata)

    # publish an algorithm asset (asset with metadata of type `algorithm`)
    service = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )

    # publish a dataset asset
    if asset_type == "allow_all_published":
        dataset_ddo_w_compute_service = get_registered_asset(
            publisher_wallet, custom_services="vanilla_compute", custom_services_args=[]
        )
    else:
        dataset_ddo_w_compute_service = get_registered_asset(
            publisher_wallet,
            custom_services="vanilla_compute",
            custom_services_args=[
                {
                    "did": alg_ddo.did,
                    "filesChecksum": msg_hash(service.encrypted_files),
                    "containerSectionChecksum": msg_hash(
                        json.dumps(
                            alg_ddo.metadata["algorithm"]["container"],
                            separators=(",", ":"),
                        )
                    ),
                }
            ],
        )

    service = get_first_service_by_type(
        dataset_ddo_w_compute_service, ServiceType.COMPUTE
    )
    datatoken = service.datatoken_address
    mint_100_datatokens(web3, datatoken, consumer_wallet.address, publisher_wallet)

    environments = get_c2d_environments()

    if not do_send:
        return (dataset_ddo_w_compute_service, alg_ddo)

    tx_id, _ = start_order(
        web3,
        datatoken,
        c2d_address,
        service.index,
        get_provider_fees(
            dataset_ddo_w_compute_service.did,
            service,
            consumer_wallet.address,
            get_future_valid_until(short=short_valid_until),
            environments[0]["id"],
        ),
        consumer_wallet,
    )

    alg_service = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)

    alg_tx_id, _ = start_order(
        web3,
        alg_service.datatoken_address,
        c2d_address,
        alg_service.index,
        get_provider_fees(
            alg_ddo.did,
            alg_service,
            consumer_wallet.address,
            get_future_valid_until(short=short_valid_until),
            environments[0]["id"],
            force_zero=True,
        ),
        consumer_wallet,
    )

    return (dataset_ddo_w_compute_service, tx_id, alg_ddo, alg_tx_id)


def get_compute_signature(client, consumer_wallet, did, job_id=None):
    nonce = datetime.utcnow().timestamp()

    # prepare consumer signature on did
    if job_id:
        msg = f"{consumer_wallet.address}{job_id}{did}{nonce}"
    else:
        msg = f"{consumer_wallet.address}{did}{nonce}"
    signature = sign_message(msg, consumer_wallet)

    return nonce, signature


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


def get_future_valid_until(short=False):
    # return a timestamp for one hour in the future or 30s in the future if short
    time_diff = timedelta(hours=1) if not short else timedelta(seconds=30)
    return int((datetime.utcnow() + time_diff).timestamp())
