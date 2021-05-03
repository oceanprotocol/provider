import itertools
import json

from ocean_lib.common.agreements.service_agreement import ServiceAgreement
from ocean_lib.common.agreements.service_types import ServiceTypes
from ocean_lib.models.data_token import DataToken
from ocean_provider.constants import BaseURLs
from tests.test_helpers import (
    add_ethereum_prefix_and_hash_msg,
    comp_ds,
    get_algorithm_ddo,
    get_algorithm_ddo_different_provider,
    get_nonce,
    mint_tokens_and_wait,
    send_order,
    sign_hash,
)


def build_and_send_ddo_with_compute_service(
    client, publisher_wallet, consumer_wallet, alg_diff=False, asset_type=None
):
    # publish an algorithm asset (asset with metadata of type `algorithm`)
    alg_ddo = (
        get_algorithm_ddo_different_provider(client, consumer_wallet)
        if alg_diff
        else get_algorithm_ddo(client, consumer_wallet)
    )
    alg_data_token = alg_ddo.as_dictionary()["dataToken"]
    alg_dt_contract = DataToken(alg_data_token)

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
            alg_dt_contract = DataToken(alg_data_token)
            mint_tokens_and_wait(alg_dt_contract, consumer_wallet, consumer_wallet)
            algos.append(alg_ddo)

        dataset_ddo_w_compute_service = comp_ds(
            client, publisher_wallet, "specific_algo_dids", algos
        )
    else:
        dataset_ddo_w_compute_service = comp_ds(client, publisher_wallet)

    ddo = dataset_ddo_w_compute_service
    data_token = dataset_ddo_w_compute_service.data_token_address
    dt_contract = DataToken(data_token)
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


def get_compute_signature(client, consumer_wallet, did):
    nonce = get_nonce(client, consumer_wallet.address)

    # prepare consumer signature on did
    msg = f"{consumer_wallet.address}{did}{nonce}"
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = sign_hash(_hash, consumer_wallet)

    return signature


def post_to_compute(client, payload):
    compute_endpoint = BaseURLs.ASSETS_URL + "/compute"
    return client.post(
        compute_endpoint, data=json.dumps(payload), content_type="application/json"
    )
