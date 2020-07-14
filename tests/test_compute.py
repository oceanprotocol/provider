#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import json

from ocean_provider.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_provider.web3_internal.web3helper import Web3Helper
from ocean_utils.agreements.service_agreement import ServiceAgreement
from ocean_utils.agreements.service_types import ServiceTypes
from web3 import Web3

from ocean_provider.constants import BaseURLs
from ocean_provider.contracts.datatoken import DataTokenContract
from ocean_provider.util import build_stage_output_dict

from tests.test_helpers import (
    get_consumer_account,
    get_publisher_account,
    get_dataset_ddo_with_compute_service_no_rawalgo, get_dataset_ddo_with_compute_service_specific_algo_dids, get_algorithm_ddo,
    get_dataset_ddo_with_compute_service, get_compute_job_info, get_possible_compute_job_status_text, mint_tokens_and_wait)

SERVICE_ENDPOINT = BaseURLs.BASE_PROVIDER_URL + '/services/download'


def test_compute_norawalgo_allowed(client):
    pub_acc = get_publisher_account()
    cons_acc = get_consumer_account()

    # publish a dataset asset
    dataset_ddo_w_compute_service = get_dataset_ddo_with_compute_service_no_rawalgo(pub_acc)
    did = dataset_ddo_w_compute_service.did
    ddo = dataset_ddo_w_compute_service
    data_token = dataset_ddo_w_compute_service.as_dictionary()['dataToken']
    dt_contract = DataTokenContract(data_token)
    mint_tokens_and_wait(dt_contract, cons_acc, pub_acc)

    # CHECKPOINT 1
    algorithm_meta = {
        "rawcode": "console.log('Hello world'!)",
        "format": 'docker-image',
        "version": '0.1',
        "container": {
            "entrypoint": 'node $ALGO',
            "image": 'node',
            "tag": '10'
        }
    }
    # prepare parameter values for the compute endpoint
    # signature, documentId, consumerAddress, and algorithmDid or algorithmMeta

    sa = ServiceAgreement.from_ddo(ServiceTypes.CLOUD_COMPUTE, dataset_ddo_w_compute_service)

    init_endpoint = BaseURLs.ASSETS_URL + '/initialize'
    payload = dict({
        'documentId': ddo.did,
        'serviceId': sa.index,
        'serviceType': sa.type,
        'dataToken': data_token,
        'consumerAddress': cons_acc.address
    })

    request_url = init_endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])

    response = client.get(
        request_url
    )
    assert response.status == '200 OK'

    tx_params = response.json
    num_tokens = tx_params['numTokens']
    assert tx_params['from'] == cons_acc.address
    assert tx_params['to'] == pub_acc.address
    assert tx_params['dataToken'] == ddo.as_dictionary()['dataToken']

    tx_id = dt_contract.transfer(tx_params['to'], num_tokens, cons_acc)
    dt_contract.get_tx_receipt(tx_id)

    # prepare consumer signature on did
    msg = f'{cons_acc.address}{did}'
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_acc)

    # Start the compute job
    payload = dict({
        'signature': signature,
        'documentId': did,
        'serviceId': sa.index,
        'serviceType': sa.type,
        'consumerAddress': cons_acc.address,
        'transferTxId': tx_id,
        'dataToken': data_token,
        'output': build_stage_output_dict(dict(), dataset_ddo_w_compute_service, cons_acc.address, pub_acc),
        'algorithmDid': '',
        'algorithmMeta': algorithm_meta,
        'algorithmDataToken': ''
    })

    compute_endpoint = BaseURLs.ASSETS_URL + '/compute'
    response = client.post(
        compute_endpoint,
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert response.status == '400 BAD REQUEST', f'start compute job failed: {response.status} , { response.data}'


def test_compute_specific_algo_dids(client):
    pub_acc = get_publisher_account()
    cons_acc = get_consumer_account()

    # publish a dataset asset
    dataset_ddo_w_compute_service = get_dataset_ddo_with_compute_service_specific_algo_dids(pub_acc)
    did = dataset_ddo_w_compute_service.did
    ddo = dataset_ddo_w_compute_service
    data_token = dataset_ddo_w_compute_service.as_dictionary()['dataToken']
    dt_contract = DataTokenContract(data_token)
    mint_tokens_and_wait(dt_contract, cons_acc, pub_acc)

    # publish an algorithm asset (asset with metadata of type `algorithm`)
    alg_ddo = get_algorithm_ddo(cons_acc)
    alg_data_token = alg_ddo.as_dictionary()['dataToken']
    alg_dt_contract = DataTokenContract(alg_data_token)
    mint_tokens_and_wait(alg_dt_contract, pub_acc, cons_acc)
    # CHECKPOINT 1

    # prepare parameter values for the compute endpoint
    # signature, documentId, consumerAddress, and algorithmDid or algorithmMeta

    sa = ServiceAgreement.from_ddo(
        ServiceTypes.CLOUD_COMPUTE, dataset_ddo_w_compute_service)

    init_endpoint = BaseURLs.ASSETS_URL + '/initialize'
    payload = dict({
        'documentId': ddo.did,
        'serviceId': sa.index,
        'serviceType': sa.type,
        'dataToken': data_token,
        'consumerAddress': cons_acc.address
    })

    request_url = init_endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])

    response = client.get(
        request_url
    )
    assert response.status == '200 OK'

    tx_params = response.json
    num_tokens = tx_params['numTokens']
    assert tx_params['from'] == cons_acc.address
    assert tx_params['to'] == pub_acc.address
    assert tx_params['dataToken'] == ddo.as_dictionary()['dataToken']

    tx_id = dt_contract.transfer(tx_params['to'], num_tokens, cons_acc)
    dt_contract.get_tx_receipt(tx_id)

    # prepare consumer signature on did
    msg = f'{cons_acc.address}{did}'
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_acc)

    # Start the compute job
    payload = dict({
        'signature': signature,
        'documentId': did,
        'serviceId': sa.index,
        'serviceType': sa.type,
        'consumerAddress': cons_acc.address,
        'transferTxId': tx_id,
        'dataToken': data_token,
        'output': build_stage_output_dict(dict(), dataset_ddo_w_compute_service, cons_acc.address, pub_acc),
        'algorithmDid': alg_ddo.did,
        'algorithmMeta': {},
        'algorithmDataToken': alg_data_token
    })

    compute_endpoint = BaseURLs.ASSETS_URL + '/compute'
    response = client.post(
        compute_endpoint,
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert response.status == '400 BAD REQUEST', f'start compute job failed: {response.status} , { response.data}'


def test_compute(client):
    init_endpoint = BaseURLs.ASSETS_URL + '/initialize'

    pub_acc = get_publisher_account()
    cons_acc = get_consumer_account()

    # publish a dataset asset
    dataset_ddo_w_compute_service = get_dataset_ddo_with_compute_service(pub_acc)
    did = dataset_ddo_w_compute_service.did
    ddo = dataset_ddo_w_compute_service
    data_token = dataset_ddo_w_compute_service.as_dictionary()['dataToken']
    dt_contract = DataTokenContract(data_token)
    mint_tokens_and_wait(dt_contract, cons_acc, pub_acc)

    # publish an algorithm asset (asset with metadata of type `algorithm`)
    alg_ddo = get_algorithm_ddo(cons_acc, pub_acc)
    alg_data_token = alg_ddo.as_dictionary()['dataToken']
    alg_dt_contract = DataTokenContract(alg_data_token)
    mint_tokens_and_wait(alg_dt_contract, cons_acc, cons_acc)
    # CHECKPOINT 1

    sa = ServiceAgreement.from_ddo(
        ServiceTypes.CLOUD_COMPUTE, dataset_ddo_w_compute_service)

    # initialize the service
    payload = dict({
        'documentId': ddo.did,
        'serviceId': sa.index,
        'serviceType': sa.type,
        'dataToken': data_token,
        'consumerAddress': cons_acc.address
    })

    request_url = init_endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])

    response = client.get(
        request_url
    )
    assert response.status == '200 OK'

    tx_params = response.json
    num_tokens = tx_params['numTokens']
    assert tx_params['from'] == cons_acc.address
    assert tx_params['to'] == pub_acc.address
    assert tx_params['dataToken'] == ddo.as_dictionary()['dataToken']

    tx_id = dt_contract.transfer(tx_params['to'], num_tokens, cons_acc)
    dt_contract.get_tx_receipt(tx_id)

    alg_service = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, alg_ddo)
    alg_tx_id = alg_dt_contract.transfer(tx_params['to'], int(alg_service.get_cost()), cons_acc)
    alg_dt_contract.get_tx_receipt(alg_tx_id)

    # prepare consumer signature on did
    msg = f'{cons_acc.address}{did}'
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_acc)

    # Start the compute job
    payload = dict({
        'signature': signature,
        'documentId': did,
        'serviceId': sa.index,
        'serviceType': sa.type,
        'consumerAddress': cons_acc.address,
        'transferTxId': tx_id,
        'dataToken': data_token,
        'output': build_stage_output_dict(dict(), dataset_ddo_w_compute_service, cons_acc.address, pub_acc),
        'algorithmDid': alg_ddo.did,
        'algorithmMeta': {},
        'algorithmDataToken': alg_data_token,
        'algorithmTransferTxId': alg_tx_id
    })

    compute_endpoint = BaseURLs.ASSETS_URL + '/compute'
    response = client.post(
        compute_endpoint,
        data=json.dumps(payload),
        content_type='application/json'
    )
    assert response.status == '200 OK', f'start compute job failed: {response.data}'
    job_info = response.json[0]
    print(f'got response from starting compute job: {job_info}')
    job_id = job_info.get('jobId', '')

    msg = f'{cons_acc.address}{job_id}{did}'
    _hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Web3Helper.sign_hash(_hash, cons_acc)

    payload = dict({
        'signature': signature,
        'documentId': did,
        'consumerAddress': cons_acc.address,
        'jobId': job_id,
    })

    job_info = get_compute_job_info(client, compute_endpoint, payload)
    assert job_info, f'Failed to get job info for jobId {job_id}'
    print(f'got info for compute job {job_id}: {job_info}')
    assert job_info['statusText'] in get_possible_compute_job_status_text()
