#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import json
import time
import uuid

from ocean_keeper import Keeper
from ocean_keeper.utils import get_account, add_ethereum_prefix_and_hash_msg
from ocean_utils.agreements.service_types import ServiceTypes

from ocean_provider.constants import BaseURLs
from ocean_provider.contracts.custom_contract import FactoryContract
from ocean_provider.utils.basics import get_config
from ocean_provider.utils.data_token import get_asset_for_data_token
from ocean_provider.utils.encryption import do_encrypt

from tests.conftest import get_sample_ddo, get_resource_path

from plecos import plecos
from ocean_utils.ddo.ddo import DDO
from ocean_utils.utils.utilities import checksum
from ocean_utils.ddo.metadata import MetadataMain
from ocean_utils.aquarius.aquarius import Aquarius
from ocean_utils.did import DID
from ocean_utils.ddo.public_key_rsa import PUBLIC_KEY_TYPE_RSA
from ocean_utils.agreements.service_factory import ServiceDescriptor, ServiceFactory


def get_publisher_account():
    return get_account(0)


def get_consumer_account():
    return get_account(1)


def get_access_service_descriptor(account, metadata):
    access_service_attributes = {
        "main": {
            "name": "dataAssetAccessServiceAgreement",
            "creator": account.address,
            "cost": metadata[MetadataMain.KEY]['cost'],
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated']
        }
    }

    return ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        f'http://localhost:8030{BaseURLs.ASSETS_URL}/download',
        0
    )


def get_registered_ddo(account, metadata, service_descriptor):
    aqua = Aquarius('http://localhost:5000')

    ddo = DDO()
    ddo_service_endpoint = aqua.get_service_endpoint()

    # Create new data token contract
    dt_contract = FactoryContract(get_config().factory_address)\
        .create_data_token(account, metadata_url=ddo_service_endpoint)
    if not dt_contract:
        raise AssertionError('Creation of data token contract failed.')

    ddo._other_values = {'dataToken': dt_contract.address}

    metadata_service_desc = ServiceDescriptor.metadata_service_descriptor(
        metadata, ddo_service_endpoint
    )
    service_descriptors = list(
        [ServiceDescriptor.authorization_service_descriptor('http://localhost:12001')])
    service_descriptors.append(service_descriptor)
    service_type = service_descriptor[0]

    service_descriptors = [metadata_service_desc] + service_descriptors

    services = ServiceFactory.build_services(service_descriptors)
    checksums = dict()
    for service in services:
        checksums[str(service.index)] = checksum(service.main)

    # Adding proof to the ddo.
    ddo.add_proof(checksums, account)

    did = ddo.assign_did(DID.did(ddo.proof['checksum']))
    ddo_service_endpoint.replace('{did}', did)
    services[0].set_service_endpoint(ddo_service_endpoint)

    stype_to_service = {s.type: s for s in services}
    _service = stype_to_service[service_type]

    for service in services:
        ddo.add_service(service)

    # ddo.proof['signatureValue'] = ocean_lib.sign_hash(
    #     did_to_id_bytes(did), account)

    ddo.add_public_key(did, account.address)

    ddo.add_authentication(did, PUBLIC_KEY_TYPE_RSA)

    try:
        _oldddo = aqua.get_asset_ddo(ddo.did)
        if _oldddo:
            aqua.retire_asset_ddo(ddo.did)
    except ValueError:
        pass

    # if not plecos.is_valid_dict_local(ddo.metadata):
    #     print(f'invalid metadata: {plecos.validate_dict_local(ddo.metadata)}')
    #     assert False, f'invalid metadata: {plecos.validate_dict_local(ddo.metadata)}'

    files_list = json.dumps(metadata['main']['files'])
    encrypted_files = do_encrypt(files_list, account)

    # only assign if the encryption worked
    if encrypted_files:
        index = 0
        for file in metadata['main']['files']:
            file['index'] = index
            index = index + 1
            del file['url']
        metadata['encryptedFiles'] = encrypted_files

    # ddo._other_values
    try:
        aqua.publish_asset_ddo(ddo)
    except Exception as e:
        print(f'error publishing ddo {ddo.did} in Aquarius: {e}')
        raise

    return ddo


def get_dataset_ddo_with_access_service(account):
    metadata = get_sample_ddo()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_access_service_descriptor(account, metadata)
    return get_registered_ddo(account, metadata, service_descriptor)


def get_sample_algorithm_ddo():
    path = get_resource_path('ddo', 'ddo_sample_algorithm.json')
    assert path.exists(), f"{path} does not exist!"
    with open(path, 'r') as file_handle:
        metadata = file_handle.read()
    return json.loads(metadata)


def get_sample_ddo_with_compute_service():
    # 'ddo_sa_sample.json')
    path = get_resource_path('ddo', 'ddo_with_compute_service.json')
    assert path.exists(), f"{path} does not exist!"
    with open(path, 'r') as file_handle:
        metadata = file_handle.read()
    return json.loads(metadata)


def get_compute_service_descriptor(keeper, account, price, metadata):
    template_name = keeper.template_manager.SERVICE_TO_TEMPLATE_NAME[ServiceTypes.CLOUD_COMPUTE]
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": account.address,
            "cost": price,
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated']
        }
    }

    return ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        f'http://localhost:8030{BaseURLs.ASSETS_URL}/compute',
        keeper.template_manager.create_template_id(template_name)
    )


def get_compute_service_descriptor_no_rawalgo(keeper, account, price, metadata):
    template_name = keeper.template_manager.SERVICE_TO_TEMPLATE_NAME[ServiceTypes.CLOUD_COMPUTE]
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": account.address,
            "cost": price,
            "privacy": {
                "allowRawAlgorithm": False,
                "trustedAlgorithms": [],
                "allowNetworkAccess": True
            },
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated']
        }
    }

    return ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        f'http://localhost:8030{BaseURLs.ASSETS_URL}/compute',
        keeper.template_manager.create_template_id(template_name)
    )


def get_compute_service_descriptor_specific_algo_dids(keeper, account, price, metadata):
    template_name = keeper.template_manager.SERVICE_TO_TEMPLATE_NAME[ServiceTypes.CLOUD_COMPUTE]
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": account.address,
            "cost": price,
            "privacy": {
                "allowRawAlgorithm": True,
                "trustedAlgorithms": ['did:op:123', 'did:op:1234'],
                "allowNetworkAccess": True
            },
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated']
        }
    }

    return ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        f'http://localhost:8030{BaseURLs.ASSETS_URL}/compute',
        keeper.template_manager.create_template_id(template_name)
    )


def get_algorithm_ddo(account):
    metadata = get_sample_algorithm_ddo()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_access_service_descriptor(account, metadata)
    return get_registered_ddo(account, metadata, service_descriptor)


def get_dataset_ddo_with_compute_service(account):
    metadata = get_sample_ddo_with_compute_service()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_compute_service_descriptor(
        Keeper, account, metadata[MetadataMain.KEY]['cost'], metadata)
    return get_registered_ddo(account, metadata, service_descriptor)


def get_dataset_ddo_with_compute_service_no_rawalgo(account):
    metadata = get_sample_ddo_with_compute_service()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_compute_service_descriptor_no_rawalgo(
        Keeper, account, metadata[MetadataMain.KEY]['cost'], metadata)
    return get_registered_ddo(account, metadata, service_descriptor)


def get_dataset_ddo_with_compute_service_specific_algo_dids(account):
    metadata = get_sample_ddo_with_compute_service()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_compute_service_descriptor_specific_algo_dids(
        Keeper, account, metadata[MetadataMain.KEY]['cost'], metadata)
    return get_registered_ddo(account, metadata, service_descriptor)


def get_possible_compute_job_status_text():
    return {
        10: 'Job started',
        20: 'Configuring volumes',
        30: 'Provisioning success',
        31: 'Data provisioning failed',
        32: 'Algorithm provisioning failed',
        40: 'Running algorithm',
        50: 'Filtering results',
        60: 'Publishing results',
        70: 'Job completed',
    }.values()


def get_compute_job_info(client, endpoint, params):
    response = client.get(
        endpoint + '?' + '&'.join([f'{k}={v}' for k, v in params.items()]),
        data=json.dumps(params),
        content_type='application/json'
    )
    assert response.status_code == 200 and response.data, \
        f'get compute job info failed: status {response.status}, data {response.data}'

    job_info = response.json if response.json else json.loads(response.data)
    if not job_info:
        print(f'There is a problem with the job info response: {response.data}')
        return None, None

    return job_info[0]


def _check_job_id(client, job_id, did, token_address, wait_time=20):
    endpoint = BaseURLs.ASSETS_URL + '/compute'
    cons_acc = get_consumer_account()

    msg = f'{cons_acc.address}{job_id}{did}'
    agreement_id_hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = Keeper.sign_hash(agreement_id_hash, cons_acc)
    payload = dict({
        'signature': signature,
        'documentId': did,
        'consumerAddress': cons_acc.address,
        'jobId': job_id,
    })

    job_info = get_compute_job_info(client, endpoint, payload)
    assert job_info, f'Failed to get job info for jobId {job_id}'
    print(f'got info for compute job {job_id}: {job_info}')
    assert job_info['statusText'] in get_possible_compute_job_status_text()
    did = None
    # get did of results
    for _ in range(wait_time*4):
        job_info = get_compute_job_info(client, endpoint, payload)
        did = job_info['did']
        if did:
            break
        time.sleep(0.25)

    assert did, f'Compute job has no results, job info {job_info}.'
    # check results ddo
    ddo = get_asset_for_data_token(token_address, did)
    assert ddo, f'Failed to resolve ddo for did {did}'


def mint_tokens_and_wait(data_token_contract, receiver_account, minter_account):
    dtc = data_token_contract
    tx_id = dtc.mint(receiver_account.address, 50, minter_account)
    dtc.get_tx_receipt(tx_id)
    time.sleep(2)

    def verify_supply(mint_amount=50):
        supply = dtc.contract_concise.totalSupply()
        if supply <= 0:
            _tx_id = dtc.mint(receiver_account.address, mint_amount, minter_account)
            dtc.get_tx_receipt(_tx_id)
            supply = dtc.contract_concise.totalSupply()
        return supply

    while True:
        try:
            s = verify_supply()
            if s > 0:
                break
        except (ValueError, Exception):
            pass
