#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import json
import time
import uuid


from eth_utils import remove_0x_prefix
from ocean_lib.utils import get_account, add_ethereum_prefix_and_hash_msg

from ocean_provider.constants import BaseURLs
from ocean_provider.util import do_encrypt, get_config, web3, keeper_instance

from tests.conftest import get_sample_ddo, get_resource_path

from plecos import plecos
from ocean_utils.ddo.ddo import DDO
from ocean_utils.utils.utilities import checksum
from ocean_utils.ddo.metadata import MetadataMain
from ocean_utils.aquarius.aquarius import Aquarius
from ocean_utils.did import DID, did_to_id_bytes
from ocean_utils.ddo.public_key_rsa import PUBLIC_KEY_TYPE_RSA
from ocean_utils.agreements.service_agreement import ServiceAgreement
from ocean_utils.agreements.service_factory import ServiceDescriptor, ServiceFactory
from ocean_utils.agreements.service_types import ServiceTypes


def get_publisher_account():
    return get_account(0)


def get_consumer_account():
    return get_account(1)


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


def get_access_service_descriptor(keeper, account, metadata):
    template_name = keeper.template_manager.SERVICE_TO_TEMPLATE_NAME[ServiceTypes.ASSET_ACCESS]
    access_service_attributes = {
        "main": {
            "name": "dataAssetAccessServiceAgreement",
            "creator": account.address,
            "price": metadata[MetadataMain.KEY]['price'],
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated']
        }
    }

    return ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        f'http://localhost:8030{BaseURLs.ASSETS_URL}/consume',
    )


def get_compute_service_descriptor(keeper, account, price, metadata):
    template_name = keeper.template_manager.SERVICE_TO_TEMPLATE_NAME[ServiceTypes.CLOUD_COMPUTE]
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": account.address,
            "price": price,
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated']
        }
    }

    return ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        f'http://localhost:8030{BaseURLs.ASSETS_URL}/compute',
    )


def get_compute_service_descriptor_no_rawalgo(keeper, account, price, metadata):
    template_name = keeper.template_manager.SERVICE_TO_TEMPLATE_NAME[ServiceTypes.CLOUD_COMPUTE]
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": account.address,
            "price": price,
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
    )


def get_compute_service_descriptor_specific_algo_dids(keeper, account, price, metadata):
    template_name = keeper.template_manager.SERVICE_TO_TEMPLATE_NAME[ServiceTypes.CLOUD_COMPUTE]
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": account.address,
            "price": price,
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
    )


def get_algorithm_ddo(account, providers=None):
    keeper = keeper_instance()
    metadata = get_sample_algorithm_ddo()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_access_service_descriptor(
        keeper, account, metadata)
    return get_registered_ddo(account, metadata, service_descriptor, providers)


def get_dataset_ddo_with_compute_service(account, providers=None):
    keeper = keeper_instance()
    metadata = get_sample_ddo_with_compute_service()[
        'service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_compute_service_descriptor(
        keeper, account, metadata[MetadataMain.KEY]['price'], metadata)
    return get_registered_ddo(account, metadata, service_descriptor, providers)


def get_dataset_ddo_with_compute_service_no_rawalgo(account, providers=None):
    keeper = keeper_instance()
    metadata = get_sample_ddo_with_compute_service()[
        'service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_compute_service_descriptor_no_rawalgo(
        keeper, account, metadata[MetadataMain.KEY]['price'], metadata)
    return get_registered_ddo(account, metadata, service_descriptor, providers)


def get_dataset_ddo_with_compute_service_specific_algo_dids(account, providers=None):
    keeper = keeper_instance()
    metadata = get_sample_ddo_with_compute_service()[
        'service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_compute_service_descriptor_specific_algo_dids(
        keeper, account, metadata[MetadataMain.KEY]['price'], metadata)
    return get_registered_ddo(account, metadata, service_descriptor, providers)


def get_dataset_ddo_with_access_service(account, providers=None):
    keeper = keeper_instance()
    metadata = get_sample_ddo()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_access_service_descriptor(
        keeper, account, metadata)
    return get_registered_ddo(account, metadata, service_descriptor, providers)


def get_registered_ddo(account, metadata, service_descriptor, providers=None):
    aqua = Aquarius('http://localhost:5000')

    ddo = DDO()
    ddo_service_endpoint = aqua.get_service_endpoint()

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

    if not plecos.is_valid_dict_local(ddo.metadata):
        print(f'invalid metadata: {plecos.validate_dict_local(ddo.metadata)}')
        assert False, f'invalid metadata: {plecos.validate_dict_local(ddo.metadata)}'

    encrypted_files = do_encrypt(
        remove_0x_prefix(ddo.asset_id),
        json.dumps(metadata['main']['files']),
        account,
        get_config()
    )

    # only assign if the encryption worked
    if encrypted_files:
        index = 0
        for file in metadata['main']['files']:
            file['index'] = index
            index = index + 1
            del file['url']
        metadata['encryptedFiles'] = encrypted_files

    keeper_instance().did_registry.register(
        ddo.asset_id,
        checksum=web3().toBytes(hexstr=ddo.asset_id),
        url=ddo_service_endpoint,
        account=account,
        providers=providers
    )

    try:
        aqua.publish_asset_ddo(ddo)
    except Exception as e:
        print(f'error publishing ddo {ddo.did} in Aquarius: {e}')
        raise

    return ddo


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
        print(
            f'There is a problem with the job info response: {response.data}')
        return None, None

    return job_info[0]


def _check_job_id(client, job_id, agreement_id, wait_time=20):
    endpoint = BaseURLs.ASSETS_URL + '/compute'
    cons_acc = get_consumer_account()

    keeper = keeper_instance()
    msg = f'{cons_acc.address}{job_id}{agreement_id}'
    agreement_id_hash = add_ethereum_prefix_and_hash_msg(msg)
    signature = sign_hash(agreement_id_hash, cons_acc)
    payload = dict({
        'signature': signature,
        'serviceAgreementId': agreement_id,
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
    ddo = DIDResolver(keeper.did_registry).resolve(did)
    assert ddo, f'Failed to resolve ddo for did {did}'
    consumer_permission = keeper.did_registry.get_permission(
        did, cons_acc.address)
    assert consumer_permission is True, \
        f'Consumer address {cons_acc.address} has no permissions on the results ' \
        f'did {did}. This is required, the consumer must be able to access the results'
