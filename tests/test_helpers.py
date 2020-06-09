#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import json
import uuid


from ocean_keeper.utils import get_account

from ocean_provider.constants import BaseURLs
from ocean_provider.contracts.custom_contract import FactoryContract
from ocean_provider.utils.basics import get_config
from ocean_provider.utils.encryption import do_encrypt

from tests.conftest import get_sample_ddo

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
            "price": metadata[MetadataMain.KEY]['price'],
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated']
        }
    }

    return ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        f'http://localhost:8030{BaseURLs.ASSETS_URL}/download',
        0
    )


def get_dataset_ddo_with_access_service(account):
    metadata = get_sample_ddo()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_access_service_descriptor(account, metadata)
    return get_registered_ddo(account, metadata, service_descriptor)


def get_registered_ddo(account, metadata, service_descriptor):
    aqua = Aquarius('http://localhost:5000')

    ddo = DDO()
    ddo_service_endpoint = aqua.get_service_endpoint()

    # Create new data token contract
    dt_contract = FactoryContract(get_config().factory_address)\
        .create_data_token(account, metadata_url=ddo_service_endpoint)
    if not dt_contract:
        raise AssertionError('Creation of data token contract failed.')

    ddo._other_values = {'dataTokenAddress': dt_contract.address}

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
        json.dumps(metadata['main']['files']),
        account,
    )

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
