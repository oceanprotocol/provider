#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import json
import mimetypes
import time
from copy import deepcopy
from datetime import datetime
from unittest.mock import Mock, MagicMock
import uuid

import pytest
from eth_utils import add_0x_prefix
from ocean_lib.utils import add_ethereum_prefix_and_hash_msg
from ocean_utils.agreements.service_agreement import ServiceAgreement
from ocean_utils.agreements.service_factory import ServiceFactory
from ocean_utils.agreements.service_types import ServiceTypes
from ocean_utils.aquarius.aquarius import Aquarius
from ocean_utils.http_requests.requests_session import get_requests_session
from werkzeug.utils import get_content_type

from ocean_utils.did import DID, did_to_id

from ocean_provider.constants import BaseURLs
from ocean_provider.exceptions import InvalidSignatureError, ServiceAgreementExpired
from ocean_provider.util import (
    check_auth_token,
    do_secret_store_decrypt,
    generate_auth_token,
    get_config,
    get_provider_account,
    is_auth_token_valid,
    verify_signature,
    web3,
    build_download_response,
    get_download_url,
)
from tests.conftest import get_sample_ddo
from tests.test_helpers import (
    get_dataset_ddo_with_access_service,
    get_consumer_account,
    get_publisher_account,
    get_access_service_descriptor)

PURCHASE_ENDPOINT = BaseURLs.BASE_BRIZO_URL + '/services/access/initialize'
SERVICE_ENDPOINT = BaseURLs.BASE_BRIZO_URL + '/services/consume'


def dummy_callback(*_):
    pass


def test_consume(client):
    aqua = Aquarius('http://localhost:5000')
    for did in aqua.list_assets():
        aqua.retire_asset_ddo(did)

    endpoint = BaseURLs.ASSETS_URL + '/consume'

    pub_acc = get_publisher_account()
    cons_acc = get_consumer_account()

    keeper = keeper_instance()
    ddo = get_dataset_ddo_with_access_service(pub_acc, providers=[pub_acc.address])

    # initialize an agreement
    agreement_id = place_order(pub_acc, ddo, cons_acc, ServiceTypes.ASSET_ACCESS)
    payload = dict({
        'serviceAgreementId': agreement_id,
        'consumerAddress': cons_acc.address
    })

    agr_id_hash = add_ethereum_prefix_and_hash_msg(agreement_id)
    signature = keeper.sign_hash(agr_id_hash, cons_acc)
    index = 0

    event = keeper.agreement_manager.subscribe_agreement_created(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    consumer_balance = keeper.token.get_token_balance(cons_acc.address)
    if consumer_balance < 50:
        keeper.dispenser.request_tokens(50-consumer_balance, cons_acc)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    lock_reward(agreement_id, sa, cons_acc)
    event = keeper.lock_reward_condition.subscribe_condition_fulfilled(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event, "Lock reward condition fulfilled event is not found, check the keeper node's logs"

    grant_access(agreement_id, ddo, cons_acc, pub_acc)
    event = keeper.access_secret_store_condition.subscribe_condition_fulfilled(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event or keeper.access_secret_store_condition.check_permissions(
        ddo.asset_id, cons_acc.address
    ), f'Failed to get access permission: agreement_id={agreement_id}, ' \
       f'did={ddo.did}, consumer={cons_acc.address}'

    # Consume using decrypted url
    files_list = json.loads(
        do_secret_store_decrypt(did_to_id(ddo.did), ddo.encrypted_files, pub_acc, get_config()))
    payload['url'] = files_list[index]['url']
    request_url = endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])

    response = client.get(
        request_url
    )
    assert response.status == '200 OK'

    # Consume using url index and signature (let brizo do the decryption)
    payload.pop('url')
    payload['signature'] = signature
    payload['index'] = index
    request_url = endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])
    response = client.get(
        request_url
    )
    assert response.status == '200 OK'


def test_empty_payload(client):
    consume = client.get(
        BaseURLs.ASSETS_URL + '/consume',
        data=None,
        content_type='application/json'
    )
    assert consume.status_code == 400

    publish = client.post(
        BaseURLs.ASSETS_URL + '/publish',
        data=None,
        content_type='application/json'
    )
    assert publish.status_code == 400


def test_publish(client):
    endpoint = BaseURLs.ASSETS_URL + '/publish'
    did = DID.did({"0": str(uuid.uuid4())})
    asset_id = did_to_id(did)
    account = get_provider_account()
    test_urls = [
        'url 00',
        'url 11',
        'url 22'
    ]
    keeper = keeper_instance()
    urls_json = json.dumps(test_urls)
    asset_id_hash = add_ethereum_prefix_and_hash_msg(asset_id)
    signature = keeper.sign_hash(asset_id_hash, account)
    address = web3().eth.account.recoverHash(asset_id_hash, signature=signature)
    assert address.lower() == account.address.lower()
    address = keeper.personal_ec_recover(asset_id, signature)
    assert address.lower() == account.address.lower()

    payload = {
        'documentId': asset_id,
        'signature': signature,
        'document': urls_json,
        'publisherAddress': account.address
    }
    post_response = client.post(
        endpoint,
        data=json.dumps(payload),
        content_type='application/json'
    )
    encrypted_url = post_response.data.decode('utf-8')
    assert encrypted_url.startswith('0x')

    # publish using auth token
    signature = generate_auth_token(account)
    payload['signature'] = signature
    did = DID.did({"0": str(uuid.uuid4())})
    asset_id = did_to_id(did)
    payload['documentId'] = add_0x_prefix(asset_id)
    post_response = client.post(
        endpoint,
        data=json.dumps(payload),
        content_type='application/json'
    )
    encrypted_url = post_response.data.decode('utf-8')
    assert encrypted_url.startswith('0x')


def test_auth_token():
    token = "0x1d2741dee30e64989ef0203957c01b14f250f5d2f6ccb0" \
            "c88c9518816e4fcec16f84e545094eb3f377b7e214ded226" \
            "76fbde8ca2e41b4eb1b3565047ecd9acf300-1568372035"
    pub_address = "0xe2DD09d719Da89e5a3D0F2549c7E24566e947260"
    doc_id = "663516d306904651bbcf9fe45a00477c215c7303d8a24c5bad6005dd2f95e68e"
    assert is_auth_token_valid(token), f'cannot recognize auth-token {token}'
    address = check_auth_token(token)
    assert address and address.lower() == pub_address.lower(), f'address mismatch, got {address}, ' \
                                                               f'' \
                                                               f'' \
                                                               f'expected {pub_address}'

    try:
        verify_signature(Keeper, pub_address, token, doc_id)
    except InvalidSignatureError as e:
        assert False, f'invalid signature/auth-token {token}, {pub_address}, {doc_id}: {e}'


def test_exec_endpoint():
    pass


def test_download_ipfs_file(client):
    cid = 'QmQfpdcMWnLTXKKW9GPV7NgtEugghgD6HgzSF6gSrp2mL9'
    url = f'ipfs://{cid}'
    download_url = get_download_url(url, None)
    requests_session = get_requests_session()

    request = Mock()
    request.range = None

    print(f'got ipfs download url: {download_url}')
    assert download_url and download_url.endswith(f'ipfs/{cid}')
    response = build_download_response(request, requests_session, download_url, download_url, None)
    assert response.data, f'got no data {response.data}'


def test_build_download_response():
    request = Mock()
    request.range = None

    class Dummy:
        pass

    mocked_response = Dummy()
    mocked_response.content = b'asdsadf'
    mocked_response.status_code = 200
    mocked_response.headers = {}

    requests_session = Dummy()
    requests_session.get = MagicMock(return_value=mocked_response)

    filename = '<<filename>>.xml'
    content_type = mimetypes.guess_type(filename)[0]
    url = f'https://source-lllllll.cccc/{filename}'
    response = build_download_response(request, requests_session, url, url, None)
    assert response.headers["content-type"] == content_type
    assert response.headers.get_all('Content-Disposition')[0] == f'attachment;filename={filename}'

    filename = '<<filename>>'
    url = f'https://source-lllllll.cccc/{filename}'
    response = build_download_response(request, requests_session, url, url, None)
    assert response.headers["content-type"] == get_content_type(response.default_mimetype, response.charset)
    assert response.headers.get_all('Content-Disposition')[0] == f'attachment;filename={filename}'

    filename = '<<filename>>'
    url = f'https://source-lllllll.cccc/{filename}'
    response = build_download_response(request, requests_session, url, url, content_type)
    assert response.headers["content-type"] == content_type
    assert response.headers.get_all('Content-Disposition')[0] == f'attachment;filename={filename+mimetypes.guess_extension(content_type)}'

    mocked_response_with_attachment = deepcopy(mocked_response)
    attachment_file_name = 'test.xml'
    mocked_response_with_attachment.headers = {'content-disposition': f'attachment;filename={attachment_file_name}'}

    requests_session_with_attachment = Dummy()
    requests_session_with_attachment.get = MagicMock(return_value=mocked_response_with_attachment)

    url = 'https://source-lllllll.cccc/not-a-filename'
    response = build_download_response(request, requests_session_with_attachment, url, url, None)
    assert response.headers["content-type"] == mimetypes.guess_type(attachment_file_name)[0]
    assert response.headers.get_all('Content-Disposition')[0] == f'attachment;filename={attachment_file_name}'

    mocked_response_with_content_type = deepcopy(mocked_response)
    response_content_type = 'text/csv'
    mocked_response_with_content_type.headers = {'content-type': response_content_type}

    requests_session_with_content_type = Dummy()
    requests_session_with_content_type.get = MagicMock(return_value=mocked_response_with_content_type)

    filename = 'filename.txt'
    url = f'https://source-lllllll.cccc/{filename}'
    response = build_download_response(request, requests_session_with_content_type, url, url, None)
    assert response.headers["content-type"] == response_content_type
    assert response.headers.get_all('Content-Disposition')[0] == f'attachment;filename={filename}'


def test_agreement_expiry():
    pub_acc = get_publisher_account()
    keeper = keeper_instance()
    metadata = get_sample_ddo()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    service_descriptor = get_access_service_descriptor(keeper, pub_acc, metadata)
    service_descriptor[1]['attributes']['main']['timeout'] = 2
    agreement = ServiceFactory.build_service(service_descriptor)
    start_time = datetime.now().timestamp()
    not_expired = validate_agreement_expiry(agreement, start_time)
    assert not_expired, 'Agreement should not be expired at this point.'
    time.sleep(3)
    with pytest.raises(ServiceAgreementExpired):
        validate_agreement_expiry(agreement, start_time)
