#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import mimetypes
from copy import deepcopy
from unittest.mock import Mock, MagicMock

from ocean_lib.models.data_token import DataToken
from werkzeug.utils import get_content_type
from ocean_utils.agreements.service_agreement import ServiceAgreement
from ocean_utils.agreements.service_types import ServiceTypes
from ocean_utils.aquarius.aquarius import Aquarius
from ocean_utils.http_requests.requests_session import get_requests_session
from ocean_lib.web3_internal.web3helper import Web3Helper
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg

from ocean_provider.constants import BaseURLs
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.util import build_download_response, get_download_url
from ocean_provider.utils.accounts import (
    check_auth_token,
    generate_auth_token,
    is_auth_token_valid,
    verify_signature,
)

from tests.test_helpers import (
    get_dataset_ddo_with_access_service,
    get_consumer_wallet,
    get_publisher_wallet,
    mint_tokens_and_wait, get_nonce, send_order)

SERVICE_ENDPOINT = BaseURLs.BASE_PROVIDER_URL + '/services/download'


def dummy_callback(*_):
    pass


def test_download_service(client):
    aqua = Aquarius('http://localhost:5000')
    try:
        for did in aqua.list_assets():
            aqua.retire_asset_ddo(did)
    except (ValueError, Exception):
        pass

    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()

    ddo = get_dataset_ddo_with_access_service(client, pub_wallet)
    dt_address = ddo.as_dictionary()['dataToken']
    dt_token = DataToken(dt_address)
    mint_tokens_and_wait(dt_token, cons_wallet, pub_wallet)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    tx_id = send_order(client, ddo, dt_token, sa, cons_wallet)
    index = 0
    download_endpoint = BaseURLs.ASSETS_URL + '/download'
    # Consume using url index and auth token (let the provider do the decryption)
    payload = dict({
        'documentId': ddo.did,
        'serviceId': sa.index,
        'serviceType': sa.type,
        'dataToken': dt_address,
        'consumerAddress': cons_wallet.address
    })
    payload['signature'] = generate_auth_token(cons_wallet)
    payload['transferTxId'] = tx_id
    payload['fileIndex'] = index
    request_url = download_endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])
    response = client.get(
        request_url
    )
    assert response.status_code == 200, f'{response.data}'

    # Consume using url index and signature (withOUT nonce), should fail
    _hash = add_ethereum_prefix_and_hash_msg(ddo.did)
    payload['signature'] = Web3Helper.sign_hash(_hash, cons_wallet)
    request_url = download_endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])
    print('>>>> Expecting InvalidSignatureError from the download endpoint <<<<')
    response = client.get(
        request_url
    )
    assert response.status_code == 401, f'{response.data}'

    # Consume using url index and signature (with nonce)
    nonce = get_nonce(client, cons_wallet.address)
    _hash = add_ethereum_prefix_and_hash_msg(f'{ddo.did}{nonce}')
    payload['signature'] = Web3Helper.sign_hash(_hash, cons_wallet)
    request_url = download_endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])
    response = client.get(
        request_url
    )
    assert response.status_code == 200, f'{response.data}'


def test_empty_payload(client):
    consume = client.get(
        BaseURLs.ASSETS_URL + '/download',
        data=None,
        content_type='application/json'
    )
    assert consume.status_code == 400

    publish = client.post(
        BaseURLs.ASSETS_URL + '/encrypt',
        data=None,
        content_type='application/json'
    )
    assert publish.status_code == 400


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
        verify_signature(pub_address, token, doc_id)
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
