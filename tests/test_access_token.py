#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0
import time

from ocean_lib.models.data_token import DataToken
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_lib.web3_internal.web3helper import Web3Helper
from ocean_utils.agreements.service_agreement import ServiceAgreement
from ocean_utils.agreements.service_types import ServiceTypes
from ocean_utils.aquarius.aquarius import Aquarius

from ocean_provider.access_token import AccessToken
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import generate_auth_token, get_private_key
from ocean_provider.utils.basics import get_config
from ocean_provider.utils.encryption import do_decrypt
from tests.test_helpers import (get_consumer_wallet,
                                get_dataset_ddo_with_access_service, get_nonce,
                                get_publisher_wallet, get_some_wallet,
                                mint_tokens_and_wait, send_order)

user_access_token = AccessToken(get_config().storage_path)


def test_access_token(client):
    aqua = Aquarius('http://localhost:5000')
    try:
        for did in aqua.list_assets():
            aqua.retire_asset_ddo(did)
    except (ValueError, Exception):
        pass

    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()
    some_wallet = get_some_wallet()

    ddo = get_dataset_ddo_with_access_service(client, pub_wallet)
    dt_address = ddo.as_dictionary()['dataToken']
    dt_token = DataToken(dt_address)
    mint_tokens_and_wait(dt_token, cons_wallet, pub_wallet)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    tx_id = send_order(client, ddo, dt_token, sa, cons_wallet)
    index = 0
    at_endpoint = BaseURLs.ASSETS_URL + '/accesstoken'
    # Consume using url index and auth token
    # (let the provider do the decryption)
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
    payload['secondsToExpiration'] = 15 * 60
    payload['delegatePublicKey'] = get_private_key(cons_wallet).public_key

    request_url = at_endpoint + '?' + '&'.join(
        [f'{k}={v}' for k, v in payload.items()]
    )
    response = client.get(request_url)
    assert response.status_code == 200

    response_json = response.get_json()
    assert 'access_token' in response_json
    # start from scratch, preventing 400 from duplicate failures
    decrypted_at = do_decrypt(response_json['access_token'], cons_wallet)
    user_access_token.storage._run_query(
        "DELETE from access_token where access_token=?;",
        (decrypted_at,)
    )

    # Try generating access token using url index and
    # signature (withOUT nonce), should fail
    _hash = add_ethereum_prefix_and_hash_msg(ddo.did)
    payload['signature'] = Web3Helper.sign_hash(_hash, cons_wallet)
    request_url = at_endpoint + '?' + '&'.join(
        [f'{k}={v}' for k, v in payload.items()]
    )
    print('>>>> Expecting InvalidSignatureError from the download endpoint <<<<')  # noqa
    response = client.get(
        request_url
    )
    assert response.status_code == 400, f'{response.data}'

    # Consume using url index and signature (with nonce)
    nonce = get_nonce(client, cons_wallet.address)
    _hash = add_ethereum_prefix_and_hash_msg(f'{ddo.did}{nonce}')
    payload['signature'] = Web3Helper.sign_hash(_hash, cons_wallet)
    payload.pop('delegatePublicKey')
    request_url = at_endpoint + '?' + '&'.join(
        [f'{k}={v}' for k, v in payload.items()]
    )
    response = client.get(request_url)
    # missing delegatePublicKey
    assert response.status_code == 400, f'{response.data}'

    payload['delegatePublicKey'] = get_private_key(some_wallet).public_key
    response = client.get(request_url)
    request_url = at_endpoint + '?' + '&'.join(
        [f'{k}={v}' for k, v in payload.items()]
    )
    response = client.get(request_url)
    assert response.status_code == 200, f'{response.data}'

    response = client.get(request_url)
    # second time doesn't work because token already exists
    assert response.status_code == 400, f'{response.data}'


def test_access_token_usage(client):
    aqua = Aquarius('http://localhost:5000')
    try:
        for did in aqua.list_assets():
            aqua.retire_asset_ddo(did)
    except (ValueError, Exception):
        pass

    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()
    some_wallet = get_some_wallet()

    ddo = get_dataset_ddo_with_access_service(client, pub_wallet)
    dt_address = ddo.as_dictionary()['dataToken']
    dt_token = DataToken(dt_address)
    mint_tokens_and_wait(dt_token, cons_wallet, pub_wallet)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    tx_id = send_order(client, ddo, dt_token, sa, cons_wallet)
    index = 0
    at_endpoint = BaseURLs.ASSETS_URL + '/accesstoken'
    # Consume using url index and auth token
    # (let the provider do the decryption)
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
    payload['secondsToExpiration'] = 15 * 60
    payload['delegatePublicKey'] = get_private_key(some_wallet).public_key

    request_url = at_endpoint + '?' + '&'.join(
        [f'{k}={v}' for k, v in payload.items()]
    )
    response = client.get(request_url)
    assert response.status_code == 200
    response_json = response.get_json()
    assert 'access_token' in response_json

    decrypted_at = do_decrypt(response_json['access_token'], some_wallet)

    download_endpoint = BaseURLs.ASSETS_URL + '/download'
    # Consume using url index and signature (with nonce)
    nonce = decrypted_at
    _hash = add_ethereum_prefix_and_hash_msg(f'{ddo.did}{nonce}')
    payload.pop('secondsToExpiration')
    payload['consumerAddress'] = some_wallet.address
    payload['signature'] = Web3Helper.sign_hash(_hash, some_wallet)
    request_url = download_endpoint + '?' + '&'.join(
        [f'{k}={v}' for k, v in payload.items()]
    )
    response = client.get(request_url)
    assert response.status_code == 200, f'{response.data}'

    # intentional duplication, it works for multiple access
    response = client.get(request_url)
    assert response.status_code == 200, f'{response.data}'


def test_access_token_expired(client):
    aqua = Aquarius('http://localhost:5000')
    try:
        for did in aqua.list_assets():
            aqua.retire_asset_ddo(did)
    except (ValueError, Exception):
        pass

    pub_wallet = get_publisher_wallet()
    cons_wallet = get_consumer_wallet()
    some_wallet = get_some_wallet()

    ddo = get_dataset_ddo_with_access_service(client, pub_wallet)
    dt_address = ddo.as_dictionary()['dataToken']
    dt_token = DataToken(dt_address)
    mint_tokens_and_wait(dt_token, cons_wallet, pub_wallet)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    tx_id = send_order(client, ddo, dt_token, sa, cons_wallet)
    index = 0
    at_endpoint = BaseURLs.ASSETS_URL + '/accesstoken'
    # Consume using url index and auth token
    # (let the provider do the decryption)
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
    payload['secondsToExpiration'] = 1
    payload['delegatePublicKey'] = get_private_key(some_wallet).public_key

    request_url = at_endpoint + '?' + '&'.join(
        [f'{k}={v}' for k, v in payload.items()]
    )
    response = client.get(request_url)
    assert response.status_code == 200
    response_json = response.get_json()
    assert 'access_token' in response_json

    decrypted_at = do_decrypt(response_json['access_token'], some_wallet)

    download_endpoint = BaseURLs.ASSETS_URL + '/download'
    # Consume using url index and signature (with nonce)
    nonce = decrypted_at
    _hash = add_ethereum_prefix_and_hash_msg(f'{ddo.did}{nonce}')
    payload.pop('secondsToExpiration')
    payload['consumerAddress'] = some_wallet.address
    payload['signature'] = Web3Helper.sign_hash(_hash, some_wallet)
    request_url = download_endpoint + '?' + '&'.join(
        [f'{k}={v}' for k, v in payload.items()]
    )

    # let's give our token some time to expire... then it should fail
    time.sleep(5)
    response = client.get(request_url)
    assert response.status_code == 400, f'{response.data}'
