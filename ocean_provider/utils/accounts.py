import json
import time
from datetime import datetime

import eth_keys
from web3 import Web3
from ocean_utils.http_requests.requests_session import get_requests_session

from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.utils.basics import get_config
from ocean_provider.utils.web3 import web3
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_lib.web3_internal.web3helper import Web3Helper


def verify_signature(signer_address, signature, original_msg, nonce: int=None):
    if is_auth_token_valid(signature):
        address = check_auth_token(signature)
    else:
        assert nonce is not None, 'nonce is required when not using user auth token.'
        message = f'{original_msg}{str(nonce)}'
        address = Web3Helper.personal_ec_recover(message, signature)

    if address.lower() == signer_address.lower():
        return True

    msg = f'Invalid signature {signature} for ' \
          f'ethereum address {signer_address}, documentId {original_msg}' \
          f'and nonce {nonce}.'
    raise InvalidSignatureError(msg)


def get_private_key(wallet):
    pk = wallet.private_key
    if not isinstance(pk, bytes):
        pk = web3().toBytes(hexstr=pk)
    return eth_keys.KeyAPI.PrivateKey(pk)


def is_auth_token_valid(token):
    return isinstance(token, str) and token.startswith('0x') and len(token.split('-')) == 2


def check_auth_token(token):
    parts = token.split('-')
    if len(parts) < 2:
        return '0x0'
    # :HACK: alert, this should be part of ocean-lib-py
    sig, timestamp = parts
    auth_token_message = get_config().auth_token_message or "Ocean Protocol Authentication"
    default_exp = 24 * 60 * 60
    expiration = int(get_config().auth_token_expiration or default_exp)
    if int(datetime.now().timestamp()) > (int(timestamp) + expiration):
        return '0x0'

    message = f'{auth_token_message}\n{timestamp}'
    address = Web3Helper.personal_ec_recover(message, sig)
    return Web3.toChecksumAddress(address)


def generate_auth_token(wallet):
    raw_msg = get_config().auth_token_message or "Ocean Protocol Authentication"
    _time = int(datetime.now().timestamp())
    _message = f'{raw_msg}\n{_time}'
    prefixed_msg_hash = add_ethereum_prefix_and_hash_msg(_message)
    return f'{Web3Helper.sign_hash(prefixed_msg_hash, wallet)}-{_time}'


def request_ether(faucet_url, wallet, wait=True):
    requests = get_requests_session()

    payload = {"address": wallet.address}
    response = requests.post(
        f'{faucet_url}/faucet',
        data=json.dumps(payload),
        headers={'content-type': 'application/json'}
    )
    try:
        response_json = json.loads(response.content)
        success = response_json.get('success', 'false') == 'true'
        if success and wait:
            time.sleep(5)

        return success, response_json.get('message', '')
    except (ValueError, Exception) as err:
        print(f'Error parsing response {response}: {err}')
        return None, None
