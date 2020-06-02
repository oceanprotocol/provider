from datetime import datetime

import eth_keys
from ocean_keeper import Keeper
from ocean_keeper.utils import get_account, add_ethereum_prefix_and_hash_msg
from web3 import Web3

from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.util import get_config


def get_provider_account():
    return get_account(0)


def personal_ec_recover(message, signed_message, ):
    return Keeper.personal_ec_recover(message, signed_message)


def verify_signature(signer_address, signature, original_msg):
    if is_token_valid(signature):
        address = check_auth_token(signature)
    else:
        address = Keeper.personal_ec_recover(original_msg, signature)

    if address.lower() == signer_address.lower():
        return True

    msg = f'Invalid signature {signature} for ' \
          f'ethereum address {signer_address} and documentId {original_msg}.'
    raise InvalidSignatureError(msg)


def get_private_key(account):
    key = account.key
    if account.password:
        key = Web3.eth.account.decrypt(key, account.password)

    return eth_keys.KeyAPI.PrivateKey(key)


def is_token_valid(token):
    return isinstance(token, str) and token.startswith('0x') and len(token.split('-')) == 2


def check_auth_token(token):
    w3 = Web3
    parts = token.split('-')
    if len(parts) < 2:
        return '0x0'
    # :HACK: alert, this should be part of ocean-utils, ocean-keeper, or a stand-alone library
    sig, timestamp = parts
    auth_token_message = get_config().auth_token_message or "Ocean Protocol Authentication"
    default_exp = 24 * 60 * 60
    expiration = int(get_config().auth_token_expiration or default_exp)
    if int(datetime.now().timestamp()) > (int(timestamp) + expiration):
        return '0x0'

    message = f'{auth_token_message}\n{timestamp}'
    address = personal_ec_recover(message, sig)
    return w3.toChecksumAddress(address)


def generate_token(account):
    raw_msg = get_config().auth_token_message or "Ocean Protocol Authentication"
    _time = int(datetime.now().timestamp())
    _message = f'{raw_msg}\n{_time}'
    prefixed_msg_hash = add_ethereum_prefix_and_hash_msg(_message)
    return f'{sign_hash(prefixed_msg_hash, account)}-{_time}'


