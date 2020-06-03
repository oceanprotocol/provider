import os
from datetime import datetime

import eth_keys
from ocean_keeper import Keeper
from ocean_keeper.utils import get_account, add_ethereum_prefix_and_hash_msg
from web3 import Web3

from ocean_provider.basics import get_config
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.web3 import web3


def get_provider_account():
    return get_account(0)


def init_account_envvars():
    os.environ['PARITY_ADDRESS'] = os.getenv('PROVIDER_ADDRESS', '')
    os.environ['PARITY_PASSWORD'] = os.getenv('PROVIDER_PASSWORD', '')
    os.environ['PARITY_KEY'] = os.getenv('PROVIDER_KEY', '')
    os.environ['PARITY_KEYFILE'] = os.getenv('PROVIDER_KEYFILE', '')
    os.environ['PARITY_ENCRYPTED_KEY'] = os.getenv('PROVIDER_ENCRYPTED_KEY', '')


def verify_signature(signer_address, signature, original_msg):
    if is_auth_token_valid(signature):
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
        key = web3().eth.account.decrypt(key, account.password)

    return eth_keys.KeyAPI.PrivateKey(key)


def is_auth_token_valid(token):
    return isinstance(token, str) and token.startswith('0x') and len(token.split('-')) == 2


def check_auth_token(token):
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
    address = Keeper.personal_ec_recover(message, sig)
    return Web3.toChecksumAddress(address)


def generate_auth_token(account):
    raw_msg = get_config().auth_token_message or "Ocean Protocol Authentication"
    _time = int(datetime.now().timestamp())
    _message = f'{raw_msg}\n{_time}'
    prefixed_msg_hash = add_ethereum_prefix_and_hash_msg(_message)
    return f'{Keeper.sign_hash(prefixed_msg_hash, account)}-{_time}'
