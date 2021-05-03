#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime

import eth_keys
from ocean_lib.web3_internal.transactions import sign_hash
from ocean_lib.web3_internal.utils import (
    add_ethereum_prefix_and_hash_msg,
    personal_ec_recover,
)
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.utils.basics import get_config
from web3 import Web3


def verify_signature(signer_address, signature, original_msg, nonce: int = None):
    if is_auth_token_valid(signature):
        address = check_auth_token(signature)
    else:
        assert nonce is not None, "nonce is required when not using user auth token."
        message = f"{original_msg}{str(nonce)}"
        address = personal_ec_recover(message, signature)

    if address.lower() == signer_address.lower():
        return True

    msg = (
        f"Invalid signature {signature} for "
        f"ethereum address {signer_address}, documentId {original_msg}"
        f"and nonce {nonce}."
    )
    raise InvalidSignatureError(msg)


def get_private_key(wallet):
    pk = wallet.private_key
    if not isinstance(pk, bytes):
        pk = Web3.toBytes(hexstr=pk)
    return eth_keys.KeyAPI.PrivateKey(pk)


def is_auth_token_valid(token):
    return (
        isinstance(token, str) and token.startswith("0x") and len(token.split("-")) == 2
    )


def check_auth_token(token):
    parts = token.split("-")
    if len(parts) < 2:
        return "0x0"
    # :HACK: alert, this should be part of ocean-lib-py
    sig, timestamp = parts
    auth_token_message = (
        get_config().auth_token_message or "Ocean Protocol Authentication"
    )
    default_exp = 24 * 60 * 60
    expiration = int(get_config().auth_token_expiration or default_exp)
    if int(datetime.now().timestamp()) > (int(timestamp) + expiration):
        return "0x0"

    message = f"{auth_token_message}\n{timestamp}"
    address = personal_ec_recover(message, sig)
    return Web3.toChecksumAddress(address)


def generate_auth_token(wallet):
    raw_msg = get_config().auth_token_message or "Ocean Protocol Authentication"
    _time = int(datetime.now().timestamp())
    _message = f"{raw_msg}\n{_time}"
    prefixed_msg_hash = add_ethereum_prefix_and_hash_msg(_message)
    return f"{sign_hash(prefixed_msg_hash, wallet)}-{_time}"
