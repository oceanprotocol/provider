#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime

import eth_keys
from eth_account.account import Account
from eth_account.messages import encode_defunct
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.utils.basics import get_config, get_web3
from web3 import Web3


def verify_signature(signer_address, signature, original_msg, nonce: int = None):
    """
    :return: True if signature is valid
    """
    if is_auth_token_valid(signature):
        address = check_auth_token(signature)
    else:
        assert nonce is not None, "nonce is required when not using user auth token."
        message = f"{original_msg}{str(nonce)}"
        address = Account.recover_message(message, signature=signature)

    if address.lower() == signer_address.lower():
        return True

    msg = (
        f"Invalid signature {signature} for "
        f"ethereum address {signer_address}, documentId {original_msg}"
        f"and nonce {nonce}."
    )
    raise InvalidSignatureError(msg)


def get_private_key(wallet):
    """Returns private key of the given wallet"""
    pk = wallet.private_key
    if not isinstance(pk, bytes):
        pk = Web3.toBytes(hexstr=pk)
    return eth_keys.KeyAPI.PrivateKey(pk)


def is_auth_token_valid(token):
    """
    :param token: str
    :return: `True` if token is valid else `False`
    """
    return (
        isinstance(token, str) and token.startswith("0x") and len(token.split("-")) == 2
    )


def check_auth_token(token):
    """
    :param token: str
    :return: String
    """
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
    address = Account.recover_message(message, signature=sig)
    return Web3.toChecksumAddress(address)


def generate_auth_token(wallet):
    """
    :param wallet: Wallet instance
    :return: `str`
    """
    raw_msg = get_config().auth_token_message or "Ocean Protocol Authentication"
    _time = int(datetime.now().timestamp())
    _message = f"{raw_msg}\n{_time}"
    signed = sign_message(_message, wallet)

    return f"{signed}-{_time}"


def sign_message(message, wallet):
    """
    :param message: str
    :param wallet: Wallet instance
    :return: `hex` value of the signed message
    """
    w3 = get_web3()
    signed = w3.eth.account.sign_message(
        encode_defunct(text=message), private_key=wallet.private_key
    )

    return signed.signature.hex()
