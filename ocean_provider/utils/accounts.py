#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

import eth_keys
from eth_account.account import Account
from eth_account.messages import encode_defunct
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.user_nonce import get_nonce
from ocean_provider.utils.basics import get_web3
from web3 import Web3

logger = logging.getLogger(__name__)


def verify_signature(signer_address, signature, original_msg, nonce):
    """
    :return: True if signature is valid
    """
    db_nonce = get_nonce(signer_address)
    if db_nonce and float(nonce) < float(db_nonce):
        msg = (
            f"Invalid signature expected nonce ({db_nonce}) > current nonce ({nonce})."
        )
        logger.error(msg)
        raise InvalidSignatureError(msg)

    message = f"{original_msg}{str(nonce)}"
    address = Account.recover_message(encode_defunct(text=message), signature=signature)

    if address.lower() == signer_address.lower():
        return True

    msg = (
        f"Invalid signature {signature} for "
        f"ethereum address {signer_address}, message {original_msg} "
        f"and nonce {nonce}. Expected: {signer_address.lower()} but got {address.lower()}"
    )
    logger.error(msg)
    raise InvalidSignatureError(msg)


def get_private_key(wallet):
    """Returns private key of the given wallet"""
    pk = wallet.key
    if not isinstance(pk, bytes):
        pk = Web3.toBytes(hexstr=pk)
    return eth_keys.KeyAPI.PrivateKey(pk)


def sign_message(message, wallet):
    """
    :param message: str
    :param wallet: Wallet instance
    :return: `hex` value of the signed message
    """
    w3 = get_web3()
    signed = w3.eth.account.sign_message(
        encode_defunct(text=message), private_key=wallet.key
    )

    return signed.signature.hex()
