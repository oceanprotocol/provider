#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from eth_account.account import Account
from eth_account.messages import encode_defunct
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.user_nonce import get_nonce
from web3 import Web3

logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)


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
    signature_bytes = Web3.toBytes(hexstr=signature)
    if signature_bytes[64] == 27:
        new_signature = b"".join([signature_bytes[0:64], b"\x00"])
    elif signature_bytes[64] == 28:
        new_signature = b"".join([signature_bytes[0:64], b"\x01"])
    else:
        new_signature = signature_bytes

    signature = keys.Signature(signature_bytes=new_signature)
    message_hash = Web3.solidityKeccak(
        ["bytes"],
        [Web3.toBytes(text=message)],
    )
    prefix = "\x19Ethereum Signed Message:\n32"
    signable_hash = Web3.solidityKeccak(
        ["bytes", "bytes"], [Web3.toBytes(text=prefix), Web3.toBytes(message_hash)]
    )
    vkey = keys.ecdsa_recover(signable_hash, signature)

    if Web3.toChecksumAddress(signer_address) != Web3.toChecksumAddress(
        vkey.to_address()
    ):
        msg = (
            f"Invalid signature {signature} for "
            f"ethereum address {signer_address}, message {original_msg} "
            f"and nonce {nonce}. Got {vkey.to_address()}"
        )
        logger.error(msg)
        raise InvalidSignatureError(msg)

    return True


def get_private_key(wallet):
    """Returns private key of the given wallet"""
    pk = wallet.key
    if not isinstance(pk, bytes):
        pk = Web3.toBytes(hexstr=pk)
    return keys.PrivateKey(pk)


def sign_message(message, wallet):
    """
    :param message: str
    :param wallet: Wallet instance
    :return: signature
    """
    keys_pk = keys.PrivateKey(wallet.key)
    message_hash = Web3.solidityKeccak(
        ["bytes"],
        [Web3.toBytes(text=message)],
    )
    prefix = "\x19Ethereum Signed Message:\n32"
    signable_hash = Web3.solidityKeccak(
        ["bytes", "bytes"], [Web3.toBytes(text=prefix), Web3.toBytes(message_hash)]
    )
    signed = keys.ecdsa_sign(message_hash=signable_hash, private_key=keys_pk)

    v = str(Web3.toHex(Web3.toBytes(signed.v)))
    r = str(Web3.toHex(Web3.toBytes(signed.r).rjust(32, b"\0")))
    s = str(Web3.toHex(Web3.toBytes(signed.s).rjust(32, b"\0")))

    signature = "0x" + r[2:] + s[2:] + v[2:]

    return signature
