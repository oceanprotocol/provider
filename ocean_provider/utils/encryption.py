#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import ecies
from web3 import Web3

from ocean_provider.utils.accounts import get_private_key


def do_encrypt(document, wallet=None, public_key=None):
    """
    :param document: Json document/string to be encrypted
    :param wallet: Wallet instance
    :param public_key: Eth public address
    :return: Encrypted String
    """
    key = get_private_key(wallet).public_key.to_hex() if wallet else public_key
    encrypted_document = ecies.encrypt(key, document.encode(encoding="utf-8"))

    return Web3.toHex(encrypted_document)


def do_decrypt(encrypted_document, provider_wallet):
    """
    :param encrypted_document: Encrypted data
    :param provider_wallet: Wallet instance
    :return: Decrypted string if successful else `None`
    """
    key = get_private_key(provider_wallet)
    try:
        return ecies.decrypt(
            key.to_hex(), Web3.toBytes(hexstr=encrypted_document)
        ).decode(encoding="utf-8")
    except Exception:
        return None
