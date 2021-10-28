#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from typing import Union

import ecies
from eth_account.account import LocalAccount
from eth_typing.encoding import HexStr
from ocean_provider.utils.accounts import get_private_key
from web3 import Web3


def do_encrypt(
    document: Union[HexStr, bytes], wallet: LocalAccount = None, public_key: str = None
) -> HexStr:
    """
    :param document: document to be encrypted as HexStr or bytes
    :param wallet: LocalAccount instance
    :param public_key: Eth public address
    :return: Encrypted String
    """
    key = get_private_key(wallet).public_key.to_hex() if wallet else public_key
    if isinstance(document, str):
        document = Web3.toBytes(hexstr=document)
    encrypted_document = ecies.encrypt(key, document)
    return Web3.toHex(encrypted_document)


def do_decrypt(
    encrypted_document: Union[HexStr, bytes], provider_wallet: LocalAccount
) -> HexStr:
    """
    :param encrypted_document: Encrypted document as HexStr or bytes
    :param provider_wallet: LocalAccount instance
    :return: Decrypted string
    """
    key = get_private_key(provider_wallet).to_hex()
    if isinstance(encrypted_document, str):
        encrypted_document = Web3.toBytes(hexstr=encrypted_document)

    return ecies.decrypt(key, encrypted_document)
