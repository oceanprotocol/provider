#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from typing import Union

import ecies
from eth_account.account import Account
from eth_typing.encoding import HexStr
from ocean_provider.utils.accounts import get_private_key
from web3 import Web3


def do_encrypt(
    document: Union[str, bytes], wallet: Account = None, public_key: str = None
) -> HexStr:
    """
    :param document: Json document/string to be encrypted
    :param wallet: Wallet instance
    :param public_key: Eth public address
    :return: Encrypted String
    """
    key = get_private_key(wallet).public_key.to_hex() if wallet else public_key
    if isinstance(document, str):
        document = document.encode("utf-8")
    encrypted_document = ecies.encrypt(key, document)
    return Web3.toHex(encrypted_document)


def do_decrypt(encrypted_document: HexStr, provider_wallet: Account):
    """
    :param encrypted_document: Encrypted data
    :param provider_wallet: Wallet instance
    :return: Decrypted string if successful else `None`
    """
    key = get_private_key(provider_wallet)
    return ecies.decrypt(key.to_hex(), Web3.toBytes(hexstr=encrypted_document)).decode(
        encoding="utf-8"
    )
