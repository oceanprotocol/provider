#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import ecies
from ocean_lib.web3_internal.wallet import Wallet
from ocean_provider.utils.accounts import get_private_key
from web3 import Web3


def do_encrypt(document, wallet: Wallet = None, public_key=None):
    key = get_private_key(wallet).public_key.to_hex() if wallet else public_key
    encrypted_document = ecies.encrypt(key, document.encode(encoding="utf-8"))

    return Web3.toHex(encrypted_document)


def do_decrypt(encrypted_document, provider_wallet):
    key = get_private_key(provider_wallet)
    try:
        return ecies.decrypt(
            key.to_hex(), Web3.toBytes(hexstr=encrypted_document)
        ).decode(encoding="utf-8")
    except Exception:
        return None


def get_address_from_public_key(public_key):
    hash = Web3.sha3(hexstr=public_key)

    return Web3.toHex(hash[-20:])
