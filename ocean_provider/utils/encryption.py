import ecies
from web3 import Web3

from ocean_provider.utils.accounts import get_private_key


def do_encrypt(document, provider_wallet):
    key = get_private_key(provider_wallet)
    encrypted_document = ecies.encrypt(key.public_key.to_hex(), document.encode(encoding='utf-8'))
    return Web3.toHex(encrypted_document)


def do_decrypt(encrypted_document, provider_wallet):
    key = get_private_key(provider_wallet)
    return ecies.decrypt(key.to_hex(), Web3.toBytes(hexstr=encrypted_document)).decode(encoding='utf-8')
