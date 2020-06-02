import ecies

from ocean_provider.utils.accounts import get_private_key


def do_encrypt(document, provider_acc):
    key = get_private_key(provider_acc)
    encrypted_document = ecies.encrypt(key.public_key, document.encode(encoding='utf-8'))
    return encrypted_document


def do_decrypt(encrypted_document, provider_acc):
    key = get_private_key(provider_acc)
    return ecies.decrypt(key.to_hex(), encrypted_document).decode(encoding='utf-8')
