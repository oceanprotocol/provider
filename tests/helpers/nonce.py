from ocean_provider.user_nonce import get_nonce, update_nonce


def build_nonce(address) -> int:
    nonce = int(get_nonce(address))
    if nonce:
        nonce = nonce + 1
        update_nonce(address, nonce)

        return nonce

    return 1
