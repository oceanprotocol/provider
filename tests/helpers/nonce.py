from ocean_provider.user_nonce import get_nonce, update_nonce


def build_nonce(address) -> int:
    nonce = get_nonce(address)
    if nonce:
        nonce = int(float(nonce)) + 1
        update_nonce(address, nonce)

        return int(nonce)

    update_nonce(address, 1)
    return 1
