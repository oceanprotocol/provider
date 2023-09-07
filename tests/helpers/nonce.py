import time
from _decimal import Decimal

from ocean_provider.user_nonce import get_nonce, update_nonce


def build_nonce(address) -> Decimal:
    nonce = get_nonce(address)
    if nonce:
        nonce = Decimal(nonce) + 1
        update_nonce(address, nonce)

        return Decimal(nonce)

    update_nonce(address, 1)
    return Decimal(1)


def build_nonce_for_compute() -> int:
    return time.time_ns()
