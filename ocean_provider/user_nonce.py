
class UserNonce:
    FIRST_NONCE = 0

    def __init__(self, initial_state=None):
        self._initial_state = initial_state or dict()

    def get_nonce(self, address):
        return self._initial_state.get(address, UserNonce.FIRST_NONCE)

    def increment_nonce(self, address):
        nonce = self._initial_state.get(address, UserNonce.FIRST_NONCE)
        self._initial_state[address] = nonce + 1
