import logging

from ocean_utils.data_store.storage_base import StorageBase

logger = logging.getLogger(__name__)


class UserNonce:
    FIRST_NONCE = 0

    def __init__(self, storage_path=None):
        self._storage_path = storage_path
        self.storage = NonceStorage(storage_path)

    def get_nonce(self, address):
        nonce = self.storage.read_nonce(address)
        if nonce is not None:
            return int(nonce)
        return UserNonce.FIRST_NONCE

    def increment_nonce(self, address):
        nonce = self.get_nonce(address)
        logger.debug(f'increment_nonce: {address}, {nonce}, new nonce {nonce+1}')
        self.storage.write_nonce(address, nonce + 1)


class NonceStorage(StorageBase):
    TABLE_NAME = 'user_nonce'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._run_query(
            f'''CREATE TABLE IF NOT EXISTS {self.TABLE_NAME}
               (address VARCHAR PRIMARY KEY , nonce VARCHAR);'''
        ) 

    def write_nonce(self, address, nonce):
        """
        Store nonce value for a specific address

        :param address: hex str the ethereum address that signed the token
        :param nonce: str
        """
        logger.debug(f'Writing nonce value to {self.TABLE_NAME} storage: '
                     f'account={address}, nonce={nonce}')
        self._run_query(
            f'''INSERT OR REPLACE
                INTO {self.TABLE_NAME}
                VALUES (?,?)''',
            [address, str(nonce)],
        )

    def read_nonce(self, address):
        """
        Retrieve stored nonce value

        :param address: hex str the ethereum address
        :return: str nonce value
        """
        try:
            rows = [row for row in self._run_query(
                f'''SELECT nonce
                    FROM {self.TABLE_NAME}
                    WHERE address=?;''',
                (address,))
                    ]
            (nonce, ) = rows[0] if rows else (None,)
            logger.debug(f'Read nonce from `{self.TABLE_NAME}` storage: '
                         f'account={address}, nonce={nonce}')
            return nonce

        except Exception as e:
            logging.error(f'Error reading nonce value for account {address}: {e}')
            return None
