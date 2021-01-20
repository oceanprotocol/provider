import logging
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import uuid4

from ocean_utils.data_store.storage_base import StorageBase

logger = logging.getLogger(__name__)


class AccessToken:
    def __init__(self, storage_path=None):
        self._storage_path = storage_path
        self.storage = AccessTokenStorage(storage_path)

    def generate_access_token(
        self, did, consumer_address, tx_id, seconds_to_exp, delegate_address
    ):
        access_token = str(uuid4())
        access_token = sha256(access_token.encode('utf-8')).hexdigest()
        self.storage.write_access_token(
            did, consumer_address, tx_id, seconds_to_exp,
            delegate_address, access_token
        )

        return access_token

    def check_unique(self, did, consumer_address, tx_id, delegate_address):
        return self.storage.check_unique(
            did, consumer_address, tx_id, delegate_address
        )

    def use_access_token(self, address):
        # TODO
        pass


class AccessTokenStorage(StorageBase):
    TABLE_NAME = 'access_token'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._run_query(
            f'''CREATE TABLE IF NOT EXISTS {self.TABLE_NAME}
               (access_token VARCHAR PRIMARY KEY, consumer_address VARCHAR,
                did VARCHAR, tx_id VARCHAR, delegate_address,
                expiry_time DATETIME);'''
        )

    def write_access_token(
        self, did, consumer_address, tx_id, seconds_to_exp,
        delegate_address, token
    ):
        """
        Store access_token value for a specific address

        :param did: str, the document id for this access_token
        :param consumer_address: str
        :param tx_id: transfer Id
        :param seconds_to_exp: int, seconds to expiration, starting now
        :param delegate_address: string, address for access_token delegation
        :param token: access_token to be written
        """
        logger.debug(
            f'Writing access_token value to {self.TABLE_NAME} storage: '
            f'consumer={consumer_address}, token written={token}'
        )
        expiry_time = datetime.now() + timedelta(seconds=int(seconds_to_exp))

        self._run_query(
            f'''INSERT OR REPLACE
                INTO {self.TABLE_NAME}
                (
                    access_token, did, consumer_address,
                    tx_id, delegate_address, expiry_time
                )
                VALUES (?,?,?,?,?,?)''',
            [
                str(token), did, consumer_address, tx_id,
                delegate_address, expiry_time
            ],
        )

    def check_unique(self, did, consumer_address, tx_id, delegate_address):
        """
        Retrieve stored access_token value

        :param did: str, the document id for which we retrieve the access_token
        :param consumer_address: str
        """
        try:
            rows = [
                row for row in self._run_query(
                    f'''SELECT access_token
                        FROM {self.TABLE_NAME}
                        WHERE did=?
                        AND consumer_address=?
                        AND delegate_address=?
                        AND tx_id=?;''',
                    (did, consumer_address, delegate_address, tx_id)
                )
            ]

            if rows:
                return False

            return True

        except Exception as e:
            logging.error(
                f'Error reading access token for {consumer_address}: {e}'
            )
            return None
