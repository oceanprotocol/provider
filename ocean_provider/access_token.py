import logging

from uuid import uuid4
from datetime import datetime, timedelta

from ocean_utils.data_store.storage_base import StorageBase

logger = logging.getLogger(__name__)


class AccessToken:
    def __init__(self, storage_path=None):
        self._storage_path = storage_path
        self.storage = AccessTokenStorage(storage_path)

    def generate_access_token(self, did, consumer_address):
        access_token = uuid4()
        self.storage.write_access_token(
            did, consumer_address, access_token
        )

        return access_token

    def check_access_token(self, did, consumer_address):
        # TODO
        return True

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
                did VARCHAR, expiry_time DATETIME);'''
        )

    def write_access_token(self, did, consumer_address, token):
        """
        Store access_token value for a specific address

        :param did: str, the document id for this access_token
        :param consumer_address: str
        :param token: access_token to be written
        """
        logger.debug(
            f'Writing access_token value to {self.TABLE_NAME} storage: '
            f'consumer={consumer_address}, token written={token}'
        )
        expiry_time = datetime.now() + timedelta(minutes=15)

        self._run_query(
            f'''INSERT OR REPLACE
                INTO {self.TABLE_NAME}
                VALUES (?,?,?,?)''',
            [str(token), did, consumer_address, expiry_time],
        )

    def check_access_token(self, did, consumer_address):
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
                        AND expiry_time < ?;''',
                    (did, consumer_address, consumer_address, datetime.now())
                )
            ]
            (access_token, ) = rows[0] if rows else (None,)
            logger.debug(
                f'Read access_token from `{self.TABLE_NAME}` storage: '
                f'consumer={consumer_address}, result={access_token}'
            )

            return access_token

        except Exception as e:
            logging.error(
                f'Error reading access token for {consumer_address}: {e}'
            )
            return None
