#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from requests.adapters import HTTPAdapter, Retry
from requests.sessions import Session


def get_requests_session() -> Session:
    """
    Set connection pool maxsize and block value to avoid `connection pool full` warnings.

    :return: requests session
    """
    session = Session()
    retries = Retry(total=8, backoff_factor=1.5, status_forcelist=[502, 503, 504])
    session.mount(
        "http://",
        HTTPAdapter(
            pool_connections=25, pool_maxsize=25, pool_block=True, max_retries=retries
        ),
    )
    session.mount(
        "https://",
        HTTPAdapter(
            pool_connections=25, pool_maxsize=25, pool_block=True, max_retries=retries
        ),
    )
    return session
