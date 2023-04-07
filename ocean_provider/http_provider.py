#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from typing import Any, Dict

import lru
import requests
from ocean_provider.version import get_version
from requests.adapters import HTTPAdapter
from requests.sessions import Session
from web3 import HTTPProvider
from web3._utils.caching import generate_cache_key


def _remove_session(key: str, session: Session) -> None:
    session.close()


_session_cache = lru.LRU(8, callback=_remove_session)


class CustomHTTPProvider(HTTPProvider):
    """Override requests to control the connection pool to make it blocking."""

    def make_request(self, method: str, params: Any) -> Dict[str, Any]:
        self.logger.debug(
            "Making request HTTP. URI: %s, Method: %s", self.endpoint_uri, method
        )
        request_data = self.encode_rpc_request(method, params)
        raw_response = make_post_request(
            self.endpoint_uri, request_data, **self.get_request_kwargs()
        )
        response = self.decode_rpc_response(raw_response)
        self.logger.debug(
            "Getting response HTTP. URI: %s, " "Method: %s, Response: %s",
            self.endpoint_uri,
            method,
            response,
        )
        return response


def make_post_request(endpoint_uri: str, data: bytes, *args, **kwargs) -> bytes:
    kwargs.setdefault("timeout", 10)

    version = get_version()
    version_header = {"User-Agent": f"OceanProvider/{version}"}

    if "headers" in kwargs:
        kwargs["headers"].update(version_header)
    else:
        kwargs["headers"] = version_header

    session = _get_session(endpoint_uri)
    response = session.post(endpoint_uri, data=data, *args, **kwargs)
    response.raise_for_status()

    return response.content


def _get_session(*args, **kwargs) -> Session:
    cache_key = generate_cache_key((args, kwargs))
    if cache_key not in _session_cache:
        # This is the main change from original Web3 `_get_session`
        session = requests.sessions.Session()
        session.mount(
            "http://",
            HTTPAdapter(pool_connections=25, pool_maxsize=25, pool_block=True),
        )
        session.mount(
            "https://",
            HTTPAdapter(pool_connections=25, pool_maxsize=25, pool_block=True),
        )
        _session_cache[cache_key] = session
    return _session_cache[cache_key]
