#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging

from flask import jsonify, make_response
from ocean_provider.utils.url import is_url

logger = logging.getLogger(__name__)

STRIPPED_URL_MSG = "<URL stripped for security reasons>"


def error_response(err_str, status: int, custom_logger=None):
    """Logs error and returns an error response."""
    back_2_dict = isinstance(err_str, dict)
    err_str = str(err_str) if not back_2_dict else json.dumps(err_str)
    err_str = strip_and_replace_urls(str(err_str))

    this_logger = custom_logger if custom_logger else logger
    this_logger.error(err_str, exc_info=1)
    err_str = err_str if not back_2_dict else json.loads(err_str)
    response = make_response(jsonify(error=err_str), status)
    response.headers["Connection"] = "close"

    return response


def strip_and_replace_urls(err_str: str) -> str:
    """Strips sensitive data from urls to be logged/returned."""
    tokens = []
    for token in err_str.split():
        tokens += [STRIPPED_URL_MSG] if is_url(token) else [token]
    return " ".join(tokens)
