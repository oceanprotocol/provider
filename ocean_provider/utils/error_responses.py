#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import json
import logging

from flask.wrappers import Response

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "text/plain", "Connection": "close"}


def error_response(err_str: str, status: int) -> Response:
    logger.error(err_str)
    return Response(err_str, status, standard_headers)


def service_unavailable(error, context, custom_logger=None):
    text_items = []
    for key, value in context.items():
        value = value if isinstance(value, str) else json.dumps(value)
        text_items.append(key + "=" + value)

    logger_message = "Payload was: " + ",".join(text_items)
    custom_logger = custom_logger if custom_logger else logger
    custom_logger.error(logger_message, exc_info=1)

    return Response(
        json.dumps({"error": str(error), "context": context}),
        503,
        headers={"content-type": "application/json"},
    )
