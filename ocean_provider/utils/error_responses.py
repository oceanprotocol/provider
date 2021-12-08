#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
import re

from flask.wrappers import Response

logger = logging.getLogger(__name__)

INFURA_ENDPOINT_HTTPS = ".infura.io/v3/"
INFURA_ENDPOINT_WSS = ".infura.io/ws/v3/"
STRIPPED_INFURA_PROJECT_ID_MSG = "<infura project id stripped for security reasons>"


def service_unavailable(error, context, custom_logger=None):
    error = strip_infura_project_id(str(error))

    text_items = []
    for key, value in context.items():
        value = value if isinstance(value, str) else json.dumps(value)
        text_items.append(key + "=" + value)

    logger_message = ",".join(text_items)
    custom_logger = custom_logger if custom_logger else logger
    custom_logger.error(f"error: {error}, payload: {logger_message}", exc_info=1)

    return Response(
        json.dumps({"error": str(error), "context": context}),
        503,
        headers={"content-type": "application/json"},
    )


def strip_infura_project_id(error: str) -> str:
    if INFURA_ENDPOINT_HTTPS in error:
        error = re.sub(
            rf"{INFURA_ENDPOINT_HTTPS}\S+",
            f"{INFURA_ENDPOINT_HTTPS}{STRIPPED_INFURA_PROJECT_ID_MSG}",
            error,
        )
    if INFURA_ENDPOINT_WSS in error:
        error = re.sub(
            rf"{INFURA_ENDPOINT_WSS}\S+",
            f"{INFURA_ENDPOINT_WSS}{STRIPPED_INFURA_PROJECT_ID_MSG}",
            error,
        )
    return error
