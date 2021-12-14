#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from ocean_provider.utils.error_responses import service_unavailable

test_logger = logging.getLogger(__name__)


def test_service_unavailable(caplog):
    e = Exception("test message")
    context = {"item1": "test1", "item2": "test2"}
    response = service_unavailable(e, context, test_logger)
    assert response.status_code == 503
    response = response.json
    assert response["error"] == "test message"
    assert response["context"] == context
    assert (
        caplog.records[0].msg == "error: test message, payload: item1=test1,item2=test2"
    )


def test_service_unavailable_strip_infura_project_id():
    """Test that service_unavilable strips out URLs."""

    context = {"item1": "test1", "item2": "test2"}

    # HTTP Infura URL (rinkeby)
    e = Exception(
        "429 Client Error: Too Many Requests for url: "
        "https://rinkeby.infura.io/v3/ffffffffffffffffffffffffffffffff"
    )
    response = service_unavailable(e, context, test_logger)
    assert (
        response.json["error"] == "429 Client Error: Too Many Requests for url: "
        "<URL stripped for security reasons>"
    )

    # Websocket Infura URL (ropsten)
    e = Exception(
        "429 Client Error: Too Many Requests for url: "
        "wss://ropsten.infura.io/ws/v3/ffffffffffffffffffffffffffffffff"
    )
    response = service_unavailable(e, context, test_logger)
    assert (
        response.json["error"] == "429 Client Error: Too Many Requests for url: "
        "<URL stripped for security reasons>"
    )

    # No URL
    e = Exception("string without a URL in it")
    response = service_unavailable(e, context, test_logger)
    assert response.json["error"] == "string without a URL in it"

    # Two URLs
    e = Exception("Two URLs: wss://google.com https://google.com")
    response = service_unavailable(e, context, test_logger)
    assert (
        response.json["error"] == "Two URLs: "
        "<URL stripped for security reasons> "
        "<URL stripped for security reasons>"
    )
