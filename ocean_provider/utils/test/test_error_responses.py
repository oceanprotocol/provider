#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

import pytest
from ocean_provider.run import handle_error
from ocean_provider.run import app

test_logger = logging.getLogger(__name__)


@pytest.mark.unit
def test_service_unavailable(caplog):
    context = {"item1": "test1", "item2": "test2"}

    with app.test_request_context(json=context):
        e = Exception("test message")
        response = handle_error(e)
        assert response.status_code == 503
        response = response.json
        assert response["error"] == "test message"
        assert response["context"] == context


@pytest.mark.unit
def test_service_unavailable_strip_infura_project_id():
    """Test that service_unavilable strips out URLs."""

    context = {"item1": "test1", "item2": "test2"}

    # HTTP Infura URL (rinkeby)
    with app.test_request_context(json=context):
        e = Exception(
            "429 Client Error: Too Many Requests for url: "
            "https://rinkeby.infura.io/v3/ffffffffffffffffffffffffffffffff"
        )
        response = handle_error(e)
        assert (
            response.json["error"] == "429 Client Error: Too Many Requests for url: "
            "<URL stripped for security reasons>"
        )

    # Websocket Infura URL (ropsten)
    with app.test_request_context(json=context):
        e = Exception(
            "429 Client Error: Too Many Requests for url: "
            "wss://ropsten.infura.io/ws/v3/ffffffffffffffffffffffffffffffff"
        )
        response = handle_error(e)
        assert (
            response.json["error"] == "429 Client Error: Too Many Requests for url: "
            "<URL stripped for security reasons>"
        )

    # No URL
    with app.test_request_context(json=context):
        e = Exception("string without a URL in it")
        response = handle_error(e)
        assert response.json["error"] == "string without a URL in it"

    # Two URLs
    with app.test_request_context(json=context):
        e = Exception("Two URLs: wss://google.com https://google.com")
        response = handle_error(e)
        assert (
            response.json["error"] == "Two URLs: "
            "<URL stripped for security reasons> "
            "<URL stripped for security reasons>"
        )
