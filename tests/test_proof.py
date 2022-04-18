#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import pytest
from requests.models import Response
from unittest.mock import patch, Mock

from ocean_provider.utils.proof import send_proof


@pytest.mark.unit
def test_no_proof_setup(client):
    assert send_proof(None, None, None, None, None, None, None) is None


@pytest.mark.unit
def test_http_proof(client, monkeypatch):
    monkeypatch.setenv("USE_HTTP_PROOF", "http://test.com")
    provider_data = json.dumps({"test_data": "test_value"})

    with patch("requests.post") as mock:
        response = Mock(spec=Response)
        response.json.return_value = {"a valid response": ""}
        response.status_code = 200
        mock.return_value = response

        assert send_proof(None, b'1', provider_data, None, None, None, None) is True

    mock.assert_called_once()

    with patch("requests.post") as mock:
        mock.side_effect = Exception("Boom!")

        assert send_proof(None, b'1', provider_data, None, None, None, None) is None

    mock.assert_called_once()
