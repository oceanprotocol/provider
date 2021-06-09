#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json

import pytest

from ocean_provider.constants import BaseURLs
from ocean_provider.exceptions import RequestNotFound
from ocean_provider.validation.requests import RBACValidator


def test_null_validator():
    with pytest.raises(RequestNotFound):
        RBACValidator()


encrypt_endpoint = BaseURLs.ASSETS_URL + "/encrypt"


def test_encrypt_request_payload():
    document = [
        {
            "url": "http://localhost:8030" + encrypt_endpoint,
            "index": 0,
            "checksum": "foo_checksum",
            "contentLength": "4535431",
            "contentType": "text/csv",
            "encoding": "UTF-8",
            "compression": "zip",
        }
    ]
    req = {"document": json.dumps(document[0])}
    validator = RBACValidator(request_name="EncryptRequest", request=req)
    payload = validator.build_payload()
    assert validator.__dict__["request"] == req
    assert payload
    assert payload["eventType"] == validator.__dict__["action"]
    assert payload["component"] == validator.__dict__["component"]
    assert payload["credentials"] == validator.__dict__["credentials"]
