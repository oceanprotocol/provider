#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from ocean_provider.util import service_unavailable
from ocean_provider.util_url import is_safe_schema, is_safe_url

test_logger = logging.getLogger(__name__)


def test_is_safe_schema():
    assert is_safe_schema("https://jsonplaceholder.typicode.com/") is True
    assert is_safe_schema("127.0.0.1") is False
    assert is_safe_schema("169.254.169.254") is False
    assert is_safe_schema("http://169.254.169.254/latest/meta-data/hostname") is True


def test_is_safe_url():
    assert is_safe_url("https://jsonplaceholder.typicode.com/") is True
    assert is_safe_url("127.0.0.1") is False
    assert is_safe_url("169.254.169.254") is False
    assert is_safe_url("http://169.254.169.254/latest/meta-data/hostname") is False


def test_service_unavailable(caplog):
    e = Exception("test message")
    context = {"item1": "test1", "item2": "test2"}
    response = service_unavailable(e, context, test_logger)
    assert response.status_code == 503
    response = response.json
    assert response["error"] == "test message"
    assert response["context"] == context
    assert caplog.records[0].msg == "Payload was: item1=test1,item2=test2"
