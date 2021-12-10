#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from ocean_provider.utils.url import is_safe_url, is_this_same_provider, is_url

test_logger = logging.getLogger(__name__)


def test_is_url():
    assert is_url("https://jsonplaceholder.typicode.com/") is True
    assert is_url("127.0.0.1") is False
    assert is_url("169.254.169.254") is False
    assert is_url("http://169.254.169.254/latest/meta-data/hostname") is True


def test_is_safe_url():
    assert is_safe_url("https://jsonplaceholder.typicode.com/") is True
    assert is_safe_url("127.0.0.1") is False
    assert is_safe_url("169.254.169.254") is False
    assert is_safe_url("http://169.254.169.254/latest/meta-data/hostname") is False


def test_is_same_provider():
    assert is_this_same_provider("http://localhost:8030")
