#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from ocean_provider.util import service_unavailable

test_logger = logging.getLogger(__name__)


def test_service_unavailable(caplog):
    e = Exception("test message")
    context = {"item1": "test1", "item2": "test2"}
    response = service_unavailable(e, context, test_logger)
    assert response.status_code == 503
    response = response.json
    assert response["error"] == "test message"
    assert response["context"] == context
    assert caplog.records[0].msg == "Payload was: item1=test1,item2=test2"
