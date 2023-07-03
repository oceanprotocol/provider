#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

import pytest
from ocean_provider.utils.compute import (
    get_compute_endpoint,
    get_compute_result_endpoint,
)

test_logger = logging.getLogger(__name__)


@pytest.mark.unit
@pytest.mark.skip("C2D connection needs fixing.")
def test_get_compute_endpoint(monkeypatch):
    monkeypatch.setenv("OPERATOR_SERVICE_URL", "http://with-slash.com/")
    assert get_compute_endpoint() == "http://with-slash.com/api/v1/operator/compute"
    assert (
        get_compute_result_endpoint()
        == "http://with-slash.com/api/v1/operator/getResult"
    )

    monkeypatch.setenv("OPERATOR_SERVICE_URL", "http://without-slash.com")
    assert get_compute_endpoint() == "http://without-slash.com/api/v1/operator/compute"
    assert (
        get_compute_result_endpoint()
        == "http://without-slash.com/api/v1/operator/getResult"
    )
