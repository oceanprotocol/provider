#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import os

import pytest
from ocean_provider.utils.address import get_address_json, get_contract_address


@pytest.mark.unit
def test_get_address_json():
    address_json = get_address_json(os.getenv("ADDRESS_FILE"))
    assert address_json["development"]["chainId"] == 8996
    assert address_json["development"]["Ocean"].startswith("0x")


@pytest.mark.unit
def test_get_contract_address():
    assert get_contract_address(
        os.getenv("ADDRESS_FILE"), "ERC721Factory", 8996
    ).startswith("0x")


@pytest.mark.unit
def test_get_address_json_missing_var(monkeypatch):
    monkeypatch.delenv("ADDRESS_FILE")
    address_json = get_address_json(os.getenv("ADDRESS_FILE"))
    assert address_json["rinkeby"]["chainId"] == 4
    assert address_json["rinkeby"]["Ocean"].startswith("0x")
