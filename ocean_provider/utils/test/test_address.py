#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import pytest

from ocean_provider.utils.address import get_address_json, get_contract_address
from ocean_provider.utils.basics import get_config


@pytest.mark.unit
def test_get_address_json():
    address_json = get_address_json(get_config().address_file)
    assert address_json["development"]["chainId"] == 8996
    assert address_json["development"]["Ocean"].startswith("0x")


@pytest.mark.unit
def test_get_contract_address():
    assert get_contract_address(
        get_config().address_file, "ERC721Factory", 8996
    ).startswith("0x")
