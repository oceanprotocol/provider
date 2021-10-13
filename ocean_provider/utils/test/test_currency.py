#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from decimal import Decimal, localcontext

import pytest
from currency import (
    ETHEREUM_DECIMAL_CONTEXT,
    MAX_ETHER,
    MAX_WEI,
    MIN_ETHER,
    MIN_WEI,
    to_wei,
)


def test_to_wei():
    """Test the to_wei function"""
    assert to_wei(Decimal("0")) == 0, "Zero ether (Decimal) should equal zero wei"
    assert to_wei("0") == 0, "Zero ether (string) should equal zero wei"
    assert to_wei(0) == 0, "Zero ether (int) should equal zero wei"
    assert (
        to_wei(Decimal("0.123456789123456789")) == 123456789_123456789
    ), "Conversion from ether (Decimal) to wei failed."
    assert (
        to_wei("0.123456789123456789") == 123456789_123456789
    ), "Conversion from ether (string) to wei failed."
    assert (
        to_wei(1) == 1_000000000_000000000
    ), "Conversion from ether (int) to wei failed."

    assert (
        to_wei("0.1234567891234567893") == 123456789_123456789
    ), "Conversion from ether to wei failed, supposed to round towards 0 (aka. truncate)."
    assert (
        to_wei("0.1234567891234567897") == 123456789_123456789
    ), "Conversion from ether to wei failed, supposed to round towards 0 (aka. truncate)."

    assert (
        to_wei(MIN_ETHER) == MIN_WEI
    ), "Conversion from minimum ether to minimum wei failed."

    assert (
        to_wei(MAX_ETHER) == MAX_WEI
    ), "Conversion from maximum ether to maximum wei failed."

    with pytest.raises(ValueError):
        # Use ETHEREUM_DECIMAL_CONTEXT when performing arithmetic on MAX_ETHER
        with localcontext(ETHEREUM_DECIMAL_CONTEXT):
            to_wei(MAX_ETHER + 1)

    USDT_DECIMALS = 6
    assert (
        to_wei("0", USDT_DECIMALS) == 0
    ), "Zero ether of USDT should equal zero wei of USDT"
    assert (
        to_wei("0.123456789123456789", USDT_DECIMALS) == 123456000_000000000
    ), "Conversion from ether to wei using decimals failed"
    assert (
        to_wei("1.123456789123456789", USDT_DECIMALS) == 1_123456000_000000000
    ), "Conversion from ether to wei using decimals failed"
