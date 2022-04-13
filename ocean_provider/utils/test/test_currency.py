#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from decimal import Decimal, localcontext

import pytest
from ocean_provider.utils.currency import (
    ETHEREUM_DECIMAL_CONTEXT,
    MAX_ETHER,
    MAX_WEI,
    MIN_ETHER,
    MIN_WEI,
    parse_units,
    to_wei,
)

USDT_DECIMALS = 6
MIN_USDT = Decimal("0.000001")
MAX_USDT = Decimal(MAX_WEI).scaleb(-USDT_DECIMALS, context=ETHEREUM_DECIMAL_CONTEXT)

SEVEN_DECIMALS = 7
MIN_SEVEN = Decimal("0.0000001")
MAX_SEVEN = Decimal(MAX_WEI).scaleb(-SEVEN_DECIMALS, context=ETHEREUM_DECIMAL_CONTEXT)


@pytest.mark.unit
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


@pytest.mark.unit
def test_parse_units():
    """Test the parse_units function"""
    assert parse_units("0", USDT_DECIMALS) == 0
    assert parse_units("0.123456789123456789", USDT_DECIMALS) == 123456
    assert parse_units("1.123456789123456789", USDT_DECIMALS) == 1_123456
    assert parse_units("5278.02", USDT_DECIMALS) == 5278_020000
    assert parse_units(MIN_USDT, USDT_DECIMALS) == MIN_WEI
    assert parse_units(MAX_USDT, USDT_DECIMALS) == MAX_WEI

    with pytest.raises(ValueError):
        # Use ETHEREUM_DECIMAL_CONTEXT when performing arithmetic on MAX_USDT
        with localcontext(ETHEREUM_DECIMAL_CONTEXT):
            parse_units(MAX_USDT + 1, USDT_DECIMALS)

    assert parse_units("0", "mwei") == 0
    assert parse_units("0.123456789123456789", "mwei") == 123456
    assert parse_units("1.123456789123456789", "mwei") == 1_123456
    assert parse_units("5278.02", "mwei") == 5278_020000
    assert parse_units(MIN_USDT, "mwei") == MIN_WEI
    assert parse_units(MAX_USDT, "mwei") == MAX_WEI

    with pytest.raises(ValueError):
        # Use ETHEREUM_DECIMAL_CONTEXT when performing arithmetic on MAX_USDT
        with localcontext(ETHEREUM_DECIMAL_CONTEXT):
            parse_units(MAX_USDT + 1, "mwei")

    assert parse_units("0", SEVEN_DECIMALS) == 0
    assert parse_units("0.123456789", SEVEN_DECIMALS) == 1234567
    assert parse_units("1.123456789", SEVEN_DECIMALS) == 1_1234567
    assert parse_units("5278.02", SEVEN_DECIMALS) == 5278_0200000
    assert parse_units(MIN_SEVEN, SEVEN_DECIMALS) == MIN_WEI
    assert parse_units(MAX_SEVEN, SEVEN_DECIMALS) == MAX_WEI
