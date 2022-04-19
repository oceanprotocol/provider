from decimal import ROUND_DOWN, Context, Decimal, localcontext
from typing import Union

from eth_utils.currency import units

"""The maximum uint256 value."""
MAX_UINT256 = 2**256 - 1

"""decimal.Context tuned to accomadate MAX_WEI.
* precision=78 because there are 78 digits in MAX_WEI (MAX_UINT256).
  Any lower and decimal operations like quantize throw an InvalidOperation error.
* rounding=ROUND_DOWN (towards 0, aka. truncate) to avoid issue where user
  removes 100% from a pool and transaction fails because it rounds up.
"""
ETHEREUM_DECIMAL_CONTEXT = Context(prec=78, rounding=ROUND_DOWN)


"""ERC20 tokens usually opt for a decimals value of 18, imitating the
relationship between Ether and Wei."""
DECIMALS_18 = 18

"""The minimum possible token amount on Ethereum-compatible blockchains, denoted in wei"""
MIN_WEI = 1

"""The maximum possible token amount on Ethereum-compatible blockchains, denoted in wei"""
MAX_WEI = MAX_UINT256

"""The minimum possible token amount on Ethereum-compatible blockchains, denoted in ether"""
MIN_ETHER = Decimal("0.000000000000000001")

"""The maximum possible token amount on Ethereum-compatible blockchains, denoted in ether"""
MAX_ETHER = Decimal(MAX_WEI).scaleb(-18, context=ETHEREUM_DECIMAL_CONTEXT)


def to_wei(amount_in_ether: Union[Decimal, str, int]) -> int:
    return parse_units(amount_in_ether, DECIMALS_18)


def parse_units(
    amount: Union[Decimal, str, int], unit_name: Union[str, int] = DECIMALS_18
) -> int:
    """
    Convert token amount from a formatted unit to an EVM-compatible integer.
    float input is purposfully not supported
    """
    num_decimals = (
        int(units[unit_name].log10()) if isinstance(unit_name, str) else unit_name
    )

    decimal_amount = normalize_and_validate_unit(amount, num_decimals)

    if decimal_amount == Decimal(0):
        return 0

    unit_value = Decimal(10) ** num_decimals

    with localcontext(ETHEREUM_DECIMAL_CONTEXT):
        return int(decimal_amount * unit_value)


def normalize_and_validate_unit(
    amount: Union[Decimal, str, int], decimals: int = DECIMALS_18
) -> Decimal:
    """Returns an amount in ether, encoded as a Decimal
    Takes Decimal, str, or int as input. Purposefully does not support float."""
    if isinstance(amount, str) or isinstance(amount, int):
        amount = Decimal(amount)

    if abs(amount) > Decimal(MAX_WEI).scaleb(
        -decimals, context=ETHEREUM_DECIMAL_CONTEXT
    ):
        raise ValueError("Token amount exceeds maximum.")

    return amount
