from decimal import ROUND_DOWN, Context, Decimal
from typing import Union

from web3.main import Web3

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


def to_wei(
    amount_in_ether: Union[Decimal, str, int], decimals: int = DECIMALS_18
) -> int:
    """
    Convert token amount to wei from ether, quantized to the specified number of decimal places
    float input is purposfully not supported
    """
    amount_in_ether = normalize_and_validate_ether(amount_in_ether)
    decimal_places = Decimal(10) ** -abs(decimals)
    return Web3.toWei(
        amount_in_ether.quantize(decimal_places, context=ETHEREUM_DECIMAL_CONTEXT),
        "ether",
    )


def normalize_and_validate_ether(amount_in_ether: Union[Decimal, str, int]) -> Decimal:
    """Returns an amount in ether, encoded as a Decimal
    Takes Decimal, str, or int as input. Purposefully does not support float."""
    if isinstance(amount_in_ether, str) or isinstance(amount_in_ether, int):
        amount_in_ether = Decimal(amount_in_ether)

    if abs(amount_in_ether) > MAX_ETHER:
        raise ValueError("Token abs(amount_in_ether) exceeds MAX_ETHER.")

    return amount_in_ether
