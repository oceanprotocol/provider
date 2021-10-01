from decimal import ROUND_DOWN, Context, Decimal
from web3.main import Web3


DECIMALS_18 = 18
ETHEREUM_DECIMAL_CONTEXT = Context(prec=78, rounding=ROUND_DOWN)
MAX_UINT256 = 2 ** 256 - 1
MAX_WEI = MAX_UINT256
MAX_ETHER = Decimal(MAX_WEI).scaleb(-18, context=ETHEREUM_DECIMAL_CONTEXT)


def to_wei(amount_in_ether, decimals: int = DECIMALS_18) -> int:
    amount_in_ether = normalize_and_validate_ether(amount_in_ether)
    decimal_places = Decimal(10) ** -abs(decimals)
    return Web3.toWei(
        amount_in_ether.quantize(decimal_places, context=ETHEREUM_DECIMAL_CONTEXT),
        "ether",
    )


def normalize_and_validate_ether(amount_in_ether) -> Decimal:
    if isinstance(amount_in_ether, str) or isinstance(amount_in_ether, int):
        amount_in_ether = Decimal(amount_in_ether)

    if abs(amount_in_ether) > MAX_ETHER:
        raise ValueError("Token abs(amount_in_ether) exceeds MAX_ETHER.")

    return amount_in_ether
