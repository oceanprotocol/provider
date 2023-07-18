from unittest.mock import patch

import pytest
from freezegun import freeze_time
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.provider_fees import get_provider_fee_amount
from tests.helpers.compute_helpers import get_future_valid_until
from tests.test_helpers import (
    BLACK_HOLE_ADDRESS,
    deploy_data_nft,
    deploy_datatoken,
    get_ocean_token_address,
)


@pytest.mark.unit
@pytest.mark.skip("C2D connection needs fixing.")
@freeze_time("Feb 11th, 2012 00:00")
def test_get_provider_fee_amount(web3, publisher_wallet):
    valid_until = get_future_valid_until()
    assert (
        get_provider_fee_amount(
            valid_until,
            "ocean-compute",
            web3,
            "0x0000000000000000000000000000000000000000",
        )
        == 0
    )

    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        BLACK_HOLE_ADDRESS,
        BLACK_HOLE_ADDRESS,
        "",
        publisher_wallet,
    )

    datatoken_address = deploy_datatoken(
        web3=web3,
        data_nft_address=data_nft_address,
        template_index=1,
        name="Datatoken 1",
        symbol="DT1",
        minter=publisher_wallet.address,
        fee_manager=publisher_wallet.address,
        publishing_market=BLACK_HOLE_ADDRESS,
        publishing_market_fee_token=get_ocean_token_address(web3),
        cap=to_wei(1000),
        publishing_market_fee_amount=0,
        from_wallet=publisher_wallet,
    )

    with patch("ocean_provider.utils.provider_fees.get_c2d_environments") as mock:
        mock.return_value = [{"id": "ocean-compute", "priceMin": 60}]
        assert (
            get_provider_fee_amount(
                valid_until, "ocean-compute", web3, datatoken_address
            )
            == 3600000000000000000000
        )
