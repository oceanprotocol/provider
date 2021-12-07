import os

from ocean_provider.utils.accounts import get_private_key


def test_get_private_key(publisher_wallet):
    assert (
        str(get_private_key(publisher_wallet)).lower()
        == os.getenv("TEST_PRIVATE_KEY1").lower()
    )
