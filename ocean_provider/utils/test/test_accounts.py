import os
from datetime import datetime, timedelta, timezone

import pytest
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.user_nonce import update_nonce
from ocean_provider.utils.accounts import (
    get_private_key,
    sign_message,
    verify_signature,
)
from tests.helpers.nonce import build_nonce


@pytest.mark.unit
def test_get_private_key(publisher_wallet):
    assert (
        str(get_private_key(publisher_wallet)).lower()
        == os.getenv("TEST_PRIVATE_KEY1").lower()
    )


@pytest.mark.unit
def test_verify_signature(consumer_wallet, publisher_wallet):
    nonce = build_nonce(consumer_wallet.address)
    did = "did:op:test"
    msg = f"{consumer_wallet.address}{did}{nonce}"
    msg_w_nonce = f"{consumer_wallet.address}{did}"
    signature = sign_message(msg, consumer_wallet)

    assert verify_signature(consumer_wallet.address, signature, msg_w_nonce, nonce)

    nonce = build_nonce(consumer_wallet.address)
    did = "did:op:test"
    msg = f"{consumer_wallet.address}{did}{nonce}"
    msg_w_nonce = f"{consumer_wallet.address}{did}"
    signature = sign_message(msg, consumer_wallet)

    with pytest.raises(InvalidSignatureError) as e_info:
        verify_signature(publisher_wallet.address, signature, msg_w_nonce, nonce)

    assert f"Invalid signature {signature} for ethereum address" in e_info.value.args[0]

    nonce = 1
    did = "did:op:test"
    msg = f"{consumer_wallet.address}{did}{nonce}"
    msg_w_nonce = f"{consumer_wallet.address}{did}"
    signature = sign_message(msg, consumer_wallet)
    # expired nonce
    with pytest.raises(InvalidSignatureError) as e_info:
        verify_signature(consumer_wallet.address, signature, msg_w_nonce, nonce)

    assert e_info.value.args[0].startswith("Invalid signature expected nonce")
