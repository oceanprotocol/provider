from datetime import datetime, timedelta
import os
import pytest

from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.utils.accounts import sign_message, verify_signature, get_private_key
from ocean_provider.user_nonce import update_nonce


@pytest.mark.unit
def test_get_private_key(publisher_wallet):
    assert (
        str(get_private_key(publisher_wallet)).lower()
        == os.getenv("TEST_PRIVATE_KEY1").lower()
    )


@pytest.mark.unit
def test_verify_signature(consumer_wallet, publisher_wallet):
    update_nonce(consumer_wallet.address, datetime.now().timestamp())

    nonce = datetime.now().timestamp()
    did = "did:op:test"
    msg = f"{consumer_wallet.address}{did}{nonce}"
    msg_w_nonce = f"{consumer_wallet.address}{did}"
    signature = sign_message(msg, consumer_wallet)

    assert verify_signature(consumer_wallet.address, signature, msg_w_nonce, nonce)

    nonce = datetime.now().timestamp()
    did = "did:op:test"
    msg = f"{consumer_wallet.address}{did}{nonce}"
    msg_w_nonce = f"{consumer_wallet.address}{did}"
    signature = sign_message(msg, consumer_wallet)

    with pytest.raises(InvalidSignatureError) as e_info:
        verify_signature(publisher_wallet.address, signature, msg_w_nonce, nonce)

    assert f"Invalid signature {signature} for ethereum address" in e_info.value.args[0]

    nonce = (datetime.now() - timedelta(days=7)).timestamp()
    did = "did:op:test"
    msg = f"{consumer_wallet.address}{did}{nonce}"
    msg_w_nonce = f"{consumer_wallet.address}{did}"
    signature = sign_message(msg, consumer_wallet)
    # expired nonce
    with pytest.raises(InvalidSignatureError) as e_info:
        verify_signature(consumer_wallet.address, signature, msg_w_nonce, nonce)

    assert e_info.value.args[0] == "Invalid signature expected nonce > current nonce."
