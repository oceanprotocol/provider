import os

from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.utils.accounts import (
    check_auth_token,
    generate_auth_token,
    get_private_key,
    is_auth_token_valid,
    verify_signature,
)


def test_get_private_key(publisher_wallet):
    assert (
        str(get_private_key(publisher_wallet)).lower()
        == os.getenv("TEST_PRIVATE_KEY1").lower()
    )


def test_is_auth_token_valid_failures():
    assert not is_auth_token_valid(5)  # not a string
    assert not is_auth_token_valid("doesnt start with 0x")
    assert not is_auth_token_valid("doesnt split with dash-")


def test_auth_token():
    token = (
        "0x1d2741dee30e64989ef0203957c01b14f250f5d2f6ccb0"
        "c88c9518816e4fcec16f84e545094eb3f377b7e214ded226"
        "76fbde8ca2e41b4eb1b3565047ecd9acf300-1568372035"
    )
    pub_address = "0xe2DD09d719Da89e5a3D0F2549c7E24566e947260"
    doc_id = "663516d306904651bbcf9fe45a00477c215c7303d8a24c5bad6005dd2f95e68e"
    assert is_auth_token_valid(token), f"cannot recognize auth-token {token}"
    address = check_auth_token(token)

    match_address = (
        f"address mismatch, got {address}, " f"" f"" f"expected {pub_address}"
    )
    assert address and address.lower() == pub_address.lower(), match_address

    try:
        verify_signature(pub_address, token, doc_id)
    except InvalidSignatureError as e:
        assert (
            False
        ), f"invalid signature/auth-token {token}, {pub_address}, {doc_id}: {e}"


def test_generate_auth_token(consumer_wallet):
    assert generate_auth_token(consumer_wallet)
