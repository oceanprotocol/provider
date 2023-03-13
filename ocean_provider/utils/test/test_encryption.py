#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import pytest
from web3.main import Web3

from ocean_provider.utils.encryption import do_decrypt, do_encrypt


@pytest.mark.unit
def test_encryption_with_bytes(provider_wallet):
    test_string = "hello_world"
    test_bytes = Web3.toBytes(text=test_string)
    result = do_encrypt(test_bytes, provider_wallet)
    assert result.startswith("0x")
    assert do_decrypt(result, provider_wallet) == test_bytes


@pytest.mark.unit
def test_encryption_with_hexstr(provider_wallet):
    test_string = '["https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"]'
    result = do_encrypt(Web3.toHex(text=test_string), provider_wallet)
    assert result.startswith("0x")
    assert do_decrypt(result, provider_wallet) == Web3.toBytes(text=test_string)


@pytest.mark.unit
def test_encryption_with_text(provider_wallet):
    test_string = (
        '["https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt", '
        '"https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"]'
    )
    result = do_encrypt(test_string, provider_wallet)
    assert result.startswith("0x")
    assert do_decrypt(result, provider_wallet) == Web3.toBytes(text=test_string)
