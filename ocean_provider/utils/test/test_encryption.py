from ocean_provider.utils.encryption import do_decrypt, do_encrypt


def test_encryption(provider_wallet):
    result = do_encrypt("test", provider_wallet)
    assert result.startswith("0x")
    assert do_decrypt(result, provider_wallet) == "test"
