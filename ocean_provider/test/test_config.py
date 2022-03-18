#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import os
import pathlib
import pytest

from ocean_provider.config import NAME_STORAGE_PATH, Config, environ_names


@pytest.mark.unit
def test_config():
    test_config = os.path.join(
        pathlib.Path(__file__).parent.parent.parent, "tests/resources/test-config.txt"
    )
    _config = Config(filename=test_config)

    assert _config.storage_path == "ocean-provider.db"

    for i, envname in enumerate(environ_names.keys()):
        os.environ[envname] = f"some-value-{i}"

    os.environ[environ_names[NAME_STORAGE_PATH][0]] = "new-storage.db"
    _config = Config(test_config)
    assert _config.storage_path == "new-storage.db"
    assert _config.address_file
    assert _config.provider_address == "0x00bd138abd70e2f00903268f3db08f2d25677c9e"
    assert _config.authorized_decrypters == []
    assert _config.block_confirmations == 0


@pytest.mark.unit
def test_config_text():
    config_text = """
        [eth-network]
        [resources]
        aquarius.url = https://another-aqua.url
    """
    config = Config(text=config_text)
    assert config.aquarius_url == "https://another-aqua.url"


@pytest.mark.unit
def test_config_dict():
    config_dict = {
        "eth-network": {},
        "resources": {"aquarius.url": "https://another-aqua2.url"},
    }
    config = Config(options_dict=config_dict)
    assert config.aquarius_url == "https://another-aqua2.url"


@pytest.mark.unit
def test_allow_non_public_ip(monkeypatch):
    config_dict = {
        "eth-network": {},
        "resources": {
            "aquarius.url": "https://another-aqua2.url",
            "allow_non_public_ip": "False",
        },
    }
    config = Config(options_dict=config_dict)
    assert config.allow_non_public_ip is False

    monkeypatch.setenv("ALLOW_NON_PUBLIC_IP", "0")
    config = Config(options_dict=config_dict)
    assert config.allow_non_public_ip is False

    monkeypatch.setenv("ALLOW_NON_PUBLIC_IP", 0)
    config = Config(options_dict=config_dict)
    assert config.allow_non_public_ip is False

    monkeypatch.setenv("ALLOW_NON_PUBLIC_IP", True)
    config = Config(options_dict=config_dict)
    assert config.allow_non_public_ip is True

    monkeypatch.setenv("ALLOW_NON_PUBLIC_IP", "True")
    config = Config(options_dict=config_dict)
    assert config.allow_non_public_ip is True

    monkeypatch.setenv("ALLOW_NON_PUBLIC_IP", "1")
    config = Config(options_dict=config_dict)
    assert config.allow_non_public_ip is True

    monkeypatch.delenv("ALLOW_NON_PUBLIC_IP")
    config = Config(options_dict=config_dict)
    assert config.allow_non_public_ip is False
