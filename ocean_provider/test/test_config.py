#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import os
import pathlib

from ocean_provider.config import NAME_STORAGE_PATH, Config, environ_names


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


def test_config_text():
    config_text = """
        [eth-network]
        [resources]
        aquarius.url = https://another-aqua.url
    """
    config = Config(text=config_text)
    assert config.aquarius_url == "https://another-aqua.url"


def test_config_dict():
    config_dict = {
        "eth-network": {},
        "resources": {"aquarius.url": "https://another-aqua2.url"},
    }
    config = Config(options_dict=config_dict)
    assert config.aquarius_url == "https://another-aqua2.url"
