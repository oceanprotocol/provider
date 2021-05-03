#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import os
import pathlib

from ocean_provider.config import NAME_STORAGE_PATH, Config, environ_names


def test_config():
    test_config = os.path.join(
        pathlib.Path(__file__).parent, "resources/test-config.txt"
    )
    _config = Config(filename=test_config)

    assert _config.storage_path == "ocean-provider.db"

    for i, envname in enumerate(environ_names.keys()):
        os.environ[envname] = f"some-value-{i}"

    os.environ[environ_names[NAME_STORAGE_PATH][0]] = "new-storage.db"
    _config = Config(test_config)
    assert _config.storage_path == "new-storage.db"
