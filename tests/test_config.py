import os

from ocean_provider.config import Config, environ_names, NAME_STORAGE_PATH
from ocean_provider.utils.basics import get_config


def test_loading_envvars():
    config_file = get_config()
    _config = Config(config_file)
    assert _config.storage_path == 'ocean-provider.db'

    for i, envname in enumerate(environ_names.keys()):
        os.environ[envname] = f'some-value-{i}'

    os.environ[environ_names[NAME_STORAGE_PATH][0]] = 'new-storage.db'
    _config = Config(config_file)
    assert _config.storage_path == 'new-storage.db'
