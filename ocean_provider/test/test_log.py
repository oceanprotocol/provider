import os
import pytest
from stat import S_IREAD

from ocean_provider.log import setup_logging


@pytest.mark.unit
def test_logging_from_env(monkeypatch, tmpdir):
    log = tmpdir.join("log.txt")
    monkeypatch.setenv("LOG_CFG", log)
    setup_logging()

    with open(log, "w"):
        pass

    os.chmod(log, S_IREAD)
    setup_logging()


@pytest.mark.unit
def test_logging_from_env_no_file(monkeypatch):
    monkeypatch.setenv("LOG_CFG", "filedoesnotexist")
    setup_logging()
