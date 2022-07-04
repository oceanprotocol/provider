#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
"""Config data."""

#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import configparser
from distutils.util import strtobool
import json
import logging
import os
from pathlib import Path

from jsonsempai import magic
from addresses import address as contract_addresses


NAME_NETWORK_URL = "network"
NAME_ADDRESS_FILE = "address.file"

NAME_AQUARIUS_URL = "aquarius.url"
NAME_PROVIDER_ADDRESS = "provider.address"
NAME_OPERATOR_SERVICE_URL = "operator_service.url"
NAME_ALLOW_NON_PUBLIC_IP = "allow_non_public_ip"
NAME_STORAGE_PATH = "storage.path"
NAME_BLOCK_CONFIRMATIONS = "block_confirmations"
NAME_AUTHORIZED_DECRYPTERS = "authorized_decrypters"
NAME_IS_POA_NETWORK = "is_poa_network"

environ_names = {
    NAME_NETWORK_URL: [
        "NETWORK_URL",
        "Network URL (e.g. Main, Kovan etc.)",
        "eth-network",
    ],
    NAME_ADDRESS_FILE: [
        "ADDRESS_FILE",
        "Path to json file of deployed contracts addresses",
        "eth-network",
    ],
    NAME_AQUARIUS_URL: ["AQUARIUS_URL", "Aquarius url (metadata store)", "resources"],
    NAME_OPERATOR_SERVICE_URL: [
        "OPERATOR_SERVICE_URL",
        "Operator service URL",
        "resources",
    ],
    NAME_ALLOW_NON_PUBLIC_IP: [
        "ALLOW_NON_PUBLIC_IP",
        "Allow non public ip",
        "resources",
    ],
    NAME_STORAGE_PATH: ["STORAGE_PATH", "Path to the local database file", "resources"],
    NAME_BLOCK_CONFIRMATIONS: [
        "BLOCK_CONFIRMATIONS",
        "Block confirmations",
        "eth-network",
    ],
    NAME_AUTHORIZED_DECRYPTERS: [
        "AUTHORIZED_DECRYPTERS",
        "List of authorized decrypters",
        "resources",
    ],
    NAME_IS_POA_NETWORK: [
        "IS_POA_NETWORK",
        "Is POA network",
        "eth-network",
    ],
}


class Config(configparser.ConfigParser):
    """Class to manage the squid-py configuration."""

    def __init__(self, filename=None, options_dict=None, **kwargs):
        """
        Initialize Config class.

        Options available:

        [eth-network]
        network = http://localhost:8545                            # ocean-contracts url.

        [resources]
        aquarius.url = http://localhost:5000

        :param filename: Path of the config file, str.
        :param options_dict: Python dict with the config, dict.
        :param kwargs: Additional args. If you pass text, you have to pass the plain text
        configuration.
        """
        configparser.ConfigParser.__init__(self)

        self._section_name = "eth-network"
        self._logger = logging.getLogger("config")

        if filename:
            self._logger.debug(f"Config: loading config file {filename}")
            with open(filename) as fp:
                text = fp.read()
                self.read_string(text)
        else:
            if "text" in kwargs:
                self.read_string(kwargs["text"])

        if options_dict:
            self._logger.debug(f"Config: loading from dict {options_dict}")
            self.read_dict(options_dict)

        self._load_environ()

    def _load_environ(self):
        for option_name, environ_item in environ_names.items():
            value = os.environ.get(environ_item[0])
            if value is not None:
                self._logger.debug(f"Config: setting environ {option_name} = {value}")
                self.set(environ_item[2], option_name, value)

    @property
    def address_file(self):
        file_path = self.get(self._section_name, NAME_ADDRESS_FILE, fallback=None)
        if file_path:
            return Path(file_path).expanduser().resolve()

        return Path(contract_addresses.__file__).expanduser().resolve()

    @property
    def network_url(self):
        """URL of the evm network. (e.g.): http://localnetwork:8545."""
        return self.get(self._section_name, NAME_NETWORK_URL, fallback=None)

    @property
    def aquarius_url(self):
        return self.get("resources", NAME_AQUARIUS_URL, fallback=None)

    @property
    def provider_address(self):
        return self.get("resources", NAME_PROVIDER_ADDRESS, fallback=None)

    @property
    def operator_service_url(self):
        """URL of the operator service component. (e.g.): http://myoperatorservice:8050."""
        return self.get("resources", NAME_OPERATOR_SERVICE_URL, fallback=None)

    @property
    def allow_non_public_ip(self):
        """Allow non public ip."""
        should_allow_non_public_ip = self.get(
            "resources", NAME_ALLOW_NON_PUBLIC_IP, fallback="false"
        )

        return bool(strtobool(str(should_allow_non_public_ip)))

    @property
    def storage_path(self):
        """Path to local storage (database file)."""
        fallback = "ocean-provider.db"
        result = self.get("resources", NAME_STORAGE_PATH, fallback=fallback)

        return result if result else fallback

    @property
    def authorized_decrypters(self):
        return json.loads(
            self.get("resources", NAME_AUTHORIZED_DECRYPTERS, fallback="[]")
        )

    @property
    def block_confirmations(self):
        return int(self.get("eth-network", NAME_BLOCK_CONFIRMATIONS, fallback=0))

    @property
    def is_poa_network(self):
        return bool(
            strtobool(self.get("eth-network", NAME_IS_POA_NETWORK, fallback="0"))
        )
