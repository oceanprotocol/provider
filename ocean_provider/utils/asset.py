#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
import json
from typing import Optional

from eth_utils import add_0x_prefix
from ocean_provider.utils.consumable import ConsumableCodes
from ocean_provider.utils.credentials import AddressCredential
from ocean_provider.utils.did import did_to_id
from ocean_provider.utils.services import Service


class Asset:
    @property
    def data_token_address(self) -> Optional[str]:
        return self.other_values["dataToken"]

    def __init__(self, dictionary: Optional[dict] = None) -> None:
        """Clear the DDO data values."""
        self._read_dict(dictionary)

    @property
    def is_disabled(self) -> bool:
        """Returns whether the asset is disabled."""
        return self.is_flag_enabled("isOrderDisabled")

    @property
    def is_retired(self) -> bool:
        """Returns whether the asset is retired."""
        return self.is_flag_enabled("isRetired")

    @property
    def asset_id(self) -> Optional[str]:
        """The asset id part of the DID"""
        if not self.did:
            return None
        return add_0x_prefix(did_to_id(self.did))

    @property
    def publisher(self) -> Optional[str]:
        return self.proof.get("creator") if self.proof else None

    @property
    def metadata(self) -> Optional[dict]:
        """Get the metadata service."""
        metadata_service = self.get_service("metadata")
        return metadata_service.attributes if metadata_service else None

    @property
    def encrypted_files(self) -> Optional[dict]:
        """Return encryptedFiles field in the base metadata."""
        return self.metadata["encryptedFiles"]

    def _read_dict(self, dictionary: dict) -> None:
        """Import a JSON dict into this DDO."""
        values = copy.deepcopy(dictionary)
        id_key = "id" if "id" in values else "_id"
        self.did = values.pop(id_key)
        self.created = values.pop("created", None)
        self.credentials = {}

        if "service" in values:
            self.services = []
            for value in values.pop("service"):
                # TODO
                if isinstance(value, str):
                    value = json.loads(value)

                service = Service.from_json(value)
                self.services.append(service)
        if "proof" in values:
            self.proof = values.pop("proof")
        if "credentials" in values:
            self.credentials = values.pop("credentials")

        self.other_values = values

    def get_service(self, service_type: str) -> Service:
        """Return a service using."""
        return next(
            (service for service in self.services if service.type == service_type), None
        )

    def get_service_by_index(self, index: int):
        """
        Get service for a given index.
        :param index: Service id, str
        :return: Service
        """
        return next(
            (service for service in self.services if service.index == index), None
        )

    @property
    def requires_address_credential(self) -> bool:
        """Checks if an address credential is required on this asset."""
        manager = AddressCredential(self)
        return manager.requires_credential()

    @property
    def allowed_addresses(self) -> list:
        """Lists addresses that are explicitly allowed in credentials."""
        manager = AddressCredential(self)
        return manager.get_addresses_of_class("allow")

    @property
    def denied_addresses(self) -> list:
        """Lists addresesses that are explicitly denied in credentials."""
        manager = AddressCredential(self)
        return manager.get_addresses_of_class("deny")

    def is_consumable(
        self,
        credential: Optional[dict] = None,
        with_connectivity_check: bool = True,
        provider_uri: Optional[str] = None,
    ) -> ConsumableCodes:
        """Checks whether an asset is consumable and returns a ConsumableCode."""
        if self.is_disabled or self.is_retired:
            return ConsumableCodes.ASSET_DISABLED

        # to be parameterized in the future, can implement other credential classes
        manager = AddressCredential(self)

        if manager.requires_credential():
            return manager.validate_access(credential)

        return ConsumableCodes.OK

    def is_flag_enabled(self, flag_name: str) -> bool:
        """
        :return: `isListed` or `bool` in metadata_service.attributes["status"]
        """
        metadata_service = self.get_service("metadata")
        default = flag_name == "isListed"  # only one that defaults to True

        if not metadata_service or "status" not in metadata_service.attributes:
            return default

        return metadata_service.attributes["status"].get(flag_name, default)
