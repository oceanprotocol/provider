#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
from typing import Optional

from eth_utils import add_0x_prefix
from ocean_provider.utils.consumable import ConsumableCodes
from ocean_provider.utils.credentials import AddressCredential
from ocean_provider.utils.did import did_to_id


class Asset:
    def __init__(self, dictionary: dict) -> None:
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

    def _read_dict(self, dictionary: dict) -> None:
        """Import a JSON dict into this DDO."""
        asset = copy.deepcopy(dictionary)
        self.did = asset.pop("id")
        self.version = asset.pop("version")
        self.chain_id = asset.pop("chainId")
        self.metadata = asset.pop("metadata")
        self.services = asset.pop("services")
        self.credentials = asset.pop("credentials")
        self.nft = asset.pop("nft")
        self.datatokens = asset.pop("datatokens")
        self.event = asset.pop("event")
        # TODO: uncomment when aquarius supports stats attribute
        # self.stats = asset.pop("stats")

    def get_service(self, service_type: str) -> dict:
        """Return a service using."""
        return next(
            (service for service in self.services if service["type"] == service_type)
        )

    def get_service_by_index(self, index: int) -> dict:
        """
        Get service for a given index.
        :param index: Service id, str
        :return: Service
        """
        return next((service for service in self.services if service[index] == index))

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
