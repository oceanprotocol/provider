#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
from typing import Optional

from ocean_provider.utils.consumable import ConsumableCodes
from ocean_provider.utils.credentials import AddressCredential
from ocean_provider.utils.services import Service, ServiceType


class Asset:
    def __init__(self, asset_dict: dict) -> None:
        ad = copy.deepcopy(asset_dict)
        self.did = ad.pop("id", None)
        self.version = ad.pop("version", None)
        self.chain_id = ad.pop("chainId", None)
        self.metadata = ad.pop("metadata", None)
        self.services = [
            Service.from_json(index, service_dict)
            for index, service_dict in enumerate(ad.pop("services", []))
        ]
        self.credentials = ad.pop("credentials", None)
        self.nft = ad.pop("nft", None)
        self.datatokens = ad.pop("datatokens", None)
        self.event = ad.pop("event", None)
        self.stats = ad.pop("stats", None)

    def get_service_by_type(self, service_type: ServiceType) -> Service:
        """Return the first Service with the given ServiceType."""
        return next(
            (service for service in self.services if service.type == service_type)
        )

    def get_service_by_index(self, index: int) -> Service:
        """Return the first Service with the given index"""
        return next((service for service in self.services if service.index == index))

    def get_service_by_id(self, service_id: str) -> Service:
        """Return the Service with teh matching id"""
        return next((service for service in self.services if service.id == service_id))

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

    @property
    def is_disabled(self) -> bool:
        return not self.metadata or (self.nft and self.nft["state"] != 0)

    def is_consumable(
        self,
        credential: Optional[dict] = None,
        with_connectivity_check: bool = True,
        provider_uri: Optional[str] = None,
    ) -> ConsumableCodes:
        """Checks whether an asset is consumable and returns a ConsumableCode."""
        if self.is_disabled:
            return ConsumableCodes.ASSET_DISABLED

        manager = AddressCredential(self)

        if manager.requires_credential():
            return manager.validate_access(credential)

        return ConsumableCodes.OK

    def is_flag_enabled(self, flag_name: str) -> bool:
        """
        :return: `isListed` or `bool` in metadata_service.attributes["status"]
        """
        metadata_service = self.get_service_by_type("metadata")
        default = flag_name == "isListed"  # only one that defaults to True

        if not metadata_service or "status" not in metadata_service.attributes:
            return default

        return metadata_service.attributes["status"].get(flag_name, default)
