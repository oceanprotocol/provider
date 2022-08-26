#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
import requests
from typing import Optional

from jsonsempai import magic  # noqa: F401
from artifacts import ERC721Template
from ocean_provider.utils.basics import get_web3
from ocean_provider.utils.consumable import ConsumableCodes
from ocean_provider.utils.credentials import AddressCredential
from ocean_provider.utils.services import Service


class Asset:
    def __init__(self, asset_dict: dict) -> None:
        ad = copy.deepcopy(asset_dict)
        self.did = ad.pop("id", None)
        self.version = ad.pop("version", None)
        self.nftAddress = ad.pop("nftAddress", None)
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

    def get_service_by_index(self, index: int) -> Service:
        """Return the first Service with the given index"""
        return next((service for service in self.services if service.index == index))

    def get_service_by_id(self, service_id: str) -> Service:
        """Return the Service with the matching id"""
        try:
            return next(
                (service for service in self.services if service.id == service_id)
            )
        except StopIteration:
            return None

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


def get_asset_from_metadatastore(metadata_url, document_id) -> Optional[Asset]:
    """
    :return: `Asset` instance or None
    """
    url = f"{metadata_url}/api/aquarius/assets/ddo/{document_id}"
    response = requests.get(url)

    return Asset(response.json()) if response.status_code == 200 else None


def check_asset_consumable(asset, consumer_address, logger, custom_url=None):
    if not asset.nft or "address" not in asset.nft:
        return False, "Asset malformed"
    web3 = get_web3()
    dt_contract = web3.eth.contract(
        abi=ERC721Template.abi, address=web3.toChecksumAddress(asset.nft["address"])
    )

    if dt_contract.caller.getMetaData()[2] != 0:
        return False, "Asset is not consumable."

    code = asset.is_consumable({"type": "address", "value": consumer_address})

    if code == ConsumableCodes.OK:  # is consumable
        return True, ""

    message = f"Error: Access to asset {asset.did} was denied with code: {code}."
    logger.error(message, exc_info=1)

    return False, message
