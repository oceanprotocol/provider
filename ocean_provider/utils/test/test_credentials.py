#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from copy import deepcopy
import json

import pytest
from ocean_provider.utils.asset import Asset
from ocean_provider.utils.consumable import ConsumableCodes, MalformedCredential
from ocean_provider.utils.credentials import AddressCredential
from tests.ddo.ddo_sa_sample_with_credentials_v4 import json_dict
from tests.test_helpers import get_resource_path


def test_asset_credentials_addresses_both():
    """Tests asset credentials when both deny and allow lists exist on the asset."""
    sample_asset_path = get_resource_path("ddo", "ddo_sa_sample_with_credentials.json")
    assert sample_asset_path.exists(), "{} does not exist!".format(sample_asset_path)

    ddo = deepcopy(json_dict)
    asset = Asset(ddo)

    address_credential = AddressCredential(asset)
    assert address_credential.get_addresses_of_class("allow") == ["0x123", "0x456a"]
    assert address_credential.get_addresses_of_class("deny") == ["0x2222", "0x333"]
    assert (
        address_credential.validate_access({"type": "address", "value": "0x111"})
        == ConsumableCodes.CREDENTIAL_NOT_IN_ALLOW_LIST
    )
    assert (
        address_credential.validate_access({"type": "address", "value": "0x456A"})
        == ConsumableCodes.OK
    )
    # if "allow" exists, "deny" is not checked anymore


def test_asset_credentials_addresses_only_deny():
    """Tests asset credentials when only the deny list exists on the asset."""
    sample_asset_path = get_resource_path("ddo", "ddo_sa_sample_with_credentials.json")
    assert sample_asset_path.exists(), "{} does not exist!".format(sample_asset_path)

    ddo = deepcopy(json_dict)
    asset = Asset(ddo)

    # remove allow to test the behaviour of deny
    asset.credentials.pop("allow")

    address_credential = AddressCredential(asset)
    assert address_credential.get_addresses_of_class("allow") == []
    assert address_credential.get_addresses_of_class("deny") == ["0x2222", "0x333"]
    assert (
        address_credential.validate_access({"type": "address", "value": "0x111"})
        == ConsumableCodes.OK
    )
    assert (
        address_credential.validate_access({"type": "address", "value": "0x333"})
        == ConsumableCodes.CREDENTIAL_IN_DENY_LIST
    )

    credential = {"type": "address", "value": ""}
    with pytest.raises(MalformedCredential):
        address_credential.validate_access(credential)


def test_asset_credentials_addresses_no_access_list():
    """Tests asset credentials when neither deny, nor allow lists exist on the asset."""
    sample_asset_path = get_resource_path("ddo", "ddo_sa_sample_with_credentials.json")
    assert sample_asset_path.exists(), "{} does not exist!".format(sample_asset_path)

    ddo = deepcopy(json_dict)
    asset = Asset(ddo)

    # if "allow" OR "deny" exist, we need a credential,
    # so remove both to test the behaviour of no credential supplied
    address_credential = AddressCredential(asset)
    asset.credentials.pop("allow")
    asset.credentials.pop("deny")

    assert address_credential.validate_access() == ConsumableCodes.OK

    # test that we can use another credential if address is not required
    assert (
        asset.is_consumable(
            {"type": "somethingelse", "value": "test"}, with_connectivity_check=False
        )
        == ConsumableCodes.OK
    )
