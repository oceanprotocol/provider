#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
import pytest
from unittest.mock import patch

from ocean_provider.utils.asset import Asset
from ocean_provider.utils.services import ServiceType, Service
from ocean_provider.validation.algo import WorkflowValidator
from tests.ddo.ddo_sample1_compute import ddo_dict, alg_ddo_dict


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_passes_algo_ddo(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with algo ddo."""
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)

    data = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": "tx_id",
        },
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": "alg_tx_id",
        },
    }

    def side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if ddo.did == args[1]:
            return ddo
        if alg_ddo.did == args[1]:
            return alg_ddo

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is True


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_passes_raw(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with raw algo."""
    ddo = Asset(ddo_dict)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)
    data = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": "tx_id",
        },
        "algorithm": {
            "serviceId": sa.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {"entrypoint": "node $ALGO", "image": "node", "tag": "10"},
            },
        },
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is True


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_fails_not_an_algo(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with algo ddo."""
    _copy = copy.deepcopy(ddo_dict)
    _copy["services"][0]["compute"]["publisherTrustedAlgorithms"] = []
    ddo = Asset(_copy)
    did = ddo.did
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)

    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "documentId": did,
            "serviceId": sa_compute.id,
            "transferTxId": "alg_tx_id",
        },
    }

    def side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if ddo.did == args[1]:
            return ddo
        if alg_ddo.did == args[1]:
            return alg_ddo

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert validator.error == f"DID {did} is not a valid algorithm"


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_fails_meta_issues(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with raw algo."""
    ddo = Asset(ddo_dict)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)
    """Tests happy flow of validator with algo ddo and raw algo."""
    data = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": "tx_id",
        },
        "algorithm": {
            "serviceId": sa.id,
            "meta": {},
        },
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error
            == "algorithmMeta must define one of `url` or `rawcode` or `remote`, but all seem missing."
        )

    # algorithmMeta container is empty
    data = {
        "dataset": {
            "documentId": ddo.did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {},
            },
        },
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error
            == "algorithm `container` must specify values for all of entrypoint, image and tag."
        )

    # algorithmMeta container is missing image
    data = {
        "dataset": {
            "documentId": ddo.did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {"entrypoint": "node $ALGO", "tag": "10"},
            },
        },
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error
            == "algorithm `container` must specify values for all of entrypoint, image and tag."
        )


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_additional_datasets(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)

    data = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": "tx_id",
        },
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": "alg_tx_id",
        },
        "additionalDatasets": "",
    }

    def side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if ddo.did == args[1]:
            return ddo
        if alg_ddo.did == args[1]:
            return alg_ddo

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        # basically the same test as test_passes_algo_ddo, additionalDatasets is empty
        assert validator.validate() is True

    # additional input is invalid
    data = {
        "dataset": {
            "documentId": ddo.did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": "alg_tx_id",
        },
        "additionalDatasets": "i can not be decoded in json!",
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == "Additional input is invalid or can not be decoded."

    did = ddo.did

    # Missing did in additional input
    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": "alg_tx_id",
        },
        "additionalDatasets": [{"transferTxId": "tx_id", "serviceId": sa.id}],
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error == "Error in input at index 1: No documentId in input item."
        )

    # Did is not valid
    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": "alg_tx_id",
        },
        "additionalDatasets": [
            {
                "documentId": "i am not a did",
                "transferTxId": "tx_id",
                "serviceId": sa.id,
            }
        ],
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error
            == "Error in input at index 1: Asset for did i am not a did not found."
        )

    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": "alg_tx_id",
        },
        "additionalDatasets": [
            {
                "documentId": did,
                "transferTxId": "tx_id",
                "serviceId": "some other service id",
            }
        ],
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error
            == "Error in input at index 1: Service id some other service id not found."
        )


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_service_not_compute(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)

    data = {
        "dataset": {
            "documentId": ddo.did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": "alg_tx_id",
        },
    }

    def side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if ddo.did == args[1]:
            return ddo
        if alg_ddo.did == args[1]:
            return alg_ddo

    def other_service(*args, **kwargs):
        return Service(
            index=0,
            service_id="smth_else",
            service_type="something else",
            datatoken_address="0xa",
            service_endpoint="test",
            encrypted_files="",
            timeout=0,
        )

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        with patch(
            "ocean_provider.utils.asset.Asset.get_service_by_id",
            side_effect=other_service,
        ):
            validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
            assert validator.validate() is False
            assert validator.error == "Services in input can only be access or compute."


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_fails_trusted(provider_wallet, consumer_address, web3):
    """Tests possible failures of the algo validation."""
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)

    # Additional input has other trusted algs
    _copy = copy.deepcopy(ddo_dict)
    _copy["id"] = "0xtrust"
    _copy["services"][0]["compute"]["publisherTrustedAlgorithms"] = [
        {"did": "0xother", "filesChecksum": "mock", "containerSectionChecksum": "mock"}
    ]
    trust_ddo = Asset(_copy)
    trust_sa = trust_ddo.get_service_by_type(ServiceType.COMPUTE)

    def side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo, trust_ddo
        if ddo.did == args[1]:
            return ddo
        if alg_ddo.did == args[1]:
            return alg_ddo
        if trust_ddo.did == args[1]:
            return trust_ddo

    data = {
        "dataset": {
            "documentId": ddo.did,
            "transferTxId": "tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": "alg_tx_id",
        },
        "additionalDatasets": [
            {
                "documentId": trust_ddo.did,
                "transferTxId": "trust_tx_id",
                "serviceId": trust_sa.id,
            }
        ],
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error
            == f"Error in input at index 1: this algorithm did {alg_ddo.did} is not trusted."
        )

    # Additional input has other trusted publishers
    _copy = copy.deepcopy(ddo_dict)
    _copy["id"] = "0xtrust"
    _copy["services"][0]["compute"]["publisherTrustedAlgorithmPublishers"] = [
        "0xabc",
    ]
    _copy["services"][0]["id"] = "compute_2"
    trust_ddo = Asset(_copy)
    trust_sa = trust_ddo.get_service_by_type(ServiceType.COMPUTE)

    data = {
        "dataset": {
            "documentId": ddo.did,
            "transferTxId": "trust_tx_id",
            "serviceId": sa.id,
        },
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": "alg_tx_id",
        },
        "additionalDatasets": [
            {
                "documentId": trust_ddo.did,
                "transferTxId": "trust_tx_id",
                "serviceId": trust_sa.id,
            }
        ],
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error
            == "Error in input at index 1: this algorithm is not from a trusted publisher"
        )
