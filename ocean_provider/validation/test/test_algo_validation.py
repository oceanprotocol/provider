#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
import pytest

from ocean_provider.utils.asset import Asset
from ocean_provider.utils.services import ServiceType, Service
from ocean_provider.validation.algo import WorkflowValidator
from tests.ddo.ddo_sample1_compute import ddo_dict, alg_ddo_dict
from tests.helpers.compute_helpers import build_and_send_ddo_with_compute_service
from unittest.mock import patch


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_passes_algo_ddo(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet, web3
):
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
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_passes_raw(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet, web3
):
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
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_fails_not_an_algo(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet, web3
):
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
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_fails_meta_issues(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet, web3
):
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
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_additional_datasets(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet, web3
):
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
            {"documentId": did, "transferTxId": "tx_id", "serviceId": "some other service id"}
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
@patch("ocean_provider.validation.algo.validate_order", return_value=(None, None, None))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "dummy"}],
)
def test_service_not_compute(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet, web3
):
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
        with patch('ocean_provider.utils.asset.Asset.get_service_by_id', side_effect=other_service):
            validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
            assert validator.validate() is False
            assert (
                validator.error
                == "Services in input can only be access or compute."
            )


@pytest.mark.integration
def test_fails(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet, web3
):
    """Tests possible failures of the algo validation."""
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        asset_type="allow_all_published_and_one_bogus",
    )
    did = ddo.did
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = ddo.get_service_by_type(ServiceType.COMPUTE)

    # Service is not compute, nor access

    # Additional input has other trusted algs
    trust_ddo, trust_tx_id, _, _ = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    trust_sa = trust_ddo.get_service_by_type(ServiceType.COMPUTE)

    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": tx_id,
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "documentId": alg_ddo.did,
            "transferTxId": alg_tx_id,
        },
        "additionalDatasets": [
            {
                "documentId": trust_ddo.did,
                "transferTxId": trust_tx_id,
                "serviceId": trust_sa.id,
            }
        ],
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == f"Error in input at index 1: this algorithm did {alg_ddo.did} is not trusted."
    )

    # Additional input has other trusted publishers
    (
        trust_ddo,
        trust_tx_id,
        alg_ddo,
        alg_tx_id,
    ) = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet, asset_type="specific_algo_publishers"
    )
    did = trust_ddo.did
    trust_sa = trust_ddo.get_service_by_type(ServiceType.COMPUTE)
    sa_compute = alg_ddo.get_service_by_type(ServiceType.ACCESS)
    sa = trust_ddo.get_service_by_type(ServiceType.COMPUTE)

    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": trust_tx_id,
            "serviceId": sa.id,
        },
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
        },
        "additionalDatasets": [
            {
                "documentId": trust_ddo.did,
                "transferTxId": trust_tx_id,
                "serviceId": trust_sa.id,
            }
        ],
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == "this algorithm is not from a trusted publisher"
