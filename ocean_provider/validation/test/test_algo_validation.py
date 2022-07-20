#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
from unittest.mock import Mock, patch

import pytest
from ocean_provider.utils.asset import Asset
from ocean_provider.utils.basics import get_web3
from ocean_provider.utils.services import Service, ServiceType
from ocean_provider.validation.algo import WorkflowValidator
from tests.ddo.ddo_sample1_compute import alg_ddo_dict, ddo_dict
from tests.helpers.compute_helpers import get_future_valid_until
from tests.test_helpers import get_first_service_by_type

provider_fees_event = Mock()
provider_fees_event.args.providerData = {"environment": "ocean-compute"}
provider_fees_event.args.validUntil = get_future_valid_until()
provider_fees_event.args.providerFeeAmount = 0

this_is_a_gist = "https://gist.githubusercontent.com/calina-c/5e8c965962bc0240eab516cb7a180670/raw/6e6cd245c039a9aac0a488857c6927d39eaafe4d/sprintf-py-conversions"


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_passes_algo_ddo(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with algo ddo."""
    web3 = get_web3()
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": "alg_tx_id",
        },
        "environment": "ocean-compute",
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
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_passes_raw(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with raw algo."""
    web3 = get_web3()
    ddo = Asset(ddo_dict)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
        "algorithm": {
            "serviceId": sa.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {
                    "entrypoint": "node $ALGO",
                    "image": "oceanprotocol/algo_dockers",
                    "tag": "python-branin",
                    "checksum": "sha256:8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
                },
            },
        },
        "environment": "ocean-compute",
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is True


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fails_not_an_algo(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with algo ddo."""
    _copy = copy.deepcopy(ddo_dict)
    _copy["services"][0]["compute"]["publisherTrustedAlgorithms"] = []
    ddo = Asset(_copy)
    did = ddo.did
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": did, "transferTxId": "tx_id", "serviceId": sa.id},
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
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fails_meta_issues(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with raw algo."""
    ddo = Asset(ddo_dict)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    """Tests happy flow of validator with algo ddo and raw algo."""
    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
        "algorithm": {"serviceId": sa.id, "meta": {}},
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
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
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
            == "algorithm `container` must specify values for all of entrypoint, image and checksum."
        )

    # algorithmMeta container is missing image
    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
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
            == "algorithm `container` must specify values for all of entrypoint, image and checksum."
        )

    # algorithmMeta container checksum does not start with sha256
    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
        "algorithm": {
            "serviceId": sa.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {
                    "entrypoint": "node $ALGO",
                    "image": "oceanprotocol/algo_dockers",
                    "tag": "python-branin",
                    "checksum": "8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
                },
            },
        },
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert validator.error == "container checksum must start with sha256:"

    # algorithmMeta container checksum is wrong
    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
        "algorithm": {
            "serviceId": sa.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {
                    "entrypoint": "node $ALGO",
                    "image": "oceanprotocol/algo_dockers",
                    "tag": "python-branin",
                    # keep the length, just make it invalid
                    "checksum": "sha256:8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b0900000",
                },
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
            == "Invalid container values provided on algorithm. Check image, tag and checksum."
        )


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_additional_datasets(provider_wallet, consumer_address, web3):
    web3 = get_web3()
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": "alg_tx_id",
        },
        "additionalDatasets": "",
        "environment": "ocean-compute",
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
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
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
        "dataset": {"documentId": did, "transferTxId": "tx_id", "serviceId": sa.id},
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
        "dataset": {"documentId": did, "transferTxId": "tx_id", "serviceId": sa.id},
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
        "dataset": {"documentId": did, "transferTxId": "tx_id", "serviceId": sa.id},
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
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_service_not_compute(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
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
            timeout=3600,
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
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fails_trusted(provider_wallet, consumer_address, web3):
    """Tests possible failures of the algo validation."""
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    # Additional input has other trusted algs
    _copy = copy.deepcopy(ddo_dict)
    _copy["id"] = "0xtrust"
    _copy["services"][0]["compute"]["publisherTrustedAlgorithms"] = [
        {"did": "0xother", "filesChecksum": "mock", "containerSectionChecksum": "mock"}
    ]
    trust_ddo = Asset(_copy)
    trust_sa = get_first_service_by_type(trust_ddo, ServiceType.COMPUTE)

    def side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo, trust_ddo
        if ddo.did == args[1]:
            return ddo
        if alg_ddo.did == args[1]:
            return alg_ddo
        if trust_ddo.did == args[1]:
            return trust_ddo

    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
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
    _copy["services"][0]["compute"]["publisherTrustedAlgorithmPublishers"] = ["0xabc"]
    _copy["services"][0]["id"] = "compute_2"
    trust_ddo = Asset(_copy)
    trust_sa = get_first_service_by_type(trust_ddo, ServiceType.COMPUTE)

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


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch("ocean_provider.validation.algo.get_service_files_list", return_value=None)
def test_fails_no_asset_url(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
        "algorithm": {"serviceId": sa.id, "meta": {}},
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert (
            validator.error
            == "Services in input with compute type must be in the same provider you are calling."
        )


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch("ocean_provider.validation.algo.validate_order", side_effect=Exception("mock"))
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fails_validate_order(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
        "algorithm": {"serviceId": sa.id, "meta": {}},
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert validator.error == f"Order for serviceId {sa.id} is not valid. mock."


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fails_no_service_id(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    data = {
        "dataset": {"documentId": ddo.did, "serviceId": None, "transferTxId": "tx_id"},
        "algorithm": {"serviceId": sa.id, "meta": {}},
    }

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore", side_effect=[ddo]
    ):
        validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
        assert validator.validate() is False
        assert validator.error == "No serviceId in input item."


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
@patch(
    "ocean_provider.serializers.StageAlgoSerializer.serialize",
    new=Mock(return_value={}),
)
def test_fails_invalid_algorithm_dict(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
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
        assert validator.validate() is False
        assert validator.error == f"cannot get url for the algorithmDid {alg_ddo.did}"


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fails_algorithm_in_use(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
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

    def record_consume_request_side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if ddo.did == args[0]:
            return ddo
        if alg_ddo.did == args[0]:
            raise Exception("I know Python!")

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        with patch(
            "ocean_provider.validation.algo.record_consume_request",
            side_effect=record_consume_request_side_effect,
        ):
            validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
            assert validator.validate() is False
            assert (
                validator.error
                == "Algorithm is already in use or can not be found on chain."
            )


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fail_wrong_algo_type(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
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
            service_id=data["algorithm"]["serviceId"],
            service_type="access",
            datatoken_address="0xa",
            service_endpoint="test",
            encrypted_files="",
            timeout=3600,
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
            assert validator.error == "Service for main asset must be compute."


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fail_allow_raw_false(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)
    ddo.services[0].compute_dict["allowRawAlgorithm"] = False
    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
        "algorithm": {
            "serviceId": sa_compute.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {
                    "entrypoint": "node $ALGO",
                    "image": "oceanprotocol/algo_dockers",
                    "tag": "python-branin",
                    "checksum": "sha256:8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
                },
            },
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
        assert validator.error == f"cannot run raw algorithm on this did {ddo.did}."


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
def test_success_multiple_services_types(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
        "algorithm": {
            "serviceId": sa_compute.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {
                    "entrypoint": "node $ALGO",
                    "image": "oceanprotocol/algo_dockers",
                    "tag": "python-branin",
                    "checksum": "sha256:8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
                },
            },
        },
        "additionalDatasets": [
            {"documentId": ddo.did, "transferTxId": "ddo.did", "serviceId": "access_1"}
        ],
        "environment": "ocean-compute",
    }

    def side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if ddo.did == args[1]:
            return ddo
        if alg_ddo.did == args[1]:
            return alg_ddo

    def another_side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if args[0].type == "access":
            return None
        return [{"url": this_is_a_gist, "type": "url"}]

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        with patch(
            "ocean_provider.validation.algo.get_service_files_list",
            side_effect=another_side_effect,
        ):
            validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
            assert validator.validate() is True


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
def test_fail_missing_algo_meta_documentId(provider_wallet, consumer_address, web3):
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "transferTxId": "tx_id", "serviceId": sa.id},
        "algorithm": {"serviceId": None, "meta": None},
        "additionalDatasets": [
            {"documentId": ddo.did, "transferTxId": "ddo.did", "serviceId": "access_1"}
        ],
    }

    def side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if ddo.did == args[1]:
            return ddo
        if alg_ddo.did == args[1]:
            return alg_ddo

    def another_side_effect(*args, **kwargs):
        nonlocal ddo, alg_ddo
        if args[0].type == "access":
            return None
        return [{"url": this_is_a_gist, "type": "url"}]

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=side_effect,
    ):
        with patch(
            "ocean_provider.validation.algo.get_service_files_list",
            side_effect=another_side_effect,
        ):
            validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
            assert validator.validate() is False
            assert (
                validator.error
                == "both meta and documentId are missing from algorithm input, at least one of these is required."
            )


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": this_is_a_gist, "type": "url"}],
)
def test_fee_amount_not_paid(provider_wallet, consumer_address, web3):
    """Tests happy flow of validator with algo ddo."""
    web3 = get_web3()
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
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
        with patch("ocean_provider.validation.algo.get_provider_fee_amount") as mock:
            mock.return_value = 10**18
            validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
            assert validator.validate() is False
            assert (
                validator.error
                == "Provider fees must be paid on the asset, OR on the algorithm ordered, OR on any additional input."
            )


@pytest.mark.unit
@patch("ocean_provider.validation.algo.check_asset_consumable", return_value=(True, ""))
@patch(
    "ocean_provider.validation.algo.validate_order",
    return_value=(None, None, provider_fees_event, None),
)
@patch(
    "ocean_provider.validation.algo.get_service_files_list",
    return_value=[{"url": "http://some.broken.url", "type": "url"}],
)
def test_algo_ddo_file_broken(provider_wallet, consumer_address, web3):
    """Tests case where algo checksum can not be computed."""
    web3 = get_web3()
    ddo = Asset(ddo_dict)
    alg_ddo = Asset(alg_ddo_dict)
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    sa = get_first_service_by_type(ddo, ServiceType.COMPUTE)

    data = {
        "dataset": {"documentId": ddo.did, "serviceId": sa.id, "transferTxId": "tx_id"},
        "algorithm": {
            "documentId": alg_ddo.did,
            "serviceId": sa_compute.id,
            "transferTxId": "alg_tx_id",
        },
        "environment": "ocean-compute",
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
        assert (
            validator.error == "Unable to check algorithm file, is it still available?"
        )
