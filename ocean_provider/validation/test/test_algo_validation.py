#
## Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import pytest

from ocean_provider.utils.asset import Asset
from ocean_provider.utils.services import ServiceType
from ocean_provider.validation.algo import WorkflowValidator, build_stage_output_dict
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
def test_passes(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet, web3
):
    """Tests happy flow of validator with algo ddo and raw algo."""
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

    with patch(
        "ocean_provider.validation.algo.get_asset_from_metadatastore",
        side_effect=[ddo, alg_ddo, alg_ddo],
    ):
        with patch(
            "ocean_provider.serializers.get_asset_from_metadatastore",
            return_value=alg_ddo,
        ):
            validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
            assert validator.validate() is True

    data = {
        "dataset": {
            "documentId": ddo.did,
            "serviceId": sa.id,
            "transferTxId": "tx_id",
        },
        "algorithm": {
            "serviceId": sa_compute.id,
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
        with patch(
            "ocean_provider.serializers.get_asset_from_metadatastore",
            return_value=alg_ddo,
        ):
            validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
            assert validator.validate() is True


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
    alg_data_token = sa_compute.datatoken_address

    # algorithmDid is not actually an algorithm
    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": tx_id,
            "serviceId": sa.id,
        },
        "algorithm": {
            "documentId": did,
            "serviceId": sa_compute.id,
            "transferTxId": alg_tx_id,
        },
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == f"DID {did} is not a valid algorithm"

    valid_output = build_stage_output_dict(
        dict(), sa.service_endpoint, consumer_address, publisher_wallet
    )

    # algorithmMeta doesn't contain 'url' or 'rawcode'
    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": tx_id,
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "meta": {},
        },
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithmMeta must define one of `url` or `rawcode` or `remote`, but all seem missing."
    )

    # algorithmMeta container is empty
    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": tx_id,
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {},
            },
        },
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithm `container` must specify values for all of entrypoint, image and tag."
    )

    # algorithmMeta container is missing image
    data = {
        "dataset": {
            "documentId": did,
            "transferTxId": tx_id,
            "serviceId": sa.id,
        },
        "algorithm": {
            "serviceId": sa_compute.id,
            "meta": {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {"entrypoint": "node $ALGO", "tag": "10"},
            },
        },
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithm `container` must specify values for all of entrypoint, image and tag."
    )

    # Additional Input validations ###
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
        "additionalDatasets": "",
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is True

    # additional input is invalid
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
        "additionalDatasets": "i can not be decoded in json!",
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == "Additional input is invalid or can not be decoded."

    # Missing did in additional input
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
        "additionalDatasets": [{"transferTxId": tx_id, "serviceId": sa.id}],
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == "Error in input at index 1: No documentId in input item."

    # Did is not valid
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
                "documentId": "i am not a did",
                "transferTxId": tx_id,
                "serviceId": sa.id,
            }
        ],
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "Error in input at index 1: Asset for did i am not a did not found."
    )

    # Service is not compute, nor access
    other_service = [s for s in ddo.services if s.type not in ["compute", "access"]][0]
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
            {"documentId": did, "transferTxId": tx_id, "serviceId": other_service.id}
        ],
    }

    validator = WorkflowValidator(web3, consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "Error in input at index 1: Services in input can only be access or compute."
    )

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
