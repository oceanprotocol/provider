#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json

from ocean_lib.common.agreements.service_types import ServiceTypes
from ocean_provider.validation.algo import WorkflowValidator, build_stage_output_dict
from tests.helpers.compute_helpers import build_and_send_ddo_with_compute_service


def test_passes(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet
):
    """Tests happy flow of validator with algo ddo and raw algo."""
    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    sa = ddo.get_service(ServiceTypes.CLOUD_COMPUTE)

    data = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "transferTxId": tx_id,
        "output": build_stage_output_dict(
            dict(), sa.service_endpoint, consumer_address, publisher_wallet
        ),
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_ddo.data_token_address,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is True

    data = {
        "documentId": ddo.did,
        "serviceId": sa.index,
        "transferTxId": tx_id,
        "output": build_stage_output_dict(
            dict(), sa.service_endpoint, consumer_address, publisher_wallet
        ),
        "algorithmMeta": json.dumps(
            {
                "rawcode": "console.log('Hello world'!)",
                "format": "docker-image",
                "version": "0.1",
                "container": {"entrypoint": "node $ALGO", "image": "node", "tag": "10"},
            }
        ),
    }
    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is True


def test_fails(
    client, provider_wallet, consumer_wallet, consumer_address, publisher_wallet
):
    """Tests possible failures of the algo validation."""
    dataset, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet
    )
    did = dataset.did
    sa = dataset.get_service(ServiceTypes.CLOUD_COMPUTE)
    alg_data_token = alg_ddo.data_token_address

    # output key is invalid
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": "this can not be decoded",
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == "Output is invalid or can not be decoded."

    # algorithmDid is not actually an algorithm
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": build_stage_output_dict(
            dict(), sa.service_endpoint, consumer_address, publisher_wallet
        ),
        "algorithmDid": did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == f"DID {did} is not a valid algorithm"

    valid_output = build_stage_output_dict(
        dict(), sa.service_endpoint, consumer_address, publisher_wallet
    )

    # algorithmMeta doesn't contain 'url' or 'rawcode'
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmMeta": {},
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithmMeta must define one of `url` or `rawcode` or `remote`, but all seem missing."
    )

    # algorithmMeta container is empty
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmMeta": {
            "rawcode": "console.log('Hello world'!)",
            "format": "docker-image",
            "version": "0.1",
            "container": {},
        },
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithm `container` must specify values for all of entrypoint, image and tag."
    )

    # algorithmMeta container is missing image
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmMeta": {
            "rawcode": "console.log('Hello world'!)",
            "format": "docker-image",
            "version": "0.1",
            "container": {"entrypoint": "node $ALGO", "tag": "10"},
        },
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithm `container` must specify values for all of entrypoint, image and tag."
    )

    # Additional Input validations ###
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInputs": "",
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is True

    # additional input is invalid
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInputs": "i can not be decoded in json!",
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == "Additional input is invalid or can not be decoded."

    # Missing did in additional input
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInputs": [{"transferTxId": tx_id, "serviceId": sa.index}],
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert validator.error == "Error in input at index 1: No documentId in input item."

    # Did is not valid
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInputs": [
            {
                "documentId": "i am not a did",
                "transferTxId": tx_id,
                "serviceId": sa.index,
            }
        ],
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "Error in input at index 1: Asset for did i am not a did not found."
    )

    # Service is not compute, nor access
    other_service = [
        s
        for s in dataset.services
        if s.type not in [ServiceTypes.CLOUD_COMPUTE, ServiceTypes.ASSET_ACCESS]
    ][0]
    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInputs": [
            {"documentId": did, "transferTxId": tx_id, "serviceId": other_service.index}
        ],
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == "Error in input at index 1: Services in input can only be access or compute."
    )

    # Additional input has other trusted algs
    trust_ddo, trust_tx_id, _, _ = build_and_send_ddo_with_compute_service(
        client, publisher_wallet, consumer_wallet, asset_type="specific_algo_dids"
    )
    trust_sa = trust_ddo.get_service(ServiceTypes.CLOUD_COMPUTE)

    data = {
        "documentId": did,
        "transferTxId": tx_id,
        "serviceId": sa.index,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInputs": [
            {
                "documentId": trust_ddo.did,
                "transferTxId": trust_tx_id,
                "serviceId": trust_sa.index,
            }
        ],
    }

    validator = WorkflowValidator(consumer_address, provider_wallet, data)
    assert validator.validate() is False
    assert (
        validator.error
        == f"Error in input at index 1: this algorithm did {alg_ddo.did} is not trusted."
    )
