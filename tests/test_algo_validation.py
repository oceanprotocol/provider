#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

from ocean_provider.util import build_stage_output_dict
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.validation.algo import AlgoValidator
from ocean_utils.agreements.service_types import ServiceTypes
from tests.test_helpers import (
    build_and_send_ddo_with_compute_service,
    get_consumer_wallet,
    get_publisher_wallet,
)


def test_passes(client):
    provider_wallet = get_provider_wallet()
    consumer_address = get_consumer_wallet().address
    pub_wallet = get_publisher_wallet()

    (
        dataset,
        did,
        _,
        sa,
        _,
        alg_ddo,
        alg_data_token,
        _,
        alg_tx_id,
    ) = build_and_send_ddo_with_compute_service(client)

    data = {
        "documentId": did,
        "output": build_stage_output_dict(
            dict(), dataset, consumer_address, pub_wallet
        ),
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is True

    data = {
        "output": build_stage_output_dict(
            dict(), dataset, consumer_address, pub_wallet
        ),
        "algorithmMeta": {
            "rawcode": "console.log('Hello world'!)",
            "format": "docker-image",
            "version": "0.1",
            "container": {"entrypoint": "node $ALGO", "image": "node", "tag": "10"},
        },
    }
    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is True


def test_fails(client):
    provider_wallet = get_provider_wallet()
    consumer_address = get_consumer_wallet().address
    pub_wallet = get_publisher_wallet()

    (
        dataset,
        did,
        tx_id,
        sa,
        data_token,
        alg_ddo,
        alg_data_token,
        alg_dt_contract,
        alg_tx_id,
    ) = build_and_send_ddo_with_compute_service(client)

    # output key is invalid
    data = {
        "output": "this can not be decoded",
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is False
    assert validator.error == "Output is invalid or can not be decoded."

    # algorithmDid is not actually an algorithm
    data = {
        "output": build_stage_output_dict(
            dict(), dataset, consumer_address, pub_wallet
        ),
        "algorithmDid": did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is False
    assert validator.error == f"DID {did} is not a valid algorithm"

    valid_output = build_stage_output_dict(
        dict(), dataset, consumer_address, pub_wallet
    )

    # algorithmMeta doesn't contain 'url' or 'rawcode'
    data = {"output": valid_output, "algorithmMeta": {}}

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithmMeta must define one of `url` or `rawcode` or `remote`, but all seem missing."
    )

    # algorithmMeta container is empty
    data = {
        "output": valid_output,
        "algorithmMeta": {
            "rawcode": "console.log('Hello world'!)",
            "format": "docker-image",
            "version": "0.1",
            "container": {},
        },
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithm `container` must specify values for all of entrypoint, image and tag."
    )

    # algorithmMeta container is missing image
    data = {
        "output": valid_output,
        "algorithmMeta": {
            "rawcode": "console.log('Hello world'!)",
            "format": "docker-image",
            "version": "0.1",
            "container": {"entrypoint": "node $ALGO", "tag": "10"},
        },
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is False
    assert (
        validator.error
        == "algorithm `container` must specify values for all of entrypoint, image and tag."
    )

    # Additional Input validations ###
    data = {
        "documentId": did,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInput": "",
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is True

    # Missing did in additional input
    data = {
        "documentId": did,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInput": [{"transferTxId": tx_id, "serviceId": sa.index}],
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is False
    assert (
        validator.error
        == "Error in additionalInput at index 0: No did in additionalInput."
    )

    # Did is not valid
    data = {
        "documentId": did,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInput": [
            {"did": "i am not a did", "transferTxId": tx_id, "serviceId": sa.index}
        ],
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is False
    assert (
        validator.error
        == "Error in additionalInput at index 0: Asset for did i am not a did not found."
    )

    # Service is not compute, nor access
    other_service = [
        s
        for s in dataset.services
        if s.type not in [ServiceTypes.CLOUD_COMPUTE, ServiceTypes.ASSET_ACCESS]
    ][0]
    data = {
        "documentId": did,
        "output": valid_output,
        "algorithmDid": alg_ddo.did,
        "algorithmDataToken": alg_data_token,
        "algorithmTransferTxId": alg_tx_id,
        "additionalInput": [
            {"did": did, "transferTxId": tx_id, "serviceId": other_service.index}
        ],
    }

    validator = AlgoValidator(consumer_address, provider_wallet, data, sa, dataset)
    assert validator.validate() is False
    assert (
        validator.error
        == "Error in additionalInput at index 0: Services in additionalInput can only be access or compute."
    )
