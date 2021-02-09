#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0
import json
import logging

from eth_utils import add_0x_prefix
from flask import Response, jsonify, request
from flask_sieve import validate
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_lib.web3_internal.web3helper import Web3Helper
from ocean_provider.log import setup_logging
from ocean_provider.user_nonce import increment_nonce
from ocean_provider.util import (
    get_compute_endpoint,
    get_request_data,
    process_compute_request,
    process_consume_request,
    record_consume_request,
    validate_order,
    validate_transfer_not_used_for_other_service,
)
from ocean_provider.utils.basics import (
    LocalFileAdapter,
    get_provider_wallet,
    setup_network,
)
from ocean_provider.validation.algo import AlgoValidator
from ocean_provider.validation.requests import (
    ComputeRequest,
    ComputeStartRequest,
    UnsignedComputeRequest,
)
from ocean_utils.agreements.service_types import ServiceTypes
from ocean_utils.did import did_to_id
from ocean_utils.http_requests.requests_session import get_requests_session

from . import services

setup_logging()
setup_network()
provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)


@services.route("/compute", methods=["DELETE"])
@validate(ComputeRequest)
def computeDelete():
    """Deletes a workflow.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: signature
        in: query
        description: Signature of the documentId to verify that the consumer has rights to download the asset.
        type: string
      - name: documentId
        in: query
        description: The ID of the asset
        required: true
        type: string
      - name: consumerAddress
        in: query
        description: The consumer address.
        required: true
        type: string
      - name: jobId
        in: query
        description: JobId.
        type: string
    responses:
      200:
        description: Call to the operator-service was successful.
      400:
        description: One of the required attributes is missing.
      401:
        description: Invalid asset data.
      500:
        description: Error
    """
    data = get_request_data(request)
    try:
        body = process_compute_request(data)
        response = requests_session.delete(
            get_compute_endpoint(),
            params=body,
            headers={"content-type": "application/json"},
        )
        increment_nonce(body["owner"])
        return Response(
            response.content,
            response.status_code,
            headers={"content-type": "application/json"},
        )
    except (ValueError, Exception) as e:
        logger.error(f"Error- {str(e)}", exc_info=1)
        return jsonify(error=f"Error : {str(e)}"), 500


@services.route("/compute", methods=["PUT"])
@validate(ComputeRequest)
def computeStop():
    """Stop the execution of a workflow.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: signature
        in: query
        description: Signature of (consumerAddress+jobId+documentId) to verify the consumer of
            this compute job/asset. The signature uses ethereum based signing method
            (see https://github.com/ethereum/EIPs/pull/683)
        type: string
      - name: documentId
        in: query
        description: The ID of the asset. If not provided, all currently running compute
            jobs will be stopped for the specified consumerAddress
        required: true
        type: string
      - name: consumerAddress
        in: query
        description: The consumer ethereum address.
        required: true
        type: string
      - name: jobId
        in: query
        description: The ID of the compute job. If not provided, all running compute jobs of
            the specified consumerAddress/documentId are suspended
        type: string
    responses:
      200:
        description: Call to the operator-service was successful.
      400:
        description: One of the required attributes is missing.
      401:
        description: Consumer signature is invalid or failed verification.
      500:
        description: General server error
    """
    data = get_request_data(request)
    try:
        body = process_compute_request(data)
        response = requests_session.put(
            get_compute_endpoint(),
            params=body,
            headers={"content-type": "application/json"},
        )
        increment_nonce(body["owner"])
        return Response(
            response.content,
            response.status_code,
            headers={"content-type": "application/json"},
        )
    except (ValueError, Exception) as e:
        logger.error(f"Error- {str(e)}", exc_info=1)
        return jsonify(error=f"Error : {str(e)}"), 500


@services.route("/compute", methods=["GET"])
@validate(UnsignedComputeRequest)
def computeStatus():
    """Get status for a specific jobId/documentId/owner

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: signature
        in: query
        description: Signature of (consumerAddress+jobId+documentId) to verify the consumer of
            this asset/compute job. The signature uses ethereum based signing method
            (see https://github.com/ethereum/EIPs/pull/683)
        type: string
      - name: documentId
        in: query
        description: The ID of the asset. If not provided, the status of all
            currently running and old compute jobs for the specified consumerAddress will be returned.
        required: true
        type: string
      - name: consumerAddress
        in: query
        description: The consumer ethereum address.
        required: true
        type: string
      - name: jobId
        in: query
        description: The ID of the compute job. If not provided, all running compute jobs of
            the specified consumerAddress/documentId are suspended
        type: string

    responses:
      200:
        description: Call to the operator-service was successful.
      400:
        description: One of the required attributes is missing.
      401:
        description: Consumer signature is invalid or failed verification.
      500:
        description: General server error
    """
    data = get_request_data(request)
    try:
        body = process_compute_request(data)
        signed_request = bool(data.get("signature"))

        response = requests_session.get(
            get_compute_endpoint(),
            params=body,
            headers={"content-type": "application/json"},
        )

        increment_nonce(body["owner"])
        _response = response.content
        # Filter status info if signature is not given or failed validation
        if not signed_request:
            resp_content = json.loads(response.content.decode("utf-8"))
            if not isinstance(resp_content, list):
                resp_content = [resp_content]
            _response = []
            keys_to_filter = ["resultsUrl", "algorithmLogUrl", "resultsDid", "owner"]
            for job_info in resp_content:
                for k in keys_to_filter:
                    job_info.pop(k)
                _response.append(job_info)

            _response = json.dumps(_response)

        return Response(
            _response,
            response.status_code,
            headers={"content-type": "application/json"},
        )

    except (ValueError, Exception) as e:
        logger.error(f"Error- {str(e)}", exc_info=1)
        return jsonify(error=f"Error : {str(e)}"), 500


@services.route("/compute", methods=["POST"])
@validate(ComputeStartRequest)
def computeStart():
    """Call the execution of a workflow.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: signature
        in: query
        description: Signature of (consumerAddress+jobId+documentId) to verify the consumer of
            this asset/compute job. The signature uses ethereum based signing method
            (see https://github.com/ethereum/EIPs/pull/683)
        type: string
      - name: consumerAddress
        in: query
        description: The consumer ethereum address.
        required: true
        type: string

      - name: algorithmDid
        in: query
        description: The DID of the algorithm Asset to be executed
        required: false
        type: string
      - name: algorithmMeta
        in: query
        description: json object that define the algorithm attributes and url or raw code
        required: false
        type: json string
      - name: output
        in: query
        description: json object that define the output section
        required: true
        type: json string
    responses:
      200:
        description: Call to the operator-service was successful.
      400:
        description: One of the required attributes is missing.
      401:
        description: Consumer signature is invalid or failed verification
      500:
        description: General server error
    """
    data = get_request_data(request)

    try:
        (
            asset,
            service,
            did,
            consumer_address,
            token_address,
        ) = process_consume_request(data)

        service_id = data.get("serviceId")
        service_type = data.get("serviceType")
        tx_id = data.get("transferTxId")

        # Verify that  the number of required tokens has been
        # transferred to the provider's wallet.

        _tx, _order_log, _transfer_log = validate_order(
            consumer_address,
            token_address,
            float(service.get_cost()),
            tx_id,
            add_0x_prefix(did_to_id(did)) if did.startswith("did:") else did,
            service_id,
        )
        validate_transfer_not_used_for_other_service(
            did, service_id, tx_id, consumer_address, token_address
        )
        record_consume_request(
            did, service_id, tx_id, consumer_address, token_address, service.get_cost()
        )

        assert service_type == ServiceTypes.CLOUD_COMPUTE

        validator = AlgoValidator(
            consumer_address, provider_wallet, data, service, asset
        )

        status = validator.validate()
        if not status:
            return jsonify(error=validator.error), 400

        stages = list([validator.stage] + validator.additional_stages)

        #########################
        # WORKFLOW
        workflow = dict({"stages": stages})

        # workflow is ready, push it to operator
        logger.info("Sending: %s", workflow)

        msg_to_sign = f"{provider_wallet.address}{did}"
        msg_hash = add_ethereum_prefix_and_hash_msg(msg_to_sign)
        payload = {
            "workflow": workflow,
            "providerSignature": Web3Helper.sign_hash(msg_hash, provider_wallet),
            "documentId": did,
            "agreementId": tx_id,
            "owner": consumer_address,
            "providerAddress": provider_wallet.address,
        }
        response = requests_session.post(
            get_compute_endpoint(),
            data=json.dumps(payload),
            headers={"content-type": "application/json"},
        )
        increment_nonce(consumer_address)
        return Response(
            response.content,
            response.status_code,
            headers={"content-type": "application/json"},
        )
    except (ValueError, KeyError, Exception) as e:
        logger.error(f"Error- {str(e)}", exc_info=1)
        return jsonify(error=f"Error : {str(e)}"), 500
