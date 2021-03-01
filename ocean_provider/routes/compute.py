#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging

from flask import Response, jsonify, request
from flask_sieve import validate
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_lib.web3_internal.web3helper import Web3Helper
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.log import setup_logging
from ocean_provider.user_nonce import get_nonce, increment_nonce
from ocean_provider.util import (
    get_compute_endpoint,
    get_request_data,
    process_compute_request,
)
from ocean_provider.utils.accounts import verify_signature
from ocean_provider.utils.basics import (
    LocalFileAdapter,
    get_provider_wallet,
    setup_network,
)
from ocean_provider.validation.algo import WorkflowValidator
from ocean_provider.validation.requests import (
    ComputeRequest,
    ComputeStartRequest,
    UnsignedComputeRequest,
)
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

        response = requests_session.get(
            get_compute_endpoint(),
            params=body,
            headers={"content-type": "application/json"},
        )

        increment_nonce(body["owner"])
        _response = response.content

        signed_request = bool(data.get("signature"))
        if signed_request:
            owner = data.get("consumerAddress")
            did = data.get("documentId")
            jobId = data.get("jobId")
            original_msg = f"{owner}{jobId}{did}"
            try:
                verify_signature(
                    owner, data.get("signature"), original_msg, get_nonce(owner)
                )
            except InvalidSignatureError:
                signed_request = False

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
        consumer_address = data.get("consumerAddress")
        validator = WorkflowValidator(consumer_address, provider_wallet, data)

        status = validator.validate()
        if not status:
            return jsonify(error=validator.error), 400

        workflow = validator.workflow
        # workflow is ready, push it to operator
        logger.info("Sending: %s", workflow)

        tx_id = data.get("transferTxId")
        did = data.get("documentId")

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
