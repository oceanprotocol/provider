#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging

from flask import Response, request
from flask_sieve import validate
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import update_nonce
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.basics import LocalFileAdapter, get_provider_wallet, get_web3
from ocean_provider.utils.error_responses import error_response, service_unavailable
from ocean_provider.utils.provider_fees import get_c2d_enviroments
from ocean_provider.utils.util import (
    build_download_response,
    get_compute_endpoint,
    get_compute_result_endpoint,
    get_request_data,
    process_compute_request,
)
from ocean_provider.validation.algo import WorkflowValidator
from ocean_provider.validation.provider_requests import (
    ComputeGetResult,
    ComputeRequest,
    ComputeStartRequest,
    UnsignedComputeRequest,
)
from requests.models import PreparedRequest

from . import services

provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "application/json", "Connection": "close"}


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
      503:
        description: Service Unavailable
    """
    data = get_request_data(request)
    logger.info(f"computeDelete called. arguments = {data}")
    try:
        body = process_compute_request(data)
        response = requests_session.delete(
            get_compute_endpoint(), params=body, headers=standard_headers
        )
        update_nonce(body["owner"], data.get("nonce"))

        response = Response(
            response.content, response.status_code, headers=standard_headers
        )
        logger.info(f"computeDelete response = {response}")
        return response
    except (ValueError, Exception) as e:
        return service_unavailable(e, data, logger)


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
      503:
        description: Service unavailable
    """
    data = get_request_data(request)
    logger.info(f"computeStop called. arguments = {data}")
    try:
        body = process_compute_request(data)
        response = requests_session.put(
            get_compute_endpoint(), params=body, headers=standard_headers
        )
        update_nonce(body["owner"], data.get("nonce"))

        response = Response(
            response.content, response.status_code, headers=standard_headers
        )
        logger.info(f"computeStop response = {response}")
        return response
    except (ValueError, Exception) as e:
        return service_unavailable(e, data, logger)


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
      - name: jobId
        in: query
        description: The ID of the compute job. If not provided, all running compute jobs of
            the specified consumerAddress/documentId are suspended
        type: string
        required: true
      - name: documentId
        in: query
        description: The ID of the asset. If not provided, the status of all
            currently running and old compute jobs for the specified consumerAddress will be returned.
        type: string
      - name: consumerAddress
        in: query
        description: The consumer ethereum address.
        required: true
        type: string

    responses:
      200:
        description: Call to the operator-service was successful.
      400:
        description: One of the required attributes is missing.
      401:
        description: Consumer signature is invalid or failed verification.
      503:
        description: Service Unavailable
    """
    data = get_request_data(request)
    logger.info(f"computeStatus called. arguments = {data}")
    try:
        body = process_compute_request(data)

        response = requests_session.get(
            get_compute_endpoint(), params=body, headers=standard_headers
        )

        _response = Response(
            response.content, response.status_code, headers=standard_headers
        )
        logger.info(f"computeStatus response = {_response}")
        return _response

    except (ValueError, Exception) as e:
        return service_unavailable(e, data, logger)


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
      - name: algorithmServiceId
        in: query
        description: the id of the service to use to process the algorithm
        required: true
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
      503:
        description: Service unavailable
    """
    data = request.json
    logger.info(f"computeStart called. arguments = {data}")

    try:
        consumer_address = data.get("consumerAddress")
        validator = WorkflowValidator(
            get_web3(), consumer_address, provider_wallet, data
        )

        status = validator.validate()
        if not status:
            return error_response(validator.error, 400, logger)

        workflow = validator.workflow
        # workflow is ready, push it to operator
        logger.info("Sending: %s", workflow)

        tx_id = data.get("transferTxId")
        did = data.get("documentId")

        msg_to_sign = f"{provider_wallet.address}{did}"

        payload = {
            "workflow": workflow,
            "providerSignature": sign_message(msg_to_sign, provider_wallet),
            "documentId": did,
            "agreementId": tx_id,
            "owner": consumer_address,
            "providerAddress": provider_wallet.address,
        }
        response = requests_session.post(
            get_compute_endpoint(), data=json.dumps(payload), headers=standard_headers
        )
        update_nonce(consumer_address, data.get("nonce"))

        response = Response(
            response.content, response.status_code, headers=standard_headers
        )
        logger.info(f"computeStart response = {response}")
        return response
    except (ValueError, KeyError, Exception) as e:
        return service_unavailable(e, data, logger)


@services.route("/computeResult", methods=["GET"])
@validate(ComputeGetResult)
def computeResult():
    """Allows download of asset data file.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: consumerAddress
        in: query
        description: The consumer address.
        required: true
        type: string
      - name: jobId
        in: query
        description: JobId
        required: true
        type: string
      - name: index
        in: query
        description: Result index
        required: true
      - name: signature
        in: query
        description: Signature of (consumerAddress+jobId+index+nonce) to verify that the consumer has rights to download the result
    responses:
      200:
        description: Content of the result
      400:
        description: One of the required attributes is missing.
      404:
        description: Result not found
      503:
        description: Service Unavailable
    """
    data = get_request_data(request)
    logger.info(f"computeResult called. arguments = {data}")
    try:
        url = get_compute_result_endpoint()
        msg_to_sign = (
            f"{data.get('jobId')}{data.get('index')}{data.get('consumerAddress')}"
        )
        # we sign the same message as consumer does, but using our key
        provider_signature = sign_message(msg_to_sign, provider_wallet)
        params = {
            "index": data.get("index"),
            "consumerAddress": data.get("consumerAddress"),
            "jobId": data.get("jobId"),
            "consumerSignature": data.get("signature"),
            "providerSignature": provider_signature,
        }
        req = PreparedRequest()
        req.prepare_url(url, params)
        result_url = req.url
        logger.debug(f"Done processing computeResult, url: {result_url}")
        update_nonce(data.get("consumerAddress"), data.get("nonce"))

        response = build_download_response(
            request, requests_session, result_url, result_url, None
        )
        logger.info(f"computeResult response = {response}")
        return response
    except Exception as e:
        return service_unavailable(
            e,
            {
                "jobId": data.get("jobId"),
                "index": data.get("index"),
                "consumerAddress": data.get("consumerAddress"),
            },
            logger,
        )


@services.route("/computeEnviroments", methods=["GET"])
def computeEnviroments():
    """Get compute enviroments

    ---
    tags:
      - services
    consumes:
      - application/json

    responses:
      200:
        description: Call to the operator-service was successful.
      503:
        description: Service Unavailable
    """
    response = Response(get_c2d_enviroments(), 200, headers=standard_headers)
    return response
