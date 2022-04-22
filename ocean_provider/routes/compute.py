#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import functools
import json
import logging
import os
from datetime import datetime

import flask
from flask import Response, jsonify, request
from flask_sieve import validate
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import update_nonce
from ocean_provider.utils.basics import (
    LocalFileAdapter,
    get_provider_wallet,
    get_web3,
    validate_timestamp,
    get_asset_from_metadatastore,
)
from ocean_provider.utils.error_responses import error_response
from ocean_provider.utils.provider_fees import (
    get_c2d_environments,
    get_provider_fees_or_remote,
)
from ocean_provider.utils.util import (
    build_download_response,
    check_environment_exists,
    get_compute_endpoint,
    get_compute_result_endpoint,
    get_metadata_url,
    get_request_data,
    process_compute_request,
    sign_for_compute,
)
from ocean_provider.validation.algo import WorkflowValidator, InputItemValidator
from ocean_provider.validation.provider_requests import (
    ComputeGetResult,
    ComputeRequest,
    ComputeStartRequest,
    InitializeComputeRequest,
    UnsignedComputeRequest,
)
from requests.models import PreparedRequest

from . import services

provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "application/json", "Connection": "close"}


def validate_compute_request(f):
    @functools.wraps(f)
    def decorated_function(*args, **kws):
        # Do something with your request here
        if not os.getenv("OPERATOR_SERVICE_URL"):
            flask.abort(404)

        return f(*args, **kws)

    return decorated_function


@services.route("/initializeCompute", methods=["POST"])
@validate(InitializeComputeRequest)
def initializeCompute():
    data = get_request_data(request)
    logger.info(f"initializeCompute called. arguments = {data}")

    datasets = data.get("datasets")
    algorithm = data["algorithm"]
    compute_env = data["compute"]["env"]
    valid_until = data["compute"]["validUntil"]
    consumer_address = data.get("consumerAddress")

    timestamp_ok = validate_timestamp(valid_until)
    valid_until = int(valid_until)

    if not timestamp_ok:
        return error_response(
            "The validUntil value is not correct.",
            400,
            logger,
        )

    if not check_environment_exists(get_c2d_environments(), compute_env):
        return error_response("Compute environment does not exist", 400, logger)

    web3 = get_web3()
    approve_params = {"datasets": []} if datasets else {}

    for i, dataset in enumerate(datasets):
        dataset["algorithm"] = algorithm
        input_item_validator = InputItemValidator(
            web3,
            consumer_address,
            provider_wallet,
            dataset,
            {"environment": compute_env},
            i,
            check_usage=False,
        )
        status = input_item_validator.validate()
        if not status:
            prefix = f"Error in input at index {i}: "
            return error_response(prefix + input_item_validator.error, 400, logger)

        service = input_item_validator.service
        did = input_item_validator.did

        approve_params["datasets"].append(
            get_provider_fees_or_remote(
                did,
                service,
                consumer_address,
                valid_until,
                compute_env,
                bool(i),
                dataset,
            )
        )

    if algorithm.get("documentId"):
        algo = get_asset_from_metadatastore(
            get_metadata_url(), algorithm.get("documentId")
        )

        try:
            asset_type = algo.metadata["type"]
        except ValueError:
            asset_type = None

        if asset_type != "algorithm":
            return error_response("DID is not a valid algorithm", 400, logger)

        algo_service = algo.get_service_by_id(algorithm.get("serviceId"))
        approve_params["algorithm"] = get_provider_fees_or_remote(
            algorithm.get("documentId"),
            algo_service,
            consumer_address,
            valid_until,
            compute_env,
            True,
            algorithm,
        )

    return jsonify(approve_params), 200
    # TODO: handle order reused


@services.route("/compute", methods=["DELETE"])
@validate_compute_request
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


@services.route("/compute", methods=["PUT"])
@validate_compute_request
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


@services.route("/compute", methods=["GET"])
@validate_compute_request
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

    body = process_compute_request(data)

    response = requests_session.get(
        get_compute_endpoint(), params=body, headers=standard_headers
    )

    _response = Response(
        response.content, response.status_code, headers=standard_headers
    )
    logger.info(f"computeStatus response = {_response}")
    return _response


@services.route("/compute", methods=["POST"])
@validate_compute_request
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
      - name: computeEnv
        in: query
        description: Compute Environment
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

    consumer_address = data.get("consumerAddress")
    validator = WorkflowValidator(get_web3(), consumer_address, provider_wallet, data)

    status = validator.validate()
    if not status:
        return error_response(validator.error, 400, logger)

    workflow = validator.workflow
    # workflow is ready, push it to operator
    logger.debug("Sending: %s", workflow)

    compute_env = data.get("environment")
    seconds = (
        datetime.fromtimestamp(validator.valid_until) - datetime.utcnow()
    ).seconds

    nonce, provider_signature = sign_for_compute(provider_wallet, consumer_address)
    web3 = get_web3()
    payload = {
        "workflow": workflow,
        "providerSignature": provider_signature,
        "agreementId": data["dataset"]["transferTxId"],
        "owner": consumer_address,
        "providerAddress": provider_wallet.address,
        "environment": compute_env,
        "maxDuration": seconds,
        "nonce": nonce,
        "chainId": web3.chain_id,
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


@services.route("/computeResult", methods=["GET"])
@validate_compute_request
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
      - name: nonce
        in: query
        description: The UTC timestamp, used to prevent replay attacks
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

    url = get_compute_result_endpoint()
    consumer_address = data.get("consumerAddress")
    job_id = data.get("jobId")
    nonce, provider_signature = sign_for_compute(
        provider_wallet, consumer_address, job_id
    )
    web3 = get_web3()
    params = {
        "index": data.get("index"),
        "owner": data.get("consumerAddress"),
        "jobId": job_id,
        "consumerSignature": data.get("signature"),
        "providerSignature": provider_signature,
        "nonce": nonce,
        "chainId": web3.chain_id,
    }
    req = PreparedRequest()
    req.prepare_url(url, params)
    result_url = req.url
    logger.debug(f"Done processing computeResult, url: {result_url}")
    update_nonce(data.get("consumerAddress"), data.get("nonce"))

    response = build_download_response(
        request, requests_session, result_url, result_url, None, validate_url=False
    )
    logger.info(f"computeResult response = {response}")

    return response


@services.route("/computeEnvironments", methods=["GET"])
@validate_compute_request
def computeEnvironments():
    """Get compute environments

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

    response = jsonify(get_c2d_environments())
    response.status_code = 200
    response.headers = standard_headers

    return response
