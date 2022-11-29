#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import functools
import json
import logging
import os

import flask
from flask import Response, jsonify, request
from flask_sieve import validate
from ocean_provider.file_types.file_types_factory import FilesTypeFactory
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import update_nonce
from ocean_provider.utils.asset import get_asset_from_metadatastore
from ocean_provider.utils.basics import (
    get_metadata_url,
    get_provider_wallet,
    get_web3,
    validate_timestamp,
)
from ocean_provider.utils.compute import (
    get_compute_endpoint,
    get_compute_result_endpoint,
    process_compute_request,
    sign_for_compute,
)
from ocean_provider.utils.compute_environments import (
    check_environment_exists,
    get_c2d_environments,
)
from ocean_provider.utils.error_responses import error_response
from ocean_provider.utils.provider_fees import (
    comb_for_valid_transfer_and_fees,
    get_provider_fees_or_remote,
)
from ocean_provider.utils.util import get_request_data
from ocean_provider.validation.algo import (
    InputItemValidator,
    WorkflowValidator,
    get_algo_checksums,
)
from ocean_provider.validation.images import validate_container
from ocean_provider.validation.provider_requests import (
    ComputeGetResult,
    ComputeRequest,
    ComputeStartRequest,
    InitializeComputeRequest,
    UnsignedComputeRequest,
)
from requests.models import PreparedRequest

from . import services

requests_session = get_requests_session()

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "application/json", "Connection": "close"}


def validate_compute_request(f):
    @functools.wraps(f)
    def decorated_function(*args, **kws):
        # refuse compute requests for download-only providers
        if not os.getenv("OPERATOR_SERVICE_URL"):
            flask.abort(404)

        return f(*args, **kws)

    return decorated_function


@services.route("/initializeCompute", methods=["POST"])
@validate(InitializeComputeRequest)
def initializeCompute():
    """Initialize a compute service request, with possible additional access requests.
    In order to consume a data service the user is required to send
    one datatoken to the provider, as well as provider fees for the compute job.

    The datatoken is transferred via the ethereum blockchain network
    by requesting the user to sign an ERC20 approval transaction
    where the approval is given to the provider's ethereum account for
    the number of tokens required by the service.

    Accepts a payload similar to startCompute: a list of datasets (json object),
    algorithm (algorithm description object), validUntil and env parameters.
    Adding a transferTxId value to a dataset object will attempt to reuse that order
    and return renewed provider fees if necessary.

    responses:
      400:
        description: One or more of the required attributes are missing or invalid.
      503:
        description: Service Unavailable.

    return:
        json object as follows:
        ```JSON
        {
            "datatoken": <data-token-contract-address>,
            "providerFee": <object containing provider fees>,
            "validOrder": <validated transfer if order can be reused.>
        }
        ```
    """
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

    if not check_environment_exists(get_c2d_environments(flat=True), compute_env):
        return error_response("Compute environment does not exist", 400, logger)

    approve_params = {"datasets": []} if datasets else {}

    index_for_provider_fees = comb_for_valid_transfer_and_fees(
        datasets + [algorithm], compute_env
    )

    algo_files_checksum = None
    algo_container_checksum = None

    if algorithm.get("documentId"):
        algo_ddo = get_asset_from_metadatastore(
            get_metadata_url(), algorithm.get("documentId")
        )

        try:
            asset_type = algo_ddo.metadata["type"]
        except ValueError:
            asset_type = None

        if asset_type != "algorithm":
            return error_response("DID is not a valid algorithm", 400, logger)

        algo_service = algo_ddo.get_service_by_id(algorithm.get("serviceId"))
        provider_wallet = get_provider_wallet(algo_ddo.chain_id)
        algo_files_checksum, algo_container_checksum = get_algo_checksums(
            algo_service, provider_wallet, algo_ddo
        )

    for i, dataset in enumerate(datasets):
        dataset["algorithm"] = algorithm
        dataset["consumerAddress"] = consumer_address
        input_item_validator = InputItemValidator(
            consumer_address,
            dataset,
            {"environment": compute_env},
            i,
            check_usage=False,
        )
        input_item_validator.algo_files_checksum = algo_files_checksum
        input_item_validator.algo_container_checksum = algo_container_checksum
        status = input_item_validator.validate()
        if not status:
            return error_response(
                {input_item_validator.resource: input_item_validator.message},
                400,
                logger,
            )

        service = input_item_validator.service

        approve_params["datasets"].append(
            get_provider_fees_or_remote(
                input_item_validator.asset,
                service,
                consumer_address,
                valid_until,
                compute_env,
                (i != index_for_provider_fees),
                dataset,
            )
        )

    if algorithm.get("documentId"):
        algorithm["consumerAddress"] = consumer_address
        approve_params["algorithm"] = get_provider_fees_or_remote(
            algo_ddo,
            algo_service,
            consumer_address,
            valid_until,
            compute_env,
            (index_for_provider_fees != len(datasets)),
            algorithm,
        )

    return jsonify(approve_params), 200


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
        description: One or more of the required attributes are missing or invalid.
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
        description: One or more of the required attributes are missing or invallid.
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
        description: One or more of the required attributes are missing or invalid.
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
        description: json object that defines the output section
        required: true
        type: json string
    responses:
      200:
        description: Call to the operator-service was successful.
      400:
        description: One or more of the required attributes are missing or invalid.
      401:
        description: Consumer signature is invalid or failed verification
      503:
        description: Service unavailable
    """
    data = request.json
    logger.info(f"computeStart called. arguments = {data}")

    consumer_address = data.get("consumerAddress")
    validator = WorkflowValidator(consumer_address, data)

    status = validator.validate()
    if not status:
        return error_response({validator.resource: validator.message}, 400, logger)

    workflow = validator.workflow
    # workflow is ready, push it to operator
    logger.debug("Sending: %s", workflow)

    compute_env = data.get("environment")

    provider_wallet = get_provider_wallet(use_universal_key=True)
    nonce, provider_signature = sign_for_compute(provider_wallet, consumer_address)
    payload = {
        "workflow": workflow,
        "providerSignature": provider_signature,
        "agreementId": validator.agreement_id,
        "owner": consumer_address,
        "providerAddress": provider_wallet.address,
        "environment": compute_env,
        "validUntil": validator.valid_until,
        "nonce": nonce,
        "chainId": validator.chain_id,
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
    """Allows download of asset data result file.

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
        description: jobId
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
        description: One or more of the required attributes are missing or invalid.
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
    provider_wallet = get_provider_wallet(use_universal_key=True)
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

    _, instance = FilesTypeFactory.validate_and_create(
        {"url": result_url, "type": "url"},
    )
    response = instance.build_download_response(
        request,
        validate_url=False,
    )
    logger.info(f"computeResult response = {response}")

    return response


@services.route("/computeEnvironments", methods=["GET"])
@validate_compute_request
def computeEnvironments():
    """Get list of compute environments

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
    return: list of objects containing information about each compute environment
    """

    response = jsonify(get_c2d_environments())
    response.status_code = 200
    response.headers = standard_headers

    return response


@services.route("/validateContainer", methods=["POST"])
def validateContainer():
    container = get_request_data(request)
    valid, messages = validate_container(container)

    if not valid:
        return error_response(messages, 400, logger)

    return container, 200
