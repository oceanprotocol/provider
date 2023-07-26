#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
from datetime import datetime, timezone

from flask import jsonify, request
from flask_sieve import validate
from ocean_provider.file_types.file_types_factory import FilesTypeFactory
from ocean_provider.requests_session import get_requests_session
from ocean_provider.routes import services
from ocean_provider.user_nonce import get_nonce, update_nonce
from ocean_provider.utils.asset import (
    check_asset_consumable,
    get_asset_from_metadatastore,
)
from ocean_provider.utils.basics import get_metadata_url, get_provider_wallet, get_web3
from ocean_provider.utils.datatoken import validate_order
from ocean_provider.utils.error_responses import error_response
from ocean_provider.utils.proof import send_proof
from ocean_provider.utils.provider_fees import get_c2d_environments, get_provider_fees
from ocean_provider.utils.services import ServiceType
from ocean_provider.utils.util import get_request_data, get_service_files_list
from ocean_provider.validation.provider_requests import (
    DownloadRequest,
    FileInfoRequest,
    InitializeRequest,
    NonceRequest,
)
from web3.main import Web3

requests_session = get_requests_session()

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "application/json", "Connection": "close"}


@services.route("/nonce", methods=["GET"])
@validate(NonceRequest)
def nonce():
    """Returns a decimal `nonce` for the given account address.

    ---
    tags:
      - consume
    consumes:
      - application/json
    parameters:
      - name: userAddress
        description: The address of the account
        required: true
        type: string
    responses:
      200:
        description: nonce returned

    return: nonce for user address
    """
    logger.info("nonce endpoint called")
    data = get_request_data(request)
    address = data.get("userAddress")
    nonce = get_nonce(address)

    if not nonce:
        new_nonce = 1
        update_nonce(address, new_nonce)
        nonce = get_nonce(address)
        assert int(nonce) == new_nonce, "New nonce could not be stored correctly."

    logger.info(f"nonce for user {address} is {nonce}")

    response = jsonify(nonce=int(nonce)), 200
    logger.info(f"nonce response = {response}")

    return response


@services.route("/fileinfo", methods=["POST"])
@validate(FileInfoRequest)
def fileinfo():
    """Retrieves Content-Type and Content-Length from the given URL or asset. Supports a payload of either url or did.
    This can be used by the publisher of an asset to check basic information
    about the URL(s). For now, this information consists of the Content-Type
    and Content-Length of the request, using primarily OPTIONS, with fallback
    to GET. In the future, we will add a hash to make sure that the file was
    not tampered with at consumption time.

    ---
    tags:
      - consume

    responses:
      200:
        description: the URL(s) could be analysed (returns the result).
      400:
        description: the URL(s) could not be analysed (bad request).
      503:
        description: Service Unavailable.

    return: list of file info (index, valid, contentLength, contentType)
    """
    data = get_request_data(request)
    logger.debug(f"fileinfo called. arguments = {data}")
    did = data.get("did")
    service_id = data.get("serviceId")

    if did:
        asset = get_asset_from_metadatastore(get_metadata_url(), did)
        if not asset:
            return error_response(
                "Cannot resolve DID",
                400,
                logger,
            )
        service = asset.get_service_by_id(service_id)
        if not service:
            return error_response(
                "Invalid serviceId.",
                400,
                logger,
            )
        provider_wallet = get_provider_wallet(asset.chain_id)
        files_list = get_service_files_list(service, provider_wallet, asset)
        if not files_list:
            return error_response("Unable to get dataset files", 400, logger)
    else:
        files_list = [data]

    with_checksum = data.get("checksum", False)

    files_info = []
    for i, file in enumerate(files_list):
        file["userdata"] = data.get("userdata")
        logger.debug(f"Validating :{file}")
        valid, message = FilesTypeFactory.validate_and_create(file)
        if not valid:
            return error_response(message, 400, logger)

        file_instance = message
        valid, details = file_instance.check_details(with_checksum=with_checksum)
        info = {"index": i, "valid": valid, "type": file["type"]}
        info.update(details)
        files_info.append(info)

    response = jsonify(files_info), 200
    logger.info(f"fileinfo response = {response}")

    return response


@services.route("/initialize", methods=["GET"])
@validate(InitializeRequest)
def initialize():
    """Initialize a service access request.
    In order to consume a data service the user is required to send
    one datatoken to the provider.

    The datatoken is transferred via the ethereum blockchain network
    by requesting the user to sign an ERC20 approval transaction
    where the approval is given to the provider's ethereum account for
    the number of tokens required by the service.

    tags:
      - consume
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
            "nonce": <nonce-used-in-consumer-signature>,
            "providerFee": <object containing provider fees>,
            "computeAddress": <compute address>,
            "transferTxId": <optional tx_id just to check an existing order>
        }
        ```
    """
    data = get_request_data(request)
    logger.info(f"initialize called. arguments = {data}")

    did = data.get("documentId")
    consumer_address = data.get("consumerAddress")

    asset = get_asset_from_metadatastore(get_metadata_url(), did)
    if not asset:
        return error_response(
            "Cannot resolve DID",
            400,
            logger,
        )
    consumable, message = check_asset_consumable(asset, consumer_address, logger)
    if not consumable:
        return error_response(message, 400, logger)

    service_id = data.get("serviceId")
    service = asset.get_service_by_id(service_id)
    if not service:
        return error_response(
            "Invalid serviceId.",
            400,
            logger,
        )
    if service.type == "compute":
        return error_response(
            "Use the initializeCompute endpoint to initialize compute jobs.",
            400,
            logger,
        )

    valid_order = None
    if "transferTxId" in data:
        try:
            _tx, _order_log, _, _ = validate_order(
                get_web3(asset.chain_id),
                consumer_address,
                data["transferTxId"],
                asset,
                service,
                allow_expired_provider_fees=True,
            )
            return {"validOrder": _order_log.transactionHash.hex()}, 200
        except Exception:
            pass

    token_address = service.datatoken_address

    file_index = int(data.get("fileIndex", "-1"))
    # we check if the file is valid only if we have fileIndex
    if file_index > -1:
        provider_wallet = get_provider_wallet(asset.chain_id)
        url_object = get_service_files_list(service, provider_wallet, asset)[file_index]
        url_object["userdata"] = data.get("userdata")
        valid, message = FilesTypeFactory.validate_and_create(url_object)
        if not valid:
            return error_response(message, 400, logger)

        file_instance = message
        valid, url_details = file_instance.check_details(with_checksum=False)
        if not valid or not url_details:
            return error_response(
                f"Error: Asset URL not found, not available or invalid. \n"
                f"Payload was: {data}",
                400,
                logger,
            )

    # Prepare the `transfer` tokens transaction with the appropriate number
    # of tokens required for this service
    # The consumer must sign and execute this transaction in order to be
    # able to consume the service
    provider_fee = get_provider_fees(asset, service, consumer_address, 0)
    if provider_fee:
        provider_fee["providerFeeAmount"] = str(provider_fee["providerFeeAmount"])
    approve_params = {
        "datatoken": token_address,
        "nonce": get_nonce(consumer_address),
        "providerFee": provider_fee,
    }

    if valid_order:
        approve_params["validOrder"] = valid_order

    response = jsonify(approve_params), 200
    logger.info(f"initialize response = {response}")

    return response


@services.route("/download", methods=["GET"])
@validate(DownloadRequest)
def download():
    """Allows download of asset data file.

    ---
    tags:
      - consume
    consumes:
      - application/json
    parameters:
      - name: consumerAddress
        in: query
        description: The consumer address.
        required: true
        type: string
      - name: documentId
        in: query
        description: The ID of the asset/document (the DID).
        required: true
        type: string
      - name: signature
        in: query
        description: Signature of the documentId to verify that the consumer has rights to download the asset.
      - name: index
        in: query
        description: Index of the file in the array of files.
    responses:
      200:
        description: Redirect to valid asset url.
      400:
        description: One or more of the required attributes are missing or invalid.
      401:
        description: Invalid asset data.
      503:
        description: Service Unavailable
    """
    data = get_request_data(request)
    logger.info(f"download called. arguments = {data}")

    did = data.get("documentId")
    consumer_address = data.get("consumerAddress")
    service_id = data.get("serviceId")
    tx_id = data.get("transferTxId")

    # grab asset for did from the metadatastore associated with
    # the datatoken address
    asset = get_asset_from_metadatastore(get_metadata_url(), did)
    service = asset.get_service_by_id(service_id)

    if service.type != ServiceType.ACCESS:
        # allow our C2D to download a compute asset
        c2d_environments = get_c2d_environments(flat=True)

        is_c2d_consumer_address = bool(
            [
                True
                for env in c2d_environments
                if Web3.toChecksumAddress(env["consumerAddress"])
                == Web3.toChecksumAddress(consumer_address)
            ]
        )

        if not is_c2d_consumer_address:
            return error_response(
                f"Service with index={service_id} is not an access service.",
                400,
                logger,
            )

    logger.info("validate_order called from download endpoint.")

    try:
        _tx, _order_log, _, _ = validate_order(
            get_web3(asset.chain_id), consumer_address, tx_id, asset, service
        )
    except Exception as e:
        return error_response(
            f"=Order with tx_id {tx_id} could not be validated due to error: {e}",
            400,
            logger,
        )

    file_index = int(data.get("fileIndex"))
    provider_wallet = get_provider_wallet(asset.chain_id)
    files_list = get_service_files_list(service, provider_wallet, asset)
    if file_index > len(files_list):
        return error_response(f"No such fileIndex {file_index}", 400, logger)
    url_object = files_list[file_index]
    url_object["userdata"] = data.get("userdata")
    url_valid, message = FilesTypeFactory.validate_and_create(url_object)

    if not url_valid:
        return error_response(message, 400, logger)

    file_instance = message
    valid, details = file_instance.check_details(with_checksum=True)

    if not valid:
        return error_response(details, 400, logger)

    logger.debug(
        f"Done processing consume request for asset {did}, "
        f" url {file_instance.get_download_url()}"
    )
    update_nonce(consumer_address, data.get("nonce"))

    response = file_instance.build_download_response(request)
    logger.info(f"download response = {response}")

    provider_proof_data = json.dumps(
        {
            "documentId": did,
            "serviceId": service_id,
            "fileIndex": file_index,
            "downloadedBytes": 0,  # TODO
        },
        separators=(",", ":"),
    )

    consumer_data = f'{did}{data.get("nonce")}'

    send_proof(
        asset.chain_id,
        order_tx_id=_tx.hash,
        provider_data=provider_proof_data,
        consumer_data=consumer_data,
        consumer_signature=data.get("signature"),
        consumer_address=consumer_address,
        datatoken_address=service.datatoken_address,
    )

    return response
