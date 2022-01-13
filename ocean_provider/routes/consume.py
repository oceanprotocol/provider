#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging

from artifacts import ERC721Template
from flask import Response, jsonify, request
from flask_sieve import validate
from jsonsempai import magic  # noqa: F401
from ocean_provider.log import setup_logging
from ocean_provider.myapp import app
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import get_nonce, update_nonce
from ocean_provider.utils.basics import (
    LocalFileAdapter,
    get_asset_from_metadatastore,
    get_provider_wallet,
    get_web3,
)
from ocean_provider.utils.error_responses import service_unavailable
from ocean_provider.utils.provider_fees import get_provider_fees
from ocean_provider.utils.services import ServiceType
from ocean_provider.utils.url import append_userdata, check_url_details
from ocean_provider.utils.util import (
    build_download_response,
    check_asset_consumable,
    get_compute_info,
    get_download_url,
    get_metadata_url,
    get_request_data,
    get_service_files_list,
    validate_order,
    validate_url_object,
)
from ocean_provider.validation.provider_requests import (
    AssetUrlsRequest,
    DownloadRequest,
    FileInfoRequest,
    InitializeRequest,
    NonceRequest,
)
from web3.main import Web3

from . import services

setup_logging()
provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "application/json", "Connection": "close"}


@services.route("/nonce", methods=["GET"])
@validate(NonceRequest)
def nonce():
    """Returns a `nonce` for the given account address."""
    logger.info("nonce endpoint called")
    data = get_request_data(request)
    address = data.get("userAddress")
    nonce = get_nonce(address)
    logger.info(f"nonce for user {address} is {nonce}")
    return Response(json.dumps({"nonce": nonce}), 200, headers=standard_headers)


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
      - services

    responses:
      200:
        description: the URL(s) could be analysed (returns the result).
      400:
        description: the URL(s) could not be analysed (bad request).

    return: list of file info (index, valid, contentLength, contentType)
    """
    data = get_request_data(request)
    logger.info(f"fileinfo endpoint called. {data}")
    did = data.get("did")
    service_id = data.get("serviceId")

    if did:
        asset = get_asset_from_metadatastore(get_metadata_url(), did)
        service = asset.get_service_by_id(service_id)
        files_list = get_service_files_list(service, provider_wallet)
        url_list = [
            get_download_url(file_item, app.config["PROVIDER_CONFIG_FILE"])
            for file_item in files_list
        ]
    else:
        url_list = [get_download_url(data, app.config["PROVIDER_CONFIG_FILE"])]

    with_checksum = data.get("checksum", False)

    files_info = []
    for i, url in enumerate(url_list):
        valid, details = check_url_details(url, with_checksum=with_checksum)
        info = {"index": i, "valid": valid}
        info.update(details)
        files_info.append(info)

    return Response(json.dumps(files_info), 200, headers=standard_headers)


@services.route("/initialize", methods=["GET"])
@validate(InitializeRequest)
def initialize():
    """Initialize a service request.
    In order to consume a data service the user is required to send
    a number of datatokens to the provider as defined in the Asset's
    service description in the Asset's DDO document.

    The datatokens are transferred via the ethereum blockchain network
    by requesting the user to sign an ERC20 `approveAndLock` transaction
    where the approval is given to the provider's ethereum account for
    the number of tokens required by the service.

    :return:
        json object as follows:
        ```JSON
        {
            "datatoken": <data-token-contract-address>,
            "nonce": <nonce-used-in-consumer-signature>,
            "providerFee": <object containing provider fees
            "computeAddress": <compute address>
        }
        ```
    """
    data = get_request_data(request)
    logger.info(f"initialize endpoint called. {data}")

    try:
        did = data.get("documentId")
        consumer_address = data.get("consumerAddress")
        compute_env = data.get("computeEnv")

        asset = get_asset_from_metadatastore(get_metadata_url(), did)
        consumable, message = check_asset_consumable(asset, consumer_address, logger)
        if not consumable:
            return jsonify(error=message), 400

        service_id = data.get("serviceId")
        service = asset.get_service_by_id(service_id)

        if service.type == "compute" and not compute_env:
            return (
                jsonify(
                    error="The computeEnv is mandatory when initializing a compute service."
                ),
                400,
            )

        token_address = service.datatoken_address

        file_index = int(data.get("fileIndex", "-1"))
        # we check if the file is valid only if we have fileIndex
        if file_index > -1:
            url_object = get_service_files_list(service, provider_wallet)[file_index]
            url_valid, message = validate_url_object(url_object, service_id)
            if not url_valid:
                return (jsonify(error=message), 400)
            download_url = get_download_url(
                url_object, app.config["PROVIDER_CONFIG_FILE"]
            )
            download_url = append_userdata(download_url, data)
            valid, url_details = check_url_details(download_url)

            if not valid:
                logger.error(
                    f"Error: Asset URL not found or not available. \n"
                    f"Payload was: {data}",
                    exc_info=1,
                )
                return jsonify(error="Asset URL not found or not available."), 400

        # Prepare the `transfer` tokens transaction with the appropriate number
        # of tokens required for this service
        # The consumer must sign and execute this transaction in order to be
        # able to consume the service
        compute_address, compute_limits = get_compute_info()
        approve_params = {
            "datatoken": token_address,
            "nonce": get_nonce(consumer_address),
            "computeAddress": compute_address,
            "providerFee": get_provider_fees(did, service, consumer_address),
        }
        return Response(json.dumps(approve_params), 200, headers=standard_headers)

    except Exception as e:
        return service_unavailable(e, data, logger)


@services.route("/download", methods=["GET"])
@validate(DownloadRequest)
def download():
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
      - name: documentId
        in: query
        description: The ID of the asset/document (the DID).
        required: true
        type: string
      - name: url
        in: query
        description: This URL is only valid if Provider acts as a proxy.
                     Consumer can't download using the URL if it's not through the Provider.
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
        description: One of the required attributes is missing.
      401:
        description: Invalid asset data.
      503:
        description: Service Unavailable
    """
    data = get_request_data(request)
    logger.info(f"download endpoint called. {data}")
    try:
        did = data.get("documentId")
        consumer_address = data.get("consumerAddress")
        service_id = data.get("serviceId")
        tx_id = data.get("transferTxId")

        # grab asset for did from the metadatastore associated with
        # the datatoken address
        asset = get_asset_from_metadatastore(get_metadata_url(), did)
        service = asset.get_service_by_id(service_id)
        token_address = service.datatoken_address

        compute_address, compute_limits = get_compute_info()

        # allow our C2D to download a compute asset
        if service.type != ServiceType.ACCESS and Web3.toChecksumAddress(
            consumer_address
        ) != Web3.toChecksumAddress(compute_address):
            return (
                jsonify(
                    error=f"Service with index={service_id} is not an access service."
                ),
                400,
            )
        logger.info("validate_order called from download endpoint.")
        _tx, _order_log, _transfer_log = validate_order(
            get_web3(), consumer_address, token_address, 1, tx_id, did, service
        )

        file_index = int(data.get("fileIndex"))
        files_list = get_service_files_list(service, provider_wallet)
        if file_index > len(files_list):
            return jsonify(error=f"No such fileIndex")
        url_object = files_list[file_index]
        url_valid, message = validate_url_object(url_object, service_id)

        if not url_valid:
            return (jsonify(error=message), 400)

        download_url = get_download_url(url_object, app.config["PROVIDER_CONFIG_FILE"])
        download_url = append_userdata(download_url, data)

        valid, details = check_url_details(url_object["url"])
        content_type = details["contentType"] if valid else None

        logger.info(
            f"Done processing consume request for asset {did}, " f" url {download_url}"
        )
        update_nonce(consumer_address, data.get("nonce"))
        return build_download_response(
            request,
            requests_session,
            url_object["url"],
            download_url,
            content_type,
            method=url_object.get("method", "GET"),
        )

    except Exception as e:
        return service_unavailable(
            e,
            {
                "documentId": data.get("documentId"),
                "consumerAddress": data.get("consumerAddress"),
                "serviceId": data.get("serviceId"),
            },
            logger,
        )


@services.route("/assetUrls", methods=["GET"])
@validate(AssetUrlsRequest)
def asset_urls():
    """Lists files from an asset
    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: documentId
        in: query
        description: The ID of the asset/document (the DID).
        required: true
        type: string
      - name: signature
        in: query
        description: Signature of the documentId to verify that the consumer has rights to download the asset.
      - name: serviceId
        in: string
        description: ServiceId for the asset access service.
      - name: nonce
        in: string
        description: User nonce.
      - name: publisherAddress
        in: query
        description: The publisher address.
        required: true
        type: string
    responses:
      200:
        description: lists asset files
      400:
        description: One of the required attributes is missing.
      503:
        description: Service Unavailable
    """
    data = get_request_data(request)
    did = data.get("documentId")
    service_id = data.get("serviceId")
    publisher_address = data.get("publisherAddress")

    logger.info(f"asset urls endpoint called. {data}")
    try:
        asset = get_asset_from_metadatastore(get_metadata_url(), did)
        service = asset.get_service_by_id(service_id)
        assert service.type == "access"

        dt_token = get_web3().eth.contract(
            abi=ERC721Template.abi, address=asset.nft["address"]
        )

        if not dt_token.caller.ownerOf(1).lower() == publisher_address.lower():
            return Response(
                json.dumps({"error": "Publisher address does not match minter."}),
                400,
                headers={"content-type": "application/json"},
            )

        urls = get_service_files_list(service, provider_wallet)

        logger.info(f"Retrieved unencrypted urls for for asset {did}")
        update_nonce(publisher_address, data.get("nonce"))

        return Response(
            json.dumps(urls), 200, headers={"content-type": "application/json"}
        )

    except Exception as e:
        return service_unavailable(
            e,
            {
                "documentId": data.get("did"),
                "serviceId": data.get("serviceId"),
                "consumerAddress": data.get("consumerAddress"),
            },
            logger,
        )


def process_consume_request(data: dict):
    did = data.get("documentId")
    token_address = data.get("datatoken")
    consumer_address = data.get("consumerAddress")
    service_id = int(data.get("serviceId"))

    # grab asset for did from the metadatastore associated with
    # the datatoken address
    asset = get_asset_from_metadatastore(get_metadata_url(), did)
    service = asset.get_service_by_id(service_id)

    return asset, service, did, consumer_address, token_address
