#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging

from flask import Response, jsonify, request
from flask_sieve import validate
from ocean_provider.log import setup_logging
from ocean_provider.myapp import app
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import get_nonce, increment_nonce
from ocean_provider.utils.basics import (
    LocalFileAdapter,
    get_asset_from_metadatastore,
    get_datatoken_minter,
    get_provider_wallet,
    get_web3,
)
from ocean_provider.utils.error_responses import service_unavailable
from ocean_provider.utils.url import append_userdata, check_url_details
from ocean_provider.utils.util import (
    build_download_response,
    check_asset_consumable,
    get_asset_download_urls,
    get_asset_url_at_index,
    get_compute_info,
    get_download_url,
    get_metadata_url,
    get_request_data,
    process_consume_request,
    record_consume_request,
    validate_order,
    validate_transfer_not_used_for_other_service,
)
from ocean_provider.validation.provider_requests import (
    DownloadRequest,
    FileInfoRequest,
    InitializeRequest,
    NonceRequest,
)

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
    url = data.get("url")

    if did:
        asset = get_asset_from_metadatastore(get_metadata_url(), did)
        url_list = get_asset_download_urls(
            asset, provider_wallet, config_file=app.config["PROVIDER_CONFIG_FILE"]
        )
    else:
        url_list = [get_download_url(url, app.config["PROVIDER_CONFIG_FILE"])]

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
    a number of data tokens to the provider as defined in the Asset's
    service description in the Asset's DDO document.

    The data tokens are transferred via the ethereum blockchain network
    by requesting the user to sign an ERC20 `approveAndLock` transaction
    where the approval is given to the provider's ethereum account for
    the number of tokens required by the service.

    :return:
        json object as follows:
        ```JSON
        {
            "from": <consumer-address>,
            "to": <receiver-address>,
            "numTokens": <tokens-amount-in-base>
            "dataToken": <data-token-contract-address>,
            "nonce": <nonce-used-in-consumer-signature>
        }
        ```
    """
    data = get_request_data(request)
    logger.info(f"initialize endpoint called. {data}")

    try:
        (asset, service, _, consumer_address, token_address) = process_consume_request(
            data
        )

        consumable, message = check_asset_consumable(asset, consumer_address, logger)
        if not consumable:
            return jsonify(error=message), 400

        url = get_asset_url_at_index(0, asset, provider_wallet)
        download_url = get_download_url(url, app.config["PROVIDER_CONFIG_FILE"])
        download_url = append_userdata(download_url, data)
        valid, _ = check_url_details(download_url)

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
            "from": consumer_address,
            "to": get_datatoken_minter(token_address),
            "numTokens": service.get_cost(),
            "dataToken": token_address,
            "nonce": get_nonce(consumer_address),
            "computeAddress": compute_address,
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
        token_address = data.get("dataToken")
        consumer_address = data.get("consumerAddress")
        service_id = int(data.get("serviceId"))
        tx_id = data.get("transferTxId")

        # grab asset for did from the metadatastore associated with
        # the Data Token address
        asset = get_asset_from_metadatastore(get_metadata_url(), did)
        service = asset.get_service_by_index(service_id)

        logger.info("validate_order called from download endpoint.")
        _tx, _order_log, _transfer_log = validate_order(
            get_web3(), consumer_address, token_address, 1, tx_id, did, service_id
        )
        validate_transfer_not_used_for_other_service(
            did, service_id, tx_id, consumer_address, token_address
        )
        record_consume_request(
            did, service_id, tx_id, consumer_address, token_address, service.get_cost()
        )

        assert service.type == "access"

        file_index = int(data.get("fileIndex"))
        file_attributes = asset.metadata["main"]["files"][file_index]
        content_type = file_attributes.get("contentType", None)
        url = get_asset_url_at_index(file_index, asset, provider_wallet)
        if not url:
            return jsonify(error="Cannot decrypt files for this asset."), 400

        download_url = get_download_url(url, app.config["PROVIDER_CONFIG_FILE"])
        download_url = append_userdata(download_url, data)

        logger.info(
            f"Done processing consume request for asset {did}, " f" url {download_url}"
        )
        increment_nonce(consumer_address)
        return build_download_response(
            request, requests_session, url, download_url, content_type
        )

    except Exception as e:
        return service_unavailable(
            e,
            {
                "documentId": data.get("did"),
                "consumerAddress": data.get("consumerAddress"),
                "serviceId": data.get("serviceId"),
                "serviceType": data.get("serviceType"),
            },
            logger,
        )
