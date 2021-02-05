#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0
import json
import logging
import os

from eth_utils import add_0x_prefix
from flask import Blueprint, Response, jsonify, request
from flask_sieve import validate
from ocean_lib.models.data_token import DataToken
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_lib.web3_internal.web3helper import Web3Helper
from ocean_utils.agreements.service_types import ServiceTypes
from ocean_utils.did import did_to_id
from ocean_utils.http_requests.requests_session import get_requests_session

from ocean_provider.log import setup_logging
from ocean_provider.myapp import app
from ocean_provider.user_nonce import get_nonce, increment_nonce
from ocean_provider.util import (build_download_response,
                                 get_asset_download_urls,
                                 get_asset_url_at_index, get_compute_endpoint,
                                 get_download_url, get_metadata_url,
                                 get_request_data, process_compute_request,
                                 process_consume_request,
                                 record_consume_request, validate_order,
                                 validate_transfer_not_used_for_other_service)
from ocean_provider.util_url import check_url_details
from ocean_provider.utils.basics import (LocalFileAdapter,
                                         get_asset_from_metadatastore,
                                         get_datatoken_minter,
                                         get_provider_wallet, setup_network)
from ocean_provider.utils.encryption import do_encrypt
from ocean_provider.validation.algo import AlgoValidator
from ocean_provider.validation.requests import (ComputeRequest,
                                                ComputeStartRequest,
                                                DownloadRequest,
                                                EncryptRequest,
                                                FileInfoRequest,
                                                InitializeRequest,
                                                NonceRequest,
                                                SimpleFlowConsumeRequest,
                                                UnsignedComputeRequest)

setup_logging()
services = Blueprint('services', __name__)
setup_network()
provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount('file://', LocalFileAdapter())

logger = logging.getLogger(__name__)


@services.route('/nonce', methods=['GET'])
@validate(NonceRequest)
def nonce():
    data = get_request_data(request)
    address = data.get('userAddress')
    nonce = get_nonce(address)
    logger.info(f'nonce for user {address} is {nonce}')
    return Response(
        json.dumps({'nonce': nonce}),
        200,
        headers={'content-type': 'application/json'}
    )


@services.route('/', methods=['GET'])
@validate(SimpleFlowConsumeRequest)
def simple_flow_consume():
    data = get_request_data(request)
    consumer = data.get('consumerAddress')
    dt_address = data.get('dataToken')
    tx_id = data.get('transferTxId')

    dt_map = None
    dt_map_str = os.getenv('CONFIG', '')
    if dt_map_str:
        dt_map = json.loads(dt_map_str)

    if not (dt_map_str and dt_map):  # or dt not in dt_map:
        return jsonify(error='This request is not supported.'), 400

    try:
        dt = DataToken(dt_address)
        # TODO: Verify that the datatoken is owned by this provider's account

        # TODO: Enable this check for the token transfer.
        # validate_order(
        #     consumer,
        #     dt_address,
        #     1,
        #     tx_id
        # )

        url = list(dt_map.values())[0]  # [dt_address]
        download_url = get_download_url(url, app.config['CONFIG_FILE'])
        logger.info(
            f'Done processing consume request for data token {dt_address}, '
            f' url {download_url}'
        )
        return build_download_response(
            request, requests_session, url, download_url
        )

    except Exception as e:
        logger.error(
            f'Error: {e}. \n'
            f'Payload was: dataToken={dt_address}, '
            f'consumerAddress={consumer}',
            exc_info=1
        )
        return jsonify(error=str(e)), 500


@services.route('/encrypt', methods=['POST'])
@validate(EncryptRequest)
def encrypt():
    """Encrypt document using the Provider's own symmetric key (symmetric encryption).
    This can be used by the publisher of an asset to encrypt the urls of the
    asset data files before publishing the asset ddo. The publisher to use this
    service is one that is using a front-end with a wallet app such as MetaMask.
    The `urls` are encrypted by the provider so that the provider will be able
    to decrypt at time of providing the service later on.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        description: Asset urls encryption.
        schema:
          type: object
          required:
            - documentId
            - document
            - publisherAddress:
          properties:
            documentId:
              description: Identifier of the asset to be registered in ocean.
              type: string
              example: 'did:op:08a429b8529856d59867503f8056903a680935a76950bb9649785cc97869a43d'
            document:
              description: document
              type: string
              example: '/some-url'
            publisherAddress:
              description: Publisher address.
              type: string
              example: '0x00a329c0648769A73afAc7F9381E08FB43dBEA72'
    responses:
      201:
        description: document successfully encrypted.
      500:
        description: Error

    return: the encrypted document (hex str)
    """
    data = get_request_data(request)
    did = data.get('documentId')
    document = json.dumps(json.loads(
        data.get('document')), separators=(',', ':'))
    publisher_address = data.get('publisherAddress')

    try:
        encrypted_document = do_encrypt(
            document,
            provider_wallet,
        )
        logger.info(f'encrypted urls {encrypted_document}, '
                    f'publisher {publisher_address}, '
                    f'documentId {did}')
        increment_nonce(publisher_address)
        return Response(
            json.dumps({'encryptedDocument': encrypted_document}),
            201,
            headers={'content-type': 'application/json'}
        )

    except Exception as e:
        logger.error(
            f'Error: {e}. \n'
            f'providerAddress={provider_wallet.address}\n'
            f'Payload was: documentId={did}, '
            f'publisherAddress={publisher_address}',
            exc_info=1
        )
        return jsonify(error=str(e)), 500


@services.route('/fileinfo', methods=['POST'])
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
    did = data.get('did')
    url = data.get('url')

    if did:
        asset = get_asset_from_metadatastore(get_metadata_url(), did)
        url_list = get_asset_download_urls(
            asset, provider_wallet, config_file=app.config['CONFIG_FILE']
        )
    else:
        url_list = [get_download_url(url, app.config['CONFIG_FILE']), ]

    with_checksum = data.get('checksum', False)

    files_info = []
    for i, url in enumerate(url_list):
        valid, details = check_url_details(url, with_checksum=with_checksum)
        info = {'index': i, 'valid': valid}
        info.update(details)
        files_info.append(info)

    return Response(
        json.dumps(files_info),
        200,
        headers={'content-type': 'application/json'}
    )


@services.route('/initialize', methods=['GET'])
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
        {
            "from": <consumer-address>,
            "to": <receiver-address>,
            "numTokens": <tokens-amount-in-base>
            "dataToken": <data-token-contract-address>,
            "nonce": <nonce-used-in-consumer-signature>
        }
    """
    data = get_request_data(request)

    try:
        asset, service, did, consumer_address, token_address = process_consume_request(  # noqa
            data,
            'initialize'
        )

        url = get_asset_url_at_index(0, asset, provider_wallet)
        download_url = get_download_url(url, app.config['CONFIG_FILE'])
        valid, details = check_url_details(download_url)

        if not valid:
            logger.error(
                f'Error: Asset URL not found or not available. \n'
                f'Payload was: {data}',
                exc_info=1
            )
            return jsonify(error="Asset URL not found or not available."), 400

        minter = get_datatoken_minter(asset, token_address)

        # Prepare the `transfer` tokens transaction with the appropriate number
        # of tokens required for this service
        # The consumer must sign and execute this transaction in order to be
        # able to consume the service
        approve_params = {
            "from": consumer_address,
            "to": minter,
            "numTokens": float(service.get_cost()),
            "dataToken": token_address,
            "nonce": get_nonce(consumer_address)
        }
        return Response(
            json.dumps(approve_params),
            200,
            headers={'content-type': 'application/json'}
        )

    except Exception as e:
        logger.error(
            f'Error: {e}. \n'
            f'Payload was: {data}',
            exc_info=1
        )
        return jsonify(error=str(e)), 500


@services.route('/download', methods=['GET'])
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
      500:
        description: Error
    """
    data = get_request_data(request)
    try:
        asset, service, did, consumer_address, token_address = process_consume_request(  # noqa
            data,
            'download'
        )
        service_id = data.get('serviceId')
        service_type = data.get('serviceType')
        tx_id = data.get("transferTxId")
        if did.startswith('did:'):
            did = add_0x_prefix(did_to_id(did))

        _tx, _order_log, _transfer_log = validate_order(
            consumer_address,
            token_address,
            float(service.get_cost()),
            tx_id,
            did,
            service_id
        )
        validate_transfer_not_used_for_other_service(
            did, service_id, tx_id, consumer_address, token_address
        )
        record_consume_request(
            did, service_id, tx_id, consumer_address, token_address,
            service.get_cost()
        )

        assert service_type == ServiceTypes.ASSET_ACCESS

        file_index = int(data.get('fileIndex'))
        file_attributes = asset.metadata['main']['files'][file_index]
        content_type = file_attributes.get('contentType', None)
        url = get_asset_url_at_index(file_index, asset, provider_wallet)

        download_url = get_download_url(url, app.config['CONFIG_FILE'])
        logger.info(f'Done processing consume request for asset {did}, '
                    f' url {download_url}')
        increment_nonce(consumer_address)
        return build_download_response(
            request, requests_session, url, download_url, content_type
        )

    except Exception as e:
        logger.error(
            f"Error: {e}. \n"
            f"Payload was: documentId={data.get('did')}, "
            f"consumerAddress={data.get('consumerAddress')},"
            f"serviceId={data.get('serviceId')}"
            f"serviceType={data.get('serviceType')}",
            exc_info=1
        )
        return jsonify(error=str(e)), 500


@services.route('/compute', methods=['DELETE'])
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
            headers={'content-type': 'application/json'})
        increment_nonce(body['owner'])
        return Response(
            response.content,
            response.status_code,
            headers={'content-type': 'application/json'}
        )
    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return jsonify(error=f'Error : {str(e)}'), 500


@services.route('/compute', methods=['PUT'])
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
            headers={'content-type': 'application/json'})
        increment_nonce(body['owner'])
        return Response(
            response.content,
            response.status_code,
            headers={'content-type': 'application/json'}
        )
    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return jsonify(error=f'Error : {str(e)}'), 500


@services.route('/compute', methods=['GET'])
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
        signed_request = bool(data.get('signature'))

        response = requests_session.get(
            get_compute_endpoint(),
            params=body,
            headers={'content-type': 'application/json'}
        )

        increment_nonce(body['owner'])
        _response = response.content
        # Filter status info if signature is not given or failed validation
        if not signed_request:
            resp_content = json.loads(response.content.decode('utf-8'))
            if not isinstance(resp_content, list):
                resp_content = [resp_content]
            _response = []
            keys_to_filter = [
                'resultsUrl', 'algorithmLogUrl', 'resultsDid', 'owner',
            ]
            for job_info in resp_content:
                for k in keys_to_filter:
                    job_info.pop(k)
                _response.append(job_info)

            _response = json.dumps(_response)

        return Response(
            _response,
            response.status_code,
            headers={'content-type': 'application/json'}
        )

    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return jsonify(error=f'Error : {str(e)}'), 500


@services.route('/compute', methods=['POST'])
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
        asset, service, did, consumer_address, token_address = process_consume_request(  # noqa
            data,
            'compute_start_job'
        )
        service_id = data.get('serviceId')
        service_type = data.get('serviceType')
        tx_id = data.get("transferTxId")

        # Verify that  the number of required tokens has been
        # transferred to the provider's wallet.

        _tx, _order_log, _transfer_log = validate_order(
            consumer_address,
            token_address,
            float(service.get_cost()),
            tx_id,
            add_0x_prefix(did_to_id(did)) if did.startswith('did:') else did,
            service_id
        )
        validate_transfer_not_used_for_other_service(
            did, service_id, tx_id, consumer_address, token_address
        )
        record_consume_request(
            did, service_id, tx_id, consumer_address, token_address,
            service.get_cost()
        )

        assert service_type == ServiceTypes.CLOUD_COMPUTE

        validator = AlgoValidator(
            consumer_address, provider_wallet, data, service, asset
        )

        status = validator.validate()
        if not status:
            return jsonify(error=validator.error), 400

        stage = validator.stage

        #########################
        # WORKFLOW
        workflow = dict({'stages': list([stage])})

        # workflow is ready, push it to operator
        logger.info('Sending: %s', workflow)

        msg_to_sign = f'{provider_wallet.address}{did}'
        msg_hash = add_ethereum_prefix_and_hash_msg(msg_to_sign)
        payload = {
            'workflow': workflow,
            'providerSignature': Web3Helper.sign_hash(
                msg_hash, provider_wallet
            ),
            'documentId': did,
            'agreementId': tx_id,
            'owner': consumer_address,
            'providerAddress': provider_wallet.address
        }
        response = requests_session.post(
            get_compute_endpoint(),
            data=json.dumps(payload),
            headers={'content-type': 'application/json'}
        )
        increment_nonce(consumer_address)
        return Response(
            response.content,
            response.status_code,
            headers={'content-type': 'application/json'}
        )
    except (ValueError, KeyError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return jsonify(error=f'Error : {str(e)}'), 500
