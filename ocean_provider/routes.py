#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0
import json
import logging

from flask import Blueprint, jsonify, request, Response
from ocean_utils.http_requests.requests_session import get_requests_session

from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.log import setup_logging
from ocean_provider.util import (
    get_provider_account,
    get_request_data, check_required_attributes, verify_signature, do_encrypt, get_config, get_metadata_store_url, get_asset,
    get_asset_for_data_token)

setup_logging()
services = Blueprint('services', __name__)
provider_acc = get_provider_account()
requests_session = get_requests_session()

logger = logging.getLogger(__name__)


@services.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypt document using the Provider's own symmetric key (symmetric encryption).

    This can be used by the publisher of an asset to encrypt the urls of the
    asset data files before publishing the asset ddo. The publisher to use this
    service is one that is using a front-end with a wallet app such as MetaMask.
    The `urls` are encrypted by the provider so that the provider will be able
    to decrypt at time of providing the service later on.

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
            - signature
            - document
            - publisherAddress:
          properties:
            documentId:
              description: Identifier of the asset to be registered in ocean.
              type: string
              example: 'did:op:08a429b8529856d59867503f8056903a680935a76950bb9649785cc97869a43d'
            signature:
              description: Publisher signature of the documentId
              type: string
              example: ''
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
    required_attributes = [
        'documentId',
        'signature',
        'document',
        'publisherAddress'
    ]
    data = get_request_data(request)

    msg, status = check_required_attributes(
        required_attributes, data, 'encrypt')
    if msg:
        return msg, status

    did = data.get('documentId')
    signature = data.get('signature')
    document = json.dumps(json.loads(
        data.get('document')), separators=(',', ':'))
    publisher_address = data.get('publisherAddress')

    try:
        # Raises ValueError when signature is invalid
        verify_signature(publisher_address, signature, did)

        encrypted_document = do_encrypt(
            remove_0x_prefix(did),
            document,
            provider_acc,
            get_config()
        )
        logger.info(f'encrypted urls {encrypted_document}, '
                    f'publisher {publisher_address}, '
                    f'documentId {did}')
        return encrypted_document, 201

    except InvalidSignatureError as e:
        msg = f'Publisher signature failed verification: {e}'
        logger.error(msg, exc_info=1)
        return msg, 401

    except Exception as e:
        logger.error(
            f'Error: {e}. \n'
            f'providerAddress={provider_acc.address}\n'
            f'Payload was: documentId={did}, '
            f'publisherAddress={publisher_address},'
            f'signature={signature}',
            exc_info=1
        )
        return f'Error: {str(e)}', 500


@services.route('/initialize', methods=['GET'])
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
    """
    required_attributes = [
        'documentId',
        'serviceId',
        'serviceType',
        'signature',
        'tokenAddress',
        'consumerAddress'
    ]
    data = get_request_data(request)

    msg, status = check_required_attributes(
        required_attributes, data, 'initialize')
    if msg:
        return msg, status

    did = data.get('documentId')
    signature = data.get('signature')
    token_address = data.get('tokenAddress')
    consumer_address = data.get('consumerAddress')
    service_id = data.get('serviceId')
    service_type = data.get('serviceType')

    # grab asset for did from the metadatastore associated with the Data Token address
    asset = get_asset_for_data_token(token_address, did)
    service = asset.get_service(service_id)
    try:
        if service.type != service_type:
            raise AssertionError(
                f'Requested service with id {service_id} has type {service.type} which '
                f'does not match the requested service type {service_type}.'
            )

        # Raises ValueError when signature is invalid
        verify_signature(consumer_address, signature, did)

        # Prepare the approveAndLock transaction with the appropriate
        # number of tokens
        # The consumer must sign and execute this transaction in order to be able to
        # consume the service
        return '', 200

    except InvalidSignatureError as e:
        msg = f'Consumer  signature failed verification: {e}'
        logger.error(msg, exc_info=1)
        return msg, 401

    except Exception as e:
        logger.error(
            f'Error: {e}. \n'
            f'Payload was: documentId={did}, '
            f'consumerAddress={consumer_address},'
            f'signature={signature}'
            f'serviceId={service_id}'
            f'serviceType={service_type}',
            exc_info=1
        )
        return f'Error: {str(e)}', 500


@services.route('/download', methods=['GET'])
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
      - name: serviceAgreementId
        in: query
        description: The ID of the service agreement.
        required: true
        type: string
      - name: url
        in: query
        description: This URL is only valid if Brizo acts as a proxy.
                     Consumer can't download using the URL if it's not through Brizo.
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
    return '', 200


@services.route('/compute', methods=['DELETE'])
def compute_delete_job():
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
      - name: serviceAgreementId
        in: query
        description: The ID of the service agreement.
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
    return '', 200


@services.route('/compute', methods=['PUT'])
def compute_stop_job():
    """Stop the execution of a workflow.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: signature
        in: query
        description: Signature of (consumerAddress+jobId+serviceAgreementId) to verify the consumer of
            this agreement/compute job. The signature uses ethereum based signing method
            (see https://github.com/ethereum/EIPs/pull/683)
        type: string
      - name: serviceAgreementId
        in: query
        description: The ID of the service agreement, must exist on-chain. If not provided, all
            currently running compute jobs will be stopped for the specified consumerAddress
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
            the specified consumerAddress/serviceAgreementId are suspended
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
    return '', 200


@services.route('/compute', methods=['GET'])
def compute_get_status_job():
    """Get status for a specific jobid/agreementId/owner

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: signature
        in: query
        description: Signature of (consumerAddress+jobId+serviceAgreementId) to verify the consumer of
            this agreement/compute job. The signature uses ethereum based signing method
            (see https://github.com/ethereum/EIPs/pull/683)
        type: string
      - name: serviceAgreementId
        in: query
        description: The ID of the service agreement, must exist on-chain. If not provided, the status of all
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
            the specified consumerAddress/serviceAgreementId are suspended
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
    return '', 200


@services.route('/compute', methods=['POST'])
def compute_start_job():
    """Call the execution of a workflow.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: signature
        in: query
        description: Signature of (consumerAddress+jobId+serviceAgreementId) to verify the consumer of
            this agreement/compute job. The signature uses ethereum based signing method
            (see https://github.com/ethereum/EIPs/pull/683)
        type: string
      - name: serviceAgreementId
        in: query
        description: The ID of the service agreement, must exist on-chain. If not provided, the status of all
            currently running and old compute jobs for the specified consumerAddress will be returned.
        required: true
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
        description: Consumer signature is invalid or failed verification, or Service Agreement is invalid
      500:
        description: General server error
    """
    return '', 200
