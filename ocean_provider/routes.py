#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0
import json
import logging
import os

from flask import Blueprint, jsonify, request, Response
from ocean_utils.http_requests.requests_session import get_requests_session

from ocean_provider.contracts.custom_contract import DataTokenContract
from ocean_provider.utils.basics import setup_network, LocalFileAdapter
from ocean_provider.myapp import app
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.log import setup_logging
from ocean_provider.util import (
    get_request_data,
    check_required_attributes,
    build_download_response,
    get_download_url,
    get_asset_url_at_index,
    validate_token_transfer,
    process_consume_request
)
from ocean_provider.utils.accounts import verify_signature, get_provider_account
from ocean_provider.utils.encryption import do_encrypt

setup_logging()
services = Blueprint('services', __name__)
setup_network()
provider_acc = get_provider_account()
requests_session = get_requests_session()
requests_session.mount('file://', LocalFileAdapter())

logger = logging.getLogger(__name__)


@services.route('/', methods=['GET'])
def simple_flow_consume():
    required_attributes = [
        'consumerAddress',
        'tokenAddress',
        'transferTxId'
    ]
    data = get_request_data(request)

    msg, status = check_required_attributes(
        required_attributes, data, 'simple_flow_consume')
    if msg:
        return msg, status

    consumer = data.get('consumerAddress')
    dt_address = data.get('tokenAddress')
    tx_id = data.get('transferTxId')

    dt_map = None
    dt_map_str = os.getenv('CONFIG', '')
    if dt_map_str:
        dt_map = json.loads(dt_map_str)

    if not (dt_map_str and dt_map):  # or dt not in dt_map:
        return jsonify(error='This request is not supported.'), 400

    try:
        dt = DataTokenContract(dt_address)
        # TODO: Verify that the datatoken is owned by this provider's account

        # TODO: Enable this check for the token transfer.
        # validate_token_transfer(
        #     consumer,
        #     provider_acc.address,
        #     dt_address,
        #     1,
        #     tx_id
        # )

        url = list(dt_map.values())[0]  # [dt_address]
        download_url = get_download_url(url, app.config['CONFIG_FILE'])
        logger.info(f'Done processing consume request for data token {dt_address}, '
                    f' url {download_url}')
        return build_download_response(request, requests_session, url, download_url)

    except Exception as e:
        logger.error(
            f'Error: {e}. \n'
            f'Payload was: tokenAddress={dt_address}, '
            f'consumerAddress={consumer}',
            exc_info=1
        )
        return jsonify(error=e), 500


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
            document,
            provider_acc,
        )
        logger.info(f'encrypted urls {encrypted_document}, '
                    f'publisher {publisher_address}, '
                    f'documentId {did}')
        return Response(
            json.dumps({'encryptedDocument': encrypted_document}),
            201,
            headers={'content-type': 'application/json'}
        )

    except InvalidSignatureError as e:
        msg = f'Publisher signature failed verification: {e}'
        logger.error(msg, exc_info=1)
        return jsonify(error=msg), 401

    except Exception as e:
        logger.error(
            f'Error: {e}. \n'
            f'providerAddress={provider_acc.address}\n'
            f'Payload was: documentId={did}, '
            f'publisherAddress={publisher_address},'
            f'signature={signature}',
            exc_info=1
        )
        return jsonify(error=e), 500


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
    data = get_request_data(request)
    try:
        asset, service, did, consumer_address, token_address = process_consume_request(
            data,
            'initialize',
            require_signature=False
        )
        service_id = data.get('serviceId')
        service_type = data.get('serviceType')

        # Prepare the `transfer` tokens transaction with the appropriate number of
        # tokens required for this service
        # The consumer must sign and execute this transaction in order to be able to
        # consume the service
        approve_params = {
            "from": consumer_address,
            "to": provider_acc.address,
            # FIXME: Replace this constant price number
            "numTokens": 5, #service.get_price(),
            "dataTokenAddress": token_address,
        }
        return Response(
            json.dumps(approve_params),
            200,
            headers={'content-type': 'application/json'}
        )

    except Exception as e:
        logger.error(
            f'Error: {e}. \n'
            f'Payload was: documentId={did}, '
            f'consumerAddress={consumer_address},'
            f'serviceId={service_id}'
            f'serviceType={service_type}',
            exc_info=1
        )
        return jsonify(error=e), 500


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
        asset, service, did, consumer_address, token_address = process_consume_request(
            data,
            'download',
            additional_params=["transferTxId", "fileIndex"]
        )
        service_id = data.get('serviceId')
        service_type = data.get('serviceType')
        signature = data.get('signature')
        tx_id = data.get("transferTxId")
        validate_token_transfer(
            consumer_address,
            provider_acc.address,
            token_address,
            # FIXME: Replace this constant price number
            5, #service.get_price(),
            tx_id
        )

        file_index = int(data.get('fileIndex'))
        file_attributes = asset.metadata['main']['files'][file_index]
        content_type = file_attributes.get('contentType', None)
        url = get_asset_url_at_index(file_index, asset, provider_acc)

        download_url = get_download_url(url, app.config['CONFIG_FILE'])
        logger.info(f'Done processing consume request for asset {did}, '
                    f' url {download_url}')
        return build_download_response(request, requests_session, url, download_url, content_type)

    except InvalidSignatureError as e:
        msg = f'Consumer signature failed verification: {e}'
        logger.error(msg, exc_info=1)
        return jsonify(error=msg), 401

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
        return jsonify(error=e), 500
