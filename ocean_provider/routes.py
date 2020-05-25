#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import logging

from flask import Blueprint, jsonify, request, Response
from ocean_utils.http_requests.requests_session import get_requests_session

from ocean_provider.log import setup_logging
from ocean_provider.util import (
    get_provider_account,
)

setup_logging()
services = Blueprint('services', __name__)
provider_acc = get_provider_account()
requests_session = get_requests_session()

logger = logging.getLogger(__name__)


@services.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypt document using the Provider's own key and symmetric encryption.

    This can be used by the publisher of an asset to encrypt the urls of the
    asset data files before publishing the asset ddo. The publisher to use this
    service is one that is using a front-end with a wallet app such as MetaMask.
    In such scenario the publisher is not able to encrypt the urls using the
    SecretStore interface and this service becomes necessary.

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
    return '', 200


@services.route('/initialize', methods=['GET'])
def initialize():
    return '', 200


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
