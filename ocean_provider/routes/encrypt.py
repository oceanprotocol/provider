#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from flask import Response, request

from ocean_provider.log import setup_logging
from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.basics import LocalFileAdapter, get_provider_wallet
from ocean_provider.utils.encryption import do_encrypt
from ocean_provider.utils.error_responses import error_response, service_unavailable

from . import services

setup_logging()
provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)


@services.route("/encrypt", methods=["POST"])
def encrypt():
    """Encrypt DDO using the Provider's own symmetric key (symmetric encryption).
    This can be used by the publisher of an asset to encrypt the DDO of the
    asset data files before publishing the asset DDO. The publisher to use this
    service is one that is using a front-end with a wallet app such as MetaMask.
    The DDO is encrypted by the provider so that the provider will be able
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
            ddo:
              description: document description object (DDO)
              type: string
              example: See https://github.com/oceanprotocol/docs/blob/feature/ddo_v4/content/concepts/did-ddo.md
            publisherAddress:
              description: Publisher address.
              type: string
              example: '0x00a329c0648769A73afAc7F9381E08FB43dBEA72'
    responses:
      201:
        description: DDO successfully encrypted.
      503:
        description: Service Unavailable

    return: the encrypted DDO (hex str)
    """
    if request.content_type != "application/octet-stream":
        return error_response(
            "Invalid request content type: should be application/octet-stream", 400
        )

    data = request.get_data()
    logger.info(f"encrypt endpoint called. {data}")

    try:
        return _encrypt(data)
    except Exception as e:
        return service_unavailable(e, data, logger)


def _encrypt(data: bytes) -> Response:
    try:
        encrypted_data = do_encrypt(data, provider_wallet)
        logger.info(f"encrypted_data = {encrypted_data}")
    except Exception:
        return error_response(f"Failed to encrypt.", 400)

    return Response(
        encrypted_data,
        201,
        headers={"Content-type": "text/plain", "Connection": "close"},
    )
