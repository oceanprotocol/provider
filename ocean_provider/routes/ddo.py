#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging

from flask import Response, request
from flask_sieve import validate
from ocean_provider.log import setup_logging
from ocean_provider.requests_session import get_requests_session
from ocean_provider.routes.consume import encrypt_and_increment_nonce
from ocean_provider.utils.basics import LocalFileAdapter, get_provider_wallet
from ocean_provider.utils.util import get_request_data, service_unavailable
from ocean_provider.validation.provider_requests import EncryptRequest

from . import ddo

setup_logging()
provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "application/json", "Connection": "close"}


@ddo.route("/encrypt", method=["POST"])
@validate(EncryptRequest)
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
            - ddo
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
    data = get_request_data(request)
    logger.info(f"encrypt endpoint called. {data}")
    did = data.get("documentId")
    ddo = json.dumps(json.loads(data.get("ddo")), separators=(",", ":"))
    publisher_address = data.get("publisherAddress")

    encrypted_document = encrypt_and_increment_nonce(did, ddo, publisher_address)
    try:
        return Response(encrypted_document, 201, headers={"content-type": "text/plain"})
    except Exception as e:
        return service_unavailable(
            e,
            {
                "providerAddress": provider_wallet.address if provider_wallet else "",
                "documentId": did,
                "publisherAddress": publisher_address,
            },
        )
