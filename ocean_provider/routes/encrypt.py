#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from flask import Response, request
from ocean_provider.requests_session import get_requests_session
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.utils.encryption import do_encrypt
from ocean_provider.utils.error_responses import error_response

from . import services

# provider_wallet = get_provider_wallet()
requests_session = get_requests_session()

logger = logging.getLogger(__name__)


@services.route("/encrypt", methods=["POST"])
def encrypt():
    """Encrypt data using the Provider's own symmetric key (symmetric encryption).
    This can be used by the publisher of an asset to encrypt the DDO of the
    asset data files before publishing the asset DDO. The publisher to use this
    service is one that is using a front-end with a wallet app such as MetaMask.
    The DDO is encrypted by the provider so that the provider will be able
    to decrypt at time of providing the service later on.

    ---
    tags:
      - services
    consumes:
      - application/octet-stream
    parameters:
      - in: chainId
        name: chainId
        required: true
        description: chainId to be used for encryption, given as query parameter
      - in: body
        name: body
        required: true
        description: Binary document contents to encrypt.
    responses:
      201:
        description: DDO successfully encrypted.
      400:
        description: Invalid request content type or failure to encrypt.
      503:
        description: Service Unavailable

    return: the encrypted DDO (hex str)
    """
    if request.content_type != "application/octet-stream":
        return error_response(
            "Invalid request content type: should be application/octet-stream",
            400,
            logger,
        )

    chain_id = request.args.get("chainId")
    if not chain_id:
        return error_response(
            "Missing chainId query parameter.",
            400,
            logger,
        )

    data = request.get_data()
    logger.debug(f"encrypt called. arguments = {data}")

    return _encrypt(data, chain_id)


def _encrypt(data: bytes, chain_id) -> Response:
    try:
        provider_wallet = get_provider_wallet(chain_id)
        encrypted_data = do_encrypt(data, provider_wallet)
        logger.info(f"encrypted_data = {encrypted_data}")
    except Exception:
        return error_response("Failed to encrypt.", 400, logger)

    response = Response(
        encrypted_data,
        201,
        headers={"Content-type": "text/plain"},
    )
    logger.info(f"encrypt response = {response}")

    return response
