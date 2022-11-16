#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import os

import jwt
from flask import jsonify, request
from flask_sieve import validate
from ocean_provider.user_nonce import (
    force_expire_token,
    force_restore_token,
    is_token_valid,
)
from ocean_provider.utils.basics import get_provider_private_key
from ocean_provider.utils.util import get_request_data
from ocean_provider.validation.provider_requests import (
    CreateTokenRequest,
    DeleteTokenRequest,
)

from . import services

logger = logging.getLogger(__name__)


@services.route("/createAuthToken", methods=["GET"])
@validate(CreateTokenRequest)
def create_auth_token():
    """Creates an AuthToken for the given address, that can replace signature in API calls.

    Accepts a user address and an expiration parameter (future UTC timestamp).
    If the token was previously deleted with the same parameters and they are still valid
    (expiration date is in the future), the same token is re-enabled.
    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: address
        description: The address of the API caller
        required: true
        type: string
      - name: expiration
        description: A valid future UTC timestamp
        required: true
        type: string
      - name: signature
        in: query
        description: Signature to verify that the address requestor has rights to create the token.
    responses:
      200:
        description: the token was successfully created or restored
      400:
        description: issue with the request parameters
      503:
        description: Service Unavailable.

    return: created or restored token if successfull, otherwise an error string
    """
    data = get_request_data(request)
    address = data.get("address")
    expiration = int(data.get("expiration"))

    pk = get_provider_private_key(any_chain=True)
    token = jwt.encode({"exp": expiration, "address": address}, pk, algorithm="HS256")
    token = token.decode("utf-8") if isinstance(token, bytes) else token

    valid, message = is_token_valid(token, address)
    if not valid and message == "Token is deleted.":
        force_restore_token(token)

    return jsonify(token=token)


@services.route("/deleteAuthToken", methods=["DELETE"])
@validate(DeleteTokenRequest)
def delete_auth_token():
    """Revokes a given AuthToken if it is still valid.

    Accepts the token and signed request parameters to determine whether the user has
    rights to delete/revoke. If the token is already expired or deleted, returns an
    error string. If the token is still valid at the time of the request, it is blacklisted,
    disallowing API calls with that token.
    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: address
        description: The address of the API caller
        required: true
        type: string
      - name: token
        description: The token string
        required: true
        type: string
      - name: signature
        in: query
        description: Signature to verify that the address requestor has rights to delete the token.
    responses:
      200:
        description: the token was successfully deleted
      400:
        description: issue with the request parameters
      503:
        description: Service Unavailable.

    return: success or error message
    """
    data = get_request_data(request)
    address = data.get("address")
    token = data.get("token")

    valid, message = is_token_valid(token, address)
    if not valid:
        return jsonify(error=message), 400

    force_expire_token(token)

    return jsonify(success="Token has been deactivated.")
