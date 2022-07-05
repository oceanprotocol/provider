#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import jwt
import logging
from flask import request, jsonify
from flask_sieve import validate
from ocean_provider.utils.util import get_request_data
from ocean_provider.user_nonce import force_expire_token, is_token_valid
from ocean_provider.validation.provider_requests import (
    CreateTokenRequest,
    DeleteTokenRequest,
)

from . import services

logger = logging.getLogger(__name__)


@services.route("/createAuthToken", methods=["GET"])
@validate(CreateTokenRequest)
def create_auth_token():
    # TODO: document endpoint
    data = get_request_data(request)
    address = data.get("address")
    expiration = int(data.get("expiration"))

    token = jwt.encode({"exp": expiration}, address, algorithm="HS256")

    return jsonify(token=token)


@services.route("/deleteAuthToken", methods=["DELETE"])
@validate(DeleteTokenRequest)
def delete_auth_token():
    # TODO: document endpoint
    data = get_request_data(request)
    address = data.get("address")
    token = data.get("token")

    valid, message = is_token_valid(token, address)
    if not valid:
        return jsonify(error=message), 400

    force_expire_token(token)

    return jsonify(success="Token has been deactivated.")
