#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import jwt
import logging
from flask import request, jsonify
from ocean_provider.utils.util import get_request_data
from ocean_provider.user_nonce import force_expire_token

from . import services

logger = logging.getLogger(__name__)


@services.route("/createAuthToken", methods=["GET"])
# @validate(DecryptRequest) TODO request validation
def create_auth_token():
    # TODO: document endpoint
    data = get_request_data(request)
    address = data.get("address")
    expiration = int(data.get("expiration"))

    token = jwt.encode({"exp": expiration}, address, algorithm="HS256")

    # TODO: exceptions etc.
    return jsonify(token=token)


@services.route("/deleteAuthToken", methods=["DELETE"])
# @validate(DecryptRequest) TODO request validation
def delete_auth_token():
    # TODO: document endpoint
    data = get_request_data(request)
    address = data.get("address")
    token = data.get("token")
    # TODO: exceptions etc.
    # when checking, check still valid with DB/redis

    try:
        jwt.decode(token, address, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify(error="Token is already expired."), 400
    except Exception:
        return jsonify(error="Token is invalid."), 400

    force_expire_token(token)

    return jsonify(success="Token has been deactivated")
