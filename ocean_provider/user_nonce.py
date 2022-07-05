#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import jwt
import logging
import os

from flask_caching import Cache
from ocean_provider import models
from ocean_provider.myapp import app

logger = logging.getLogger(__name__)
db = app.session

cache = Cache(
    app,
    config={
        "CACHE_TYPE": "redis",
        "CACHE_KEY_PREFIX": "ocean_provider",
        "CACHE_REDIS_URL": os.getenv("REDIS_CONNECTION"),
    },
)


def get_nonce(address):
    """
    :return: `nonce` for the given address stored in the database
    """
    if os.getenv("REDIS_CONNECTION"):
        result = cache.get(address)
        return result if result else None

    result = models.UserNonce.query.filter_by(address=address).first()

    return result.nonce if result else None


def update_nonce(address, nonce_value):
    """
    Updates the value of `nonce` in the database
    :param: address
    :param: nonce_value
    """
    if nonce_value is None:
        return

    if os.getenv("REDIS_CONNECTION"):
        nonce = get_or_create_user_nonce_object(address, nonce_value)
        cache.set(address, nonce)

        return

    nonce_object = get_or_create_user_nonce_object(address, nonce_value)
    nonce_object.nonce = nonce_value

    logger.debug(f"update_nonce: {address}, new nonce {nonce_object.nonce}")

    try:
        db.add(nonce_object)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Database update failed.")
        raise


def get_or_create_user_nonce_object(address, nonce_value):
    if os.getenv("REDIS_CONNECTION"):
        cache.set(address, nonce_value)

        return nonce_value

    nonce_object = models.UserNonce.query.filter_by(address=address).first()
    if nonce_object is None:
        nonce_object = models.UserNonce(address=address, nonce=nonce_value)
    return nonce_object


def force_expire_token(token):
    if os.getenv("REDIS_CONNECTION"):
        cache.set("token//" + token, True)

        return

    existing_token = models.RevokedToken.query.filter_by(token=token).first()
    if existing_token:
        return

    existing_token = models.RevokedToken(token=token)
    try:
        db.add(existing_token)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Database update failed.")
        raise


def is_token_valid(token, address):
    try:
        jwt.decode(token, address, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return False, "Token is expired."
    except Exception:
        return False, "Token is invalid."

    if os.getenv("REDIS_CONNECTION"):
        valid = not cache.get("token//" + token)
    else:
        valid = not models.RevokedToken.query.filter_by(token=token).first()

    message = "" if valid else "Token is deleted."

    return valid, message
