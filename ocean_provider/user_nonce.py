#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import os
import sqlite3

import jwt
from flask_caching import Cache
from ocean_provider import models
from ocean_provider.myapp import app
from ocean_provider.utils.basics import get_provider_private_key
from web3.main import Web3

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
        logger.debug(f"Nonce value is not provided.")
        return

    logger.debug(f"Received nonce value: {nonce_value}")

    if os.getenv("REDIS_CONNECTION"):
        cache.set(address, nonce_value)

        return

    nonce_object = models.UserNonce.query.filter_by(address=address).first()
    if nonce_object is None:
        nonce_object = models.UserNonce(address=address, nonce=nonce_value)
    else:
        if nonce_object.nonce == nonce_value:
            msg = f"Cannot create duplicates in the database.\n Existing nonce: {nonce_object.nonce} vs. new nonce: {nonce_value}"
            logger.debug(msg)
            raise sqlite3.IntegrityError(msg)

        nonce_object.nonce = nonce_value

    logger.debug(f"Wallet address: {address}, new nonce {nonce_object.nonce}")

    try:
        db.add(nonce_object)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Database update failed.")
        raise


def force_expire_token(token):
    """
    Creates the token in the database of Revoked Tokens.
    :param: token
    """
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


def force_restore_token(token):
    """
    Removes the token from the database of Revoked Tokens.
    :param: token
    """
    if os.getenv("REDIS_CONNECTION"):
        cache.delete("token//" + token)

        return

    existing_token = models.RevokedToken.query.filter_by(token=token).first()
    if not existing_token:
        return

    try:
        db.delete(existing_token)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Database update failed.")
        raise


def is_token_valid(token, address):
    """
    Decodes the token, checks expiration, ownership and presence in the blacklist.

    Returns a tuple of boolean, message representing validity and issue (only if invalid).
    :param: token
    """
    try:
        pk = get_provider_private_key(use_universal_key=True)
        decoded = jwt.decode(token, pk, algorithms=["HS256"])
        if Web3.toChecksumAddress(decoded["address"]) != Web3.toChecksumAddress(
            address
        ):
            return False, "Token is invalid."
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
