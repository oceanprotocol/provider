#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from ocean_provider import models
from ocean_provider.myapp import app

logger = logging.getLogger(__name__)
db = app.session


def get_nonce(address):
    """
    :return: `nonce` for the given address stored in the database
    """
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
    nonce_object = models.UserNonce.query.filter_by(address=address).first()
    if nonce_object is None:
        nonce_object = models.UserNonce(address=address, nonce=nonce_value)
    return nonce_object
