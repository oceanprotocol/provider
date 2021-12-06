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

    return result.nonce if result else models.UserNonce.FIRST_NONCE


def increment_nonce(address):
    """
    Increments the value of `nonce` in the database
    :param: address
    """
    nonce_object = get_or_create_user_nonce_object(address)
    nonce_value = nonce_object.nonce
    incremented_nonce = int(nonce_value) + 1
    nonce_object.nonce = incremented_nonce

    logger.debug(
        f"increment_nonce: {address}, {nonce_value}, new nonce {incremented_nonce}"
    )

    try:
        db.add(nonce_object)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception(f"Database update failed.")
        raise


def get_or_create_user_nonce_object(address):
    nonce_object = models.UserNonce.query.filter_by(address=address).first()
    if nonce_object is None:
        nonce_object = models.UserNonce(
            address=address, nonce=models.UserNonce.FIRST_NONCE
        )
    return nonce_object
