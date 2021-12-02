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
    :return: `nonce`
    """
    result = models.UserNonce.query.filter_by(address=address).first()

    return result.nonce if result else models.UserNonce.FIRST_NONCE


def increment_nonce(address):
    """
    Increatements the value of `nonce`
    :param: address
    """
    nonce_object = models.UserNonce.query.filter_by(address=address).first()

    if not nonce_object:
        nonce_object = models.UserNonce(
            address=address, nonce=models.UserNonce.FIRST_NONCE
        )
        db.add(nonce_object)

    nonce_value = nonce_object.nonce
    incremented_nonce = int(nonce_value) + 1

    logger.debug(
        f"increment_nonce: {address}, {nonce_value}, " f"new nonce {incremented_nonce}"
    )

    db.commit()
