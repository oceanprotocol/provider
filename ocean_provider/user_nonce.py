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
    result = models.UserNonce.query.filter_by(address=address).first()

    return result.nonce if result else models.UserNonce.FIRST_NONCE


def increment_nonce(address):
    nonce_object = models.UserNonce.query.filter_by(address=address).first()
    if nonce_object:
        nonce_value = nonce_object.nonce
    else:
        nonce_object = models.UserNonce(address=address)
        nonce_value = models.UserNonce.FIRST_NONCE

    logger.debug(
        f"increment_nonce: {address}, {nonce_value}, "
        "new nonce {int(nonce_value) + 1}"
    )

    nonce_object.nonce = int(nonce_value) + 1
    db.add(nonce_object)
    db.commit()
