#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging

from ocean_provider.models import UserNonce, db

logger = logging.getLogger(__name__)


def get_nonce(address):
    result = UserNonce.query.filter_by(address=address).first()

    return result.nonce if result else UserNonce.FIRST_NONCE


def increment_nonce(address):
    nonce_object = UserNonce.query.filter_by(address=address).first()
    if nonce_object:
        nonce_value = nonce_object.nonce
    else:
        nonce_object = UserNonce(address=address)
        nonce_value = UserNonce.FIRST_NONCE

    logger.debug(
        f"increment_nonce: {address}, {nonce_value}, "
        "new nonce {int(nonce_value) + 1}"
    )

    nonce_object.nonce = int(nonce_value) + 1
    db.session.add(nonce_object)
    db.session.commit()
