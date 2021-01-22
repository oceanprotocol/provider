import logging
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import uuid4

from ocean_provider.myapp import AccessToken, db

logger = logging.getLogger(__name__)


def generate_access_token(
    did, consumer_address, tx_id, seconds_to_exp, delegate_address
):
    access_token = str(uuid4())
    access_token = sha256(access_token.encode('utf-8')).hexdigest()
    expiry_time = datetime.now() + timedelta(seconds=int(seconds_to_exp))

    at_object = AccessToken(**{
        'access_token': access_token,
        'did': did,
        'consumer_address': consumer_address,
        'delegate_address': delegate_address,
        'tx_id': tx_id,
        'expiry_time': expiry_time,
    })

    db.session.add(at_object)
    db.session.commit()

    return access_token


def check_unique_access_token(did, consumer_address, tx_id, delegate_address):
    result = AccessToken.query.filter_by(
        did=did,
        consumer_address=consumer_address,
        delegate_address=delegate_address,
        tx_id=tx_id
    ).first()

    return not result


def get_access_token(delegate_address, did, tx_id):
    result = AccessToken.query.filter(
        AccessToken.expiry_time > datetime.now(),
        AccessToken.did == did,
        AccessToken.delegate_address == delegate_address,
        AccessToken.tx_id == tx_id
    ).first()

    return (result.consumer_address, result.access_token) if result else (None, None)
