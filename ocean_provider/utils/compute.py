#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import os
from datetime import datetime, timezone
from urllib.parse import urljoin

from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from ocean_provider.user_nonce import get_nonce
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.basics import get_provider_wallet

logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)


def get_compute_endpoint():
    return urljoin(os.getenv("OPERATOR_SERVICE_URL"), "api/v1/operator/compute")


def get_compute_result_endpoint():
    return urljoin(os.getenv("OPERATOR_SERVICE_URL"), "api/v1/operator/getResult")


def process_compute_request(data):
    provider_wallet = get_provider_wallet(use_universal_key=True)
    did = data.get("documentId")
    owner = data.get("consumerAddress")
    job_id = data.get("jobId")
    body = dict()
    body["providerAddress"] = provider_wallet.address
    if owner is not None:
        body["owner"] = owner
    if job_id is not None:
        body["jobId"] = job_id
    if did is not None:
        body["documentId"] = did

    nonce, provider_signature = sign_for_compute(provider_wallet, owner, job_id)
    body["providerSignature"] = provider_signature
    body["nonce"] = nonce

    return body


def sign_for_compute(wallet, owner, job_id=None):
    nonce = datetime.now(timezone.utc).timestamp() * 1000

    # prepare consumer signature on did
    msg = f"{owner}{job_id}{nonce}" if job_id else f"{owner}{nonce}"
    signature = sign_message(msg, wallet)

    return nonce, signature
