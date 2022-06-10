#
# Copyright Ocean Protocol contributors
# SPDX-License-Identifier: Apache-2.0
#
import functools
import json
import logging
import os
import requests
from datetime import datetime

from flask import Response, jsonify, request
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import get_nonce, update_nonce
from ocean_provider.utils.basics import (
    get_config, 
    get_provider_wallet, 
    get_web3
)
from ocean_provider.utils.address import get_provider_fee_token
from ocean_provider.utils.error_responses import error_response
from ocean_provider.utils.util import build_upload_response, get_request_data
from . import services

logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)
requests_session = get_requests_session()


def get_provider_upload_fees(valid_until: int):
    web3 = get_web3()
    provider_wallet = get_provider_wallet()
    provider_fee_address = provider_wallet.address
    provider_fee_token = get_provider_fee_token(web3.chain_id)

    provider_fee_amount = get_config().upload_fee
    if provider_fee_amount:
        provider_fee_amount = int(provider_fee_amount)
    else:
        provider_fee_amount = 0.01

    message_hash = web3.solidityKeccak(
        ["address", "address", "uint256", "uint256"],
        [
            web3.toChecksumAddress(provider_fee_address),
            web3.toChecksumAddress(provider_fee_token),
            provider_fee_amount,
            valid_until,
        ],
    )

    pk = keys.PrivateKey(provider_wallet.key)
    prefix = "\x19Ethereum Signed Message:\n32"
    signable_hash = web3.solidityKeccak(
        ["bytes", "bytes"], [web3.toBytes(text=prefix), web3.toBytes(message_hash)]
    )
    signed = keys.ecdsa_sign(message_hash=signable_hash, private_key=pk)

    provider_fee = {
        "providerFeeAddress": provider_fee_address,
        "providerFeeToken": provider_fee_token,
        "providerFeeAmount": provider_fee_amount,
        # make it compatible with last openzepellin https://github.com/OpenZeppelin/openzeppelin-contracts/pull/1622
        "v": (signed.v + 27) if signed.v <= 1 else signed.v,
        "r": web3.toHex(web3.toBytes(signed.r).rjust(32, b"\0")),
        "s": web3.toHex(web3.toBytes(signed.s).rjust(32, b"\0")),
        "validUntil": valid_until,
    }
    logger.debug(f"Returning provider_fees: {provider_fee}")
    return provider_fee


def validate_upload_order(web3, sender, tx_id):
    logger.debug(
        f"validate_order: tx_id={tx_id}, sender={sender}"
    )
    tx = web3.eth.get_transaction(tx_id)
    tx_nonce = tx['nonce']
    tx_sender = tx['from']
    if tx_sender.lower() != sender.lower():
        raise AssertionError(
            "`uploadOrder` transaction was from a different sender than the one specified.."
        )
    cached_nonce = get_nonce(sender)
    if not cached_nonce or int(cached_nonce) < tx_nonce:
        update_nonce(sender, tx_nonce)
        return tx
    else:
        raise AssertionError(
            "Failed to get tx receipt for the `uploadOrder` transaction.."
        )


@services.route("/initializeUpload", methods=["GET"])
def initializeUpload():
    """Get fee that Provider will charge user for file upload.

    ---
    return:
        json object as follows:
        ```JSON
        {
            "providerFee": <object containing provider fees>
        }
        ```
    """
    data = get_request_data(request)
    logger.info(f"initializeUpload called. arguments = {data}")

    providerFee = get_provider_upload_fees(0)

    response = jsonify(providerFee), 200
    logger.info(f"initializeUpload response = {response}")

    return response


@services.route('/upload', methods=['POST'])
def upload_file():
    """Allows upload of asset data file.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: consumerAddress
        in: query
        description: The consumer address.
        required: true
        type: string
      - name: transferTxId
        in: query
        description: The tx
        required: true
        type: string
      - name: file<i>
        in: request.files
        description: The multipart form data containing files.
        required: true
        type: string
      - name: link<i>
        in: request.files
        description: The multipart form data containing (sample) files.
        required: true
        type: string
    responses:
      201:
        description: Upload successful.
      400:
        description: One or more of the required attributes are missing or invalid.
    returns:
        CIDs of uploaded files.
        Example: {"fileCids": ['0x123...'], "linkCids": []}
    """
    data = get_request_data(request)
    logger.info(f"upload called. arguments = {data}")

    try:
        consumer_address = data.get("consumerAddress")
        tx_id = data.get("transferTxId")
    except Exception as e:
        return error_response(
            f"=Missing argument",
            400,
            logger,
        )

    try:
        _tx = validate_upload_order(
            get_web3(), consumer_address, tx_id,
        )
    except Exception as e:
        return error_response(
            f"=Order with tx_id {tx_id} could not be validated due to error: {e}",
            400,
            logger,
        )

    response = build_upload_response(request, requests_session)
    logger.info(f"upload response = {response}")

    return response
