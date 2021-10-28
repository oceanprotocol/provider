#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import lzma
import traceback
from hashlib import sha256
from typing import Optional

from eth_typing.encoding import HexStr
from flask import Response, request
from flask_sieve import validate
from ocean_provider.log import setup_logging
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import increment_nonce
from ocean_provider.utils.basics import (
    LocalFileAdapter,
    get_config,
    get_provider_wallet,
    get_web3,
)
from ocean_provider.utils.data_nft import (
    MetadataState,
    get_metadata,
    get_metadata_logs_from_tx_receipt,
)
from ocean_provider.utils.encryption import do_decrypt, do_encrypt
from ocean_provider.utils.util import get_request_data, service_unavailable
from ocean_provider.validation.provider_requests import DecryptRequest
from web3.main import Web3

from . import services

setup_logging()
provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "text/plain", "Connection": "close"}
# {'charset': 'utf-8'}


@services.route("/encryptDDO", methods=["POST"])
def encryptDDO():
    """Encrypt DDO using the Provider's own symmetric key (symmetric encryption).
    This can be used by the publisher of an asset to encrypt the DDO of the
    asset data files before publishing the asset DDO. The publisher to use this
    service is one that is using a front-end with a wallet app such as MetaMask.
    The DDO is encrypted by the provider so that the provider will be able
    to decrypt at time of providing the service later on.

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        description: Asset urls encryption.
        schema:
          type: object
          required:
            - documentId
            - document
            - publisherAddress:
          properties:
            documentId:
              description: Identifier of the asset to be registered in ocean.
              type: string
              example: 'did:op:08a429b8529856d59867503f8056903a680935a76950bb9649785cc97869a43d'
            ddo:
              description: document description object (DDO)
              type: string
              example: See https://github.com/oceanprotocol/docs/blob/feature/ddo_v4/content/concepts/did-ddo.md
            publisherAddress:
              description: Publisher address.
              type: string
              example: '0x00a329c0648769A73afAc7F9381E08FB43dBEA72'
    responses:
      201:
        description: DDO successfully encrypted.
      503:
        description: Service Unavailable

    return: the encrypted DDO (hex str)
    """
    if request.content_type != "application/octet-stream":
        return error_response(
            "Invalid request content type: should be application/octet-stream", 400
        )

    data = request.get_data()
    logger.info(f"encryptDDO endpoint called. {data}")

    try:
        return _encryptDDO(data)
    except Exception as e:
        return service_unavailable(e, data, logger)


def _encryptDDO(data: bytes) -> Response:

    try:
        encrypted_data = do_encrypt(data, provider_wallet)
        logger.info(f"encrypted_data = {encrypted_data}")
    except Exception:
        return error_response(f"Failed to encrypt.", 400)
    return Response(encrypted_data, 201, headers=standard_headers)


@services.route("/decryptDDO", methods=["POST"])
@validate(DecryptRequest)
def decryptDDO():
    data = get_request_data(request)
    logger.info(f"decryptDDO endpoint called. {data}")

    try:
        return _decryptDDO(
            decrypter_address=data.get("decrypterAddress"),
            chain_id=data.get("chainId"),
            transaction_id=data.get("transactionId"),
            data_nft_address=data.get("dataNftAddress"),
            encrypted_document=data.get("encryptedDocument"),
            flags=data.get("flags"),
            document_hash=data.get("documentHash"),
        )
    except Exception as e:
        return service_unavailable(e, data, logger)


def _decryptDDO(
    decrypter_address: HexStr,
    chain_id: int,
    transaction_id: Optional[HexStr],
    data_nft_address: Optional[HexStr],
    encrypted_document: Optional[HexStr],
    flags: Optional[int],
    document_hash: Optional[HexStr],
) -> Response:
    increment_nonce(decrypter_address)

    # Check if given chain_id matches Provider's chain_id
    web3 = get_web3()
    if web3.eth.chain_id != chain_id:
        return error_response(f"Unsupported chain ID", 400)

    # Check if decrypter is authorized
    authorized_decrypters = get_config().authorized_decrypters
    logger.info(f"authorized_decrypters = {authorized_decrypters}")
    if authorized_decrypters and decrypter_address not in authorized_decrypters:
        return error_response(f"Decrypter not authorized", 403)

    # Get arguments from transaction_id
    if transaction_id:
        try:
            tx_receipt = web3.eth.get_transaction_receipt(transaction_id)
            logs = get_metadata_logs_from_tx_receipt(web3, tx_receipt)
            logger.info(f"transaction_id = {transaction_id}, logs = {logs}")
            if len(logs) > 1:
                logger.warning(
                    "More than 1 MetadataCreated/MetadataUpdated event detected. "
                    "Using the event at index 0."
                )

            log = logs[0]
            data_nft_address = log.address
            # Interpret "data" as utf-8 encoded bytes
            encrypted_document = log.args["data"]
            # Interpret "flags" as array of bytes length 1
            flags = log.args["flags"]
            # Interpret metaDataHash" as utf-8 encoded bytes
            document_hash = log.args["metaDataHash"]
            logger.info(
                f"data_nft_address = {data_nft_address}, "
                f"encrypted_document = {encrypted_document}, "
                f"flags = {flags}, "
                f"document_hash = {document_hash}"
            )
        except Exception:
            response = error_response(f"Failed to get metadata logs.", 400)
            logger.error(f"{traceback.format_exc()}")
            return response
    else:
        try:
            encrypted_document = Web3.toBytes(hexstr=encrypted_document)
            flags = flags.to_bytes(1, "big")
            document_hash = Web3.toBytes(hexstr=document_hash)
        except Exception:
            return error_response(f"Failed converting input args to bytes.", 400)

    assert isinstance(encrypted_document, bytes)
    assert isinstance(flags, bytes)
    assert isinstance(document_hash, bytes)

    # Check if DDO metadata state is ACTIVE
    (_, _, metadata_state, _) = get_metadata(web3, data_nft_address)
    logger.info(f"metadata_state = {metadata_state}")
    if metadata_state == MetadataState.ACTIVE:
        pass
    elif metadata_state == MetadataState.END_OF_LIFE:
        return error_response(f"Asset end of life", 403)
    elif metadata_state == MetadataState.DEPRECATED:
        return error_response(f"Asset deprecated", 403)
    elif metadata_state == MetadataState.REVOKED:
        return error_response(f"Asset revoked", 403)
    else:
        return error_response(f"Invalid MetadataState", 400)

    working_document = encrypted_document

    # bit 2:  check if DDO is ecies encrypted
    if flags[0] & 2:
        try:
            working_document = do_decrypt(working_document, get_provider_wallet())
            logger.info("Successfully decrypted document.")
        except Exception:
            response = error_response(f"Failed to decrypt.", 400)
            logger.error(f"{traceback.format_exc()}")
            return response
    else:
        logger.warning(
            "Document not encrypted (flags bit 2 not set). Skipping decryption."
        )

    # bit 1:  check if DDO is lzma compressed
    if flags[0] & 1:
        try:
            working_document = lzma.decompress(working_document)
            logger.info("Successfully decompressed document.")
        except Exception:
            response = error_response(f"Failed to decompress", 400)
            logger.error(f"{traceback.format_exc()}")
            return response

    document = working_document
    logger.info(f"document = {document}")

    assert isinstance(encrypted_document, bytes)
    assert isinstance(flags, bytes)
    assert isinstance(document_hash, bytes)

    # Verify checksum matches
    if sha256(document).hexdigest() != document_hash.hex():
        return error_response("Checksum doesn't match.", 400)
    logger.info(f"Checksum matches.")

    return Response(document, 201, standard_headers)


def error_response(err_str: str, status: int) -> Response:
    logger.error(err_str)
    return Response(err_str, status, standard_headers)
