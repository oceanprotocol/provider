#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
import lzma
import traceback
from hashlib import sha256

from eth_typing.encoding import HexStr
from flask import Response, request
from flask_sieve import validate
from ocean_provider.log import setup_logging
from ocean_provider.requests_session import get_requests_session
from ocean_provider.routes.consume import encrypt_and_increment_nonce
from ocean_provider.utils.basics import (
    LocalFileAdapter,
    get_config,
    get_provider_wallet,
    get_web3,
)
from ocean_provider.utils.data_nft import MetadataState, get_metadata, get_metadata_logs
from ocean_provider.utils.encryption import do_decrypt
from ocean_provider.utils.util import get_request_data, service_unavailable
from ocean_provider.validation.provider_requests import DecryptRequest, EncryptRequest

from . import services

setup_logging()
provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)

standard_headers = {"Content-type": "text/plain", "Connection": "close"}


@services.route("/encryptDDO", methods=["POST"])
@validate(EncryptRequest)
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
    data = get_request_data(request)
    logger.info(f"encrypt endpoint called. {data}")
    did = data.get("documentId")
    ddo = json.dumps(json.loads(data.get("document")), separators=(",", ":"))
    publisher_address = data.get("publisherAddress")

    encrypted_document = encrypt_and_increment_nonce(did, ddo, publisher_address)
    try:
        return Response(encrypted_document, 201, headers={"content-type": "text/plain"})
    except Exception as e:
        return service_unavailable(e, data, logger)


@services.route("/decryptDDO", methods=["POST"])
@validate(DecryptRequest)
def decryptDDO():
    data = get_request_data(request)
    logger.info(f"decrypt endpoint called. {data}")

    try:
        return _decryptDDO(
            decrypter_address=data.get("decrypterAddress"),
            chain_id=data.get("chainId"),
            data_nft_address=data.get("dataNftAddress"),
            transaction_id=data.get("transactionId"),
            encrypted_document=data.get("encryptedDocument"),
            flags=data.get("flags"),
            document_hash=data.get("documentHash"),
        )
    except Exception as e:
        return service_unavailable(e, data, logger)


def _decryptDDO(
    decrypter_address: HexStr,
    chain_id: int,
    data_nft_address: HexStr,
    transaction_id: HexStr,
    encrypted_document: bytes,
    flags: bytes,
    document_hash: bytes,
):
    web3 = get_web3()
    if web3.eth.chain_id != chain_id:
        return error_response(f"Unsupported chain ID", 400)

    authorized_decrypters = get_config().authorized_decrypters
    logger.info(f"authorized_decrypters = {authorized_decrypters}")

    if authorized_decrypters and decrypter_address not in authorized_decrypters:
        return error_response(f"Decrypter not authorized", 403)

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

    if transaction_id:
        try:
            logs = get_metadata_logs(web3, data_nft_address, transaction_id)
            logger.info(f"transaction_id = {transaction_id}, logs = {logs}")
            log_args = logs[0].args
            encrypted_document = log_args["data"]
            flags = log_args["flags"]
            document_hash = log_args["metaDataHash"]
            logger.info(
                f"encrypted_document = {encrypted_document}, "
                f"flags = {flags}, "
                f"document_hash = {document_hash}"
            )
        except Exception:
            response = error_response(f"Failed to get metadata logs.", 400)
            logger.error(f"{traceback.format_exc()}")
            return response

    try:
        document = do_decrypt(encrypted_document.decode("utf-8"), get_provider_wallet())
        logger.info("Successfully decrypted document.")
    except Exception:
        response = error_response(f"Failed to decrypt.", 400)
        logger.error(f"{traceback.format_exc()}")
        return response

    if not flags:
        logger.debug("Set flags to 0!")
        flags = b"\x00"

    # bit 1:  check if ddo is lzma compressed
    if flags[0] & 1:
        try:
            document = lzma.decompress(document)
            logger.info("Successfully decompressed document.")
        except Exception:
            response = error_response(f"Failed to decompress", 400)
            logger.error(f"{traceback.format_exc()}")
            return response

    logger.info(f"document = {document}")

    if sha256(document.encode("utf-8")).hexdigest() != document_hash.hex():
        return error_response("Checksum doesn't match.", 400)

    return Response(document, 201, standard_headers)


def error_response(err_str: str, status: int) -> Response:
    logger.error(err_str)
    return Response(err_str, status, standard_headers)
