#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
import lzma
from hashlib import sha256

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
from ocean_provider.utils.data_nft import (
    MetadataState,
    get_encrypted_document_and_flags_and_hash_from_tx_id,
    get_metadata,
)
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
    decrypter_address = data.get("decrypterAddress")
    chain_id = data.get("chainId")
    data_nft_address = data.get("dataNftAddress")
    transaction_id = data.get("transactionId")
    encrypted_document = data.get("encryptedDocument")
    flags = data.get("flags")
    document_hash = data.get("documentHash")
    web3 = get_web3()
    try:
        if web3.eth.chain_id != chain_id:
            return Response("Unsupported chain ID", 400, standard_headers)

        authorized_decrypters = get_config().authorized_decrypters

        if authorized_decrypters and decrypter_address not in authorized_decrypters:
            return Response("Decrypter not authorized", 403, standard_headers)

        (_, _, metadata_state, _) = get_metadata(web3, data_nft_address)

        if metadata_state == MetadataState.ACTIVE:
            pass
        elif metadata_state == MetadataState.END_OF_LIFE:
            return Response("Asset end of life", 403, standard_headers)
        elif metadata_state == MetadataState.DEPRECATED:
            return Response("Asset deprecated", 403, standard_headers)
        elif metadata_state == MetadataState.REVOKED:
            return Response("Asset revoked", 403, standard_headers)
        else:
            return Response("Invalid MetadataState", 400, standard_headers)

        if transaction_id:
            (
                encrypted_document,
                flags,
                document_hash,
            ) = get_encrypted_document_and_flags_and_hash_from_tx_id(
                web3, data_nft_address, transaction_id
            )

        try:
            document = do_decrypt(encrypted_document, get_provider_wallet())
        except Exception as e:
            logger.error(f"Failed to decrypt: {str(e)}")

        if not flags:
            logger.debug("Set flags to 0!")
            flags = b"\x00"

        # bit 1:  check if ddo is lzma compressed
        if flags[0] & 1:
            try:
                document = lzma.decompress(document)
            except Exception as e:
                logger.error(f"Failed to decompress: {str(e)}")

        if sha256(document) != document_hash:
            return Response("Checksum doesn't match", 400, standard_headers)

        return Response(document, 201, standard_headers)
    except Exception as e:
        return service_unavailable(e, data, logger)
