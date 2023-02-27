#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import lzma
from hashlib import sha256
from typing import Optional, Tuple

from eth_typing.encoding import HexStr
from flask import Response, request
from flask_sieve import validate
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import update_nonce
from ocean_provider.utils.basics import (
    get_config,
    get_provider_wallet,
    get_web3,
)
from ocean_provider.utils.data_nft import (
    MetadataState,
    get_metadata,
    get_metadata_logs_from_tx_receipt,
)
from ocean_provider.utils.data_nft_factory import is_nft_deployed_from_factory
from ocean_provider.utils.encryption import do_decrypt
from ocean_provider.utils.error_responses import error_response
from ocean_provider.utils.util import get_request_data
from ocean_provider.validation.provider_requests import DecryptRequest
from web3.main import Web3

from . import services

provider_wallet = get_provider_wallet()
requests_session = get_requests_session()

logger = logging.getLogger(__name__)


@services.route("/decrypt", methods=["POST"])
@validate(DecryptRequest)
def decrypt():
    """Decrypts an encrypted document based on transaction Id or dataNftAddress.

    ---
    consumes:
      - application/json
    parameters:
      - name: decrypterAddress
        description: address of agent requesting decrypt
        type: string
        required: true
      - name: chainId
        description: chainId of the chain on which the encrypted document is stored
        type: int
        required: true
      - name: transactionId
        description: transaction Id where the document was created or last updated,
            required if dataNftAddress, encryptedDocument and flags parameters missing
        required: false
        type: string
      - name: dataNftAddress
        description: NFT address of the document,
            required if the transactionId parameter is missing
        required: false
        type: string
      - name: encryptedDocument
        description: encrypted document contents,
            required if the transactionId parameter is missing
        required: false
        type: string
      - name: flags
        description: encryption and compression flags,
            required if the transactionId parameter is missing
        required: false
        type: int
      - name: documentHash
        description: hash of the original document used for integrity check,
            required if the transactionId parameter is missing
        required: false
        type: int
      - name: nonce
        description: user nonce (timestamp)
        required: true
        type: decimal
      - name: signature
        description: user signature based on
            transactionId+dataNftAddress+decrypterAddress+chainId+nonce
        required: true
        type: string
    responses:
      201:
        description: decrypted document
      400:
        description: One or more of the required attributes are missing or invalid.
      503:
        description: Service Unavailable
    """
    data = get_request_data(request)
    logger.info(f"decrypt called. arguments = {data}")

    return _decrypt(
        decrypter_address=data.get("decrypterAddress"),
        chain_id=data.get("chainId"),
        transaction_id=data.get("transactionId"),
        data_nft_address=data.get("dataNftAddress"),
        encrypted_document=data.get("encryptedDocument"),
        flags=data.get("flags"),
        document_hash=data.get("documentHash"),
        nonce=data.get("nonce"),
    )


def _decrypt(
    decrypter_address: HexStr,
    chain_id: int,
    transaction_id: Optional[HexStr],
    data_nft_address: HexStr,
    encrypted_document: Optional[HexStr],
    flags: Optional[int],
    document_hash: Optional[HexStr],
    nonce: str,
) -> Response:
    update_nonce(decrypter_address, nonce)

    # Check if given chain_id matches Provider's chain_id
    web3 = get_web3()
    if web3.chain_id != chain_id:
        return error_response(f"Unsupported chain ID {chain_id}", 400, logger)

    # Check if decrypter is authorized
    authorized_decrypters = get_config().authorized_decrypters
    logger.info(f"authorized_decrypters = {authorized_decrypters}")
    if authorized_decrypters and decrypter_address not in authorized_decrypters:
        return error_response("Decrypter not authorized", 403, logger)

    if not is_nft_deployed_from_factory(web3, data_nft_address):
        return error_response(
            "Asset not deployed by the data NFT factory.", 400, logger
        )

    if not transaction_id:
        try:
            (encrypted_document, flags, document_hash) = _convert_args_to_bytes(
                encrypted_document, flags, document_hash
            )
        except Exception:
            return error_response("Failed to convert input args to bytes.", 400, logger)
    else:
        try:
            (
                encrypted_document,
                flags,
                document_hash,
            ) = _get_args_from_transaction_id(web3, transaction_id, data_nft_address)
        except Exception:
            return error_response("Failed to process transaction id.", 400, logger)
    logger.info(
        f"data_nft_address = {data_nft_address}, "
        f"encrypted_document as bytes = {encrypted_document}, "
        f"flags as bytes = {flags}, "
        f"document_hash as bytes = {document_hash}"
    )

    # Check if DDO metadata state is ACTIVE
    (_, _, metadata_state, _) = get_metadata(web3, data_nft_address)
    logger.info(f"metadata_state = {metadata_state}")
    if metadata_state in [
        MetadataState.ACTIVE,
        MetadataState.TEMPORARILY_DISABLED,
        MetadataState.UNLISTED,
    ]:
        pass
    elif metadata_state == MetadataState.END_OF_LIFE:
        return error_response("Asset end of life", 403, logger)
    elif metadata_state == MetadataState.DEPRECATED:
        return error_response("Asset deprecated", 403, logger)
    elif metadata_state == MetadataState.REVOKED:
        return error_response("Asset revoked", 403, logger)
    else:
        return error_response("Invalid MetadataState", 400, logger)

    working_document = encrypted_document

    # bit 2:  check if DDO is ecies encrypted
    if flags[0] & 2:
        try:
            working_document = do_decrypt(working_document, get_provider_wallet())
            logger.info("Successfully decrypted document.")
        except Exception:
            return error_response("Failed to decrypt.", 400, logger)
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
            return error_response("Failed to decompress", 400, logger)

    document = working_document
    logger.info(f"document = {document}")

    # Verify checksum matches
    if sha256(document).hexdigest() != document_hash.hex():
        return error_response("Checksum doesn't match.", 400, logger)
    logger.info("Checksum matches.")

    response = Response(document, 201, {"Content-type": "text/plain"})
    logger.info(f"decrypt response = {response}")
    return response


def _convert_args_to_bytes(
    encrypted_document: HexStr, flags: int, document_hash: HexStr
) -> Tuple[bytes, bytes, bytes]:
    """Return the encrypted_document, flags, and document_hash as bytes."""
    return (
        Web3.toBytes(hexstr=encrypted_document),
        flags.to_bytes(1, "big"),
        Web3.toBytes(hexstr=document_hash),
    )


def _get_args_from_transaction_id(
    web3: Web3, transaction_id: HexStr, data_nft_address: HexStr
) -> Tuple[bytes, bytes, bytes]:
    """Get the MetadataCreated and MetadataUpdated logs from the transaction id.
    Parse logs and return the data_nft_address, encrypted_document, flags, and
    document_hash.
    """
    tx_receipt = web3.eth.get_transaction_receipt(transaction_id)
    logs = get_metadata_logs_from_tx_receipt(web3, tx_receipt, data_nft_address)
    logger.info(f"transaction_id = {transaction_id}, logs = {logs}")
    if len(logs) > 1:
        logger.warning(
            "More than 1 MetadataCreated/MetadataUpdated event detected. "
            "Using the event at index 0."
        )

    log = logs[0]
    return (log.args["data"], log.args["flags"], log.args["metaDataHash"])
