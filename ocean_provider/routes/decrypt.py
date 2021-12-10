#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
import lzma
from hashlib import sha256
from typing import Optional, Tuple

from eth_typing.encoding import HexStr
from eth_typing.evm import HexAddress
from flask import Response, request
from flask_sieve import validate
from web3.main import Web3

from ocean_provider.log import setup_logging
from ocean_provider.requests_session import get_requests_session
from ocean_provider.user_nonce import update_nonce
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
from ocean_provider.utils.encryption import do_decrypt
from ocean_provider.utils.error_responses import error_response, service_unavailable
from ocean_provider.utils.util import get_request_data
from ocean_provider.validation.provider_requests import DecryptRequest

from . import services

setup_logging()
provider_wallet = get_provider_wallet()
requests_session = get_requests_session()
requests_session.mount("file://", LocalFileAdapter())

logger = logging.getLogger(__name__)


@services.route("/decrypt", methods=["POST"])
@validate(DecryptRequest)
def decrypt():
    data = get_request_data(request)
    logger.info(f"decrypt endpoint called. {data}")

    try:
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
    except Exception as e:
        return service_unavailable(e, data, logger)


def _decrypt(
    decrypter_address: HexStr,
    chain_id: int,
    transaction_id: Optional[HexStr],
    data_nft_address: Optional[HexStr],
    encrypted_document: Optional[HexStr],
    flags: Optional[int],
    document_hash: Optional[HexStr],
    nonce: str,
) -> Response:
    update_nonce(decrypter_address, nonce)

    # Check if given chain_id matches Provider's chain_id
    web3 = get_web3()
    if web3.eth.chain_id != chain_id:
        return error_response(f"Unsupported chain ID", 400)

    # Check if decrypter is authorized
    authorized_decrypters = get_config().authorized_decrypters
    logger.info(f"authorized_decrypters = {authorized_decrypters}")
    if authorized_decrypters and decrypter_address not in authorized_decrypters:
        return error_response(f"Decrypter not authorized", 403)

    if not transaction_id:
        try:
            (encrypted_document, flags, document_hash) = _convert_args_to_bytes(
                encrypted_document, flags, document_hash
            )
        except Exception:
            return error_response(f"Failed to convert input args to bytes.", 400)
    else:
        try:
            (
                data_nft_address,
                encrypted_document,
                flags,
                document_hash,
            ) = _get_args_from_transaction_id(web3, transaction_id)
        except Exception:
            return error_response(f"Failed to process transaction id.", 400)
    logger.info(
        f"data_nft_address = {data_nft_address}, "
        f"encrypted_document as bytes = {encrypted_document}, "
        f"flags as bytes = {flags}, "
        f"document_hash as bytes = {document_hash}"
    )

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
            return error_response(f"Failed to decrypt.", 400)
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
            return error_response(f"Failed to decompress", 400)

    document = working_document
    logger.info(f"document = {document}")

    # Verify checksum matches
    if sha256(document).hexdigest() != document_hash.hex():
        return error_response("Checksum doesn't match.", 400)
    logger.info(f"Checksum matches.")

    return Response(
        document, 201, {"Content-type": "text/plain", "Connection": "close"}
    )


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
    web3: Web3, transaction_id: HexStr
) -> Tuple[HexAddress, bytes, bytes, bytes]:
    """Get the MetadataCreated and MetadataUpdated logs from the transaction id.
    Parse logs and return the data_nft_address, encrypted_document, flags, and
    document_hash.
    """
    tx_receipt = web3.eth.get_transaction_receipt(transaction_id)
    logs = get_metadata_logs_from_tx_receipt(web3, tx_receipt)
    logger.info(f"transaction_id = {transaction_id}, logs = {logs}")
    if len(logs) > 1:
        logger.warning(
            "More than 1 MetadataCreated/MetadataUpdated event detected. "
            "Using the event at index 0."
        )
    log = logs[0]
    return (log.address, log.args["data"], log.args["flags"], log.args["metaDataHash"])
