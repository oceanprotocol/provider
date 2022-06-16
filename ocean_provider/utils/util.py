#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import hashlib
import json
import logging
import mimetypes
import os
from cgi import parse_header
from typing import Any, Dict, Tuple
from urllib.parse import urljoin

import werkzeug
from eth_account.signers.local import LocalAccount
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from eth_typing.encoding import HexStr
from flask import Response
from ocean_provider.utils.asset import Asset
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.utils.encryption import do_decrypt
from ocean_provider.utils.services import Service
from ocean_provider.utils.url import append_userdata, check_url_details
from web3 import Web3
from web3.types import TxParams, TxReceipt

logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)


def get_request_data(request):
    try:
        return request.args if request.args else request.json
    except werkzeug.exceptions.BadRequest:
        return {}


def msg_hash(message: str):
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def build_download_response(
    request, requests_session, download_url, content_type=None, method="GET"
):
    try:
        download_request_headers = {}
        download_response_headers = {}
        is_range_request = bool(request.range)

        if is_range_request:
            download_request_headers = {"Range": request.headers.get("range")}
            download_response_headers = download_request_headers

        if method.lower() not in ["get", "post"]:
            raise ValueError(f"Unsafe method {method}")

        method = getattr(requests_session, method.lower())
        response = method(
            download_url, headers=download_request_headers, stream=True, timeout=3
        )
        if not is_range_request:
            filename = download_url.split("/")[-1]

            content_disposition_header = response.headers.get("content-disposition")
            if content_disposition_header:
                _, content_disposition_params = parse_header(content_disposition_header)
                content_filename = content_disposition_params.get("filename")
                if content_filename:
                    filename = content_filename

            content_type_header = response.headers.get("content-type")
            if content_type_header:
                content_type = content_type_header

            file_ext = os.path.splitext(filename)[1]
            if file_ext and not content_type:
                content_type = mimetypes.guess_type(filename)[0]
            elif not file_ext and content_type:
                # add an extension to filename based on the content_type
                extension = mimetypes.guess_extension(content_type)
                if extension:
                    filename = filename + extension

            download_response_headers = {
                "Content-Disposition": f"attachment;filename={filename}",
                "Access-Control-Expose-Headers": "Content-Disposition",
                "Connection": "close",
            }

        def _generate(_response):
            for chunk in _response.iter_content(chunk_size=4096):
                if chunk:
                    yield chunk

        return Response(
            _generate(response),
            response.status_code,
            headers=download_response_headers,
            content_type=content_type,
        )
    except Exception as e:
        logger.error(f"Error preparing file download response: {str(e)}")
        raise


def get_service_files_list(
    service: Service, provider_wallet: LocalAccount, asset: Asset = None
) -> list:
    version = asset.version if asset is not None and asset.version else "4.0.0"
    if asset is None or version == "4.0.0":
        return get_service_files_list_old_structure(service, provider_wallet)

    try:
        files_str = do_decrypt(service.encrypted_files, provider_wallet)
        if not files_str:
            return None

        files_json = json.loads(files_str)

        for key in ["datatokenAddress", "nftAddress", "files"]:
            if key not in files_json:
                raise Exception(f"Key {key} not found in files.")

        if Web3.toChecksumAddress(
            files_json["datatokenAddress"]
        ) != Web3.toChecksumAddress(service.datatoken_address):
            raise Exception(
                f"Mismatch of datatoken. Got {files_json['datatokenAddress']} vs expected {service.datatoken_address}"
            )

        if Web3.toChecksumAddress(files_json["nftAddress"]) != Web3.toChecksumAddress(
            asset.nftAddress
        ):
            raise Exception(
                f"Mismatch of dataNft. Got {files_json['nftAddress']} vs expected {asset.nftAddress}"
            )

        files_list = files_json["files"]
        if not isinstance(files_list, list):
            raise TypeError(f"Expected a files list, got {type(files_list)}.")

        return files_list
    except Exception as e:
        logger.error(f"Error decrypting service files {Service}: {str(e)}")
        return None


def get_service_files_list_old_structure(
    service: Service, provider_wallet: LocalAccount
) -> list:
    try:
        files_str = do_decrypt(service.encrypted_files, provider_wallet)
        if not files_str:
            return None
        logger.debug(f"Got decrypted files str {files_str}")
        files_list = json.loads(files_str)
        if not isinstance(files_list, list):
            raise TypeError(f"Expected a files list, got {type(files_list)}.")

        return files_list
    except Exception as e:
        logger.error(f"Error decrypting service files {Service}: {str(e)}")
        return None


def validate_url_object(url_object, service_id):
    if not url_object:
        return False, f"cannot decrypt files for this service. id={service_id}"

    if "type" not in url_object or url_object["type"] not in ["ipfs", "url", "arweave"]:
        return (
            False,
            f"malformed or unsupported type for service files. id={service_id}",
        )

    if (
        (url_object["type"] == "ipfs" and "hash" not in url_object)
        or (url_object["type"] == "url" and "url" not in url_object)
        or (url_object["type"] == "arweave" and "transactionId" not in url_object)
    ):
        return False, f"malformed service files, missing required keys. id={service_id}"

    return True, ""


def get_download_url(url_object: Dict[str, Any]) -> str:
    if url_object["type"] == "url":
        return url_object["url"]
    elif url_object["type"] == "ipfs":
        if not os.getenv("IPFS_GATEWAY"):
            raise ValueError("No IPFS_GATEWAY defined, can not resolve ipfs hash.")
        return urljoin(os.getenv("IPFS_GATEWAY"), urljoin("ipfs/", url_object["hash"]))
    elif url_object["type"] == "arweave":
        if not os.getenv("ARWEAVE_GATEWAY"):
            raise ValueError(
                "No ARWEAVE_GATEWAY defined, can not resolve arweave transaction id."
            )
        return urljoin(os.getenv("ARWEAVE_GATEWAY"), url_object["transactionId"])
    else:
        raise ValueError(f"URL object type {url_object['type']} not supported.")


def check_url_valid(service, file_index, data, asset):
    provider_wallet = get_provider_wallet()

    url_object = get_service_files_list(service, provider_wallet, asset)[file_index]
    url_valid, message = validate_url_object(url_object, service.id)
    if not url_valid:
        return False, message

    download_url = get_download_url(url_object)
    download_url = append_userdata(download_url, data)
    valid, url_details = check_url_details(download_url)

    if not valid:
        logger.error(
            f"Error: Asset URL not found or not available. \n" f"Payload was: {data}",
            exc_info=1,
        )

        if not url_details:
            url_details = "Asset URL not found or not available."

    return valid, url_details


def sign_tx(web3, tx, private_key):
    """
    :param web3: Web3 object instance
    :param tx: transaction
    :param private_key: Private key of the account
    :return: rawTransaction (str)
    """
    account = web3.eth.account.from_key(private_key)
    nonce = web3.eth.get_transaction_count(account.address)
    tx["nonce"] = nonce
    signed_tx = web3.eth.account.sign_transaction(tx, private_key)

    return signed_tx.rawTransaction


def sign_and_send(
    web3: Web3, transaction: TxParams, from_account: LocalAccount
) -> Tuple[HexStr, TxReceipt]:
    """Returns the transaction id and transaction receipt."""
    transaction_signed = sign_tx(web3, transaction, from_account.key)
    transaction_hash = web3.eth.send_raw_transaction(transaction_signed)
    transaction_id = Web3.toHex(transaction_hash)

    return transaction_hash, transaction_id


def sign_send_and_wait_for_receipt(
    web3: Web3, transaction: TxParams, from_account: LocalAccount
) -> Tuple[HexStr, TxReceipt]:
    """Returns the transaction id and transaction receipt."""
    transaction_hash, transaction_id = sign_and_send(web3, transaction, from_account)

    return (transaction_id, web3.eth.wait_for_transaction_receipt(transaction_hash))
