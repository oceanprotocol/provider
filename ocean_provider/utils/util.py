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
from urllib.parse import urljoin
from datetime import datetime

import requests
import werkzeug
from jsonsempai import magic  # noqa: F401
from artifacts import ERC721Template
from eth_account.signers.local import LocalAccount
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from flask import Response
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.basics import get_config, get_provider_wallet, get_web3
from ocean_provider.utils.consumable import ConsumableCodes
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.data_nft import get_data_nft_contract
from ocean_provider.utils.datatoken import verify_order_tx
from ocean_provider.utils.encryption import do_decrypt
from ocean_provider.utils.services import Service
from ocean_provider.utils.url import is_safe_url, append_userdata, check_url_details
from websockets import ConnectionClosed

logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)


def get_metadata_url():
    return get_config().aquarius_url


def get_request_data(request):
    try:
        return request.args if request.args else request.json
    except werkzeug.exceptions.BadRequest:
        return {}


def msg_hash(message: str):
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def build_download_response(
    request,
    requests_session,
    url,
    download_url,
    content_type=None,
    method="GET",
    validate_url=True,
):
    try:
        if validate_url and not is_safe_url(url):
            raise ValueError(f"Unsafe url {url}")
        download_request_headers = {}
        download_response_headers = {}
        is_range_request = bool(request.range)

        if is_range_request:
            download_request_headers = {"Range": request.headers.get("range")}
            download_response_headers = download_request_headers

        method = getattr(requests_session, method.lower())
        response = method(
            download_url, headers=download_request_headers, stream=True, timeout=3
        )
        if not is_range_request:
            filename = url.split("/")[-1]

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


def get_service_files_list(service: Service, provider_wallet: LocalAccount) -> list:
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

    if "type" not in url_object or url_object["type"] not in ["ipfs", "url"]:
        return (
            False,
            f"malformed or unsupported type for service files. id={service_id}",
        )

    if (url_object["type"] == "ipfs" and "hash" not in url_object) or (
        url_object["type"] == "url" and "url" not in url_object
    ):
        return False, f"malformed service files, missing required keys. id={service_id}"

    return True, ""


def get_download_url(url_object):
    if url_object["type"] != "ipfs":
        return url_object["url"]

    if not os.getenv("IPFS_GATEWAY"):
        raise Exception("No IPFS_GATEWAY defined, can not resolve ipfs hash.")

    return urljoin(os.getenv("IPFS_GATEWAY"), urljoin("ipfs/", url_object["hash"]))


def get_compute_endpoint():
    return urljoin(get_config().operator_service_url, "api/v1/operator/compute")


def get_compute_environments_endpoint():
    return urljoin(get_config().operator_service_url, "api/v1/operator/environments")


def get_compute_result_endpoint():
    return urljoin(get_config().operator_service_url, "api/v1/operator/getResult")


def get_compute_info():
    try:
        compute_info = requests.get(get_config().operator_service_url).json()
        limits = {
            "algoTimeLimit": compute_info.get("algoTimeLimit"),
            "storageExpiry": compute_info.get("storageExpiry"),
        }
        compute_address = compute_info.get("address", None)
        return compute_address, limits
    except Exception as e:
        logger.error(f"Error getting CtD address: {str(e)}")
        return None, None


def validate_order(web3, sender, tx_id, asset, service, extra_data=None, allow_expired_provider_fee=False):
    did = asset.did
    token_address = service.datatoken_address
    num_tokens = 1

    logger.debug(
        f"validate_order: did={did}, service_id={service.id}, tx_id={tx_id}, "
        f"sender={sender}, num_tokens={num_tokens}, token_address={token_address}"
    )

    nft_contract = get_data_nft_contract(web3, asset.nft["address"])
    assert nft_contract.caller.isDeployed(token_address)

    amount = to_wei(num_tokens)
    num_tries = 3
    i = 0
    while i < num_tries:
        logger.debug(f"validate_order is on trial {i + 1} in {num_tries}.")
        i += 1
        try:
            tx, order_event, provider_fees_event = verify_order_tx(
                web3, token_address, tx_id, service, amount, sender, extra_data, allow_expired_provider_fee
            )
            logger.debug(
                f"validate_order succeeded for: did={did}, service_id={service.id}, tx_id={tx_id}, "
                f"sender={sender}, num_tokens={num_tokens}, token_address={token_address}. "
                f"result is: tx={tx}, order_event={order_event}."
            )

            return tx, order_event, provider_fees_event
        except ConnectionClosed:
            logger.debug("got ConnectionClosed error on validate_order.")
            if i == num_tries:
                logger.debug(
                    "reached max no. of tries, raise ConnectionClosed in validate_order."
                )
                raise
        except Exception:
            raise


def validate_transfer_not_used_for_other_service(
    did, service_id, transfer_tx_id, consumer_address, token_address
):
    logger.debug(
        f"validate_transfer_not_used_for_other_service: "
        f"did={did}, service_id={service_id}, transfer_tx_id={transfer_tx_id},"
        f" consumer_address={consumer_address}, token_address={token_address}"
    )
    return


def record_consume_request(
    did, service_id, order_tx_id, consumer_address, token_address, amount
):
    logger.debug(
        f"record_consume_request: "
        f"did={did}, service_id={service_id}, transfer_tx_id={order_tx_id}, "
        f"consumer_address={consumer_address}, token_address={token_address}, "
        f"amount={amount}"
    )
    return


def process_compute_request(data):
    provider_wallet = get_provider_wallet()
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
    web3 = get_web3()
    body["chainId"] = web3.chain_id

    return body


def decode_from_data(data, key, dec_type="list"):
    """Retrieves a dictionary key as a decoded dictionary or list."""
    default_value = list() if dec_type == "list" else dict()
    data = data.get(key, default_value)

    if data == "":
        return default_value

    if data and isinstance(data, str):
        try:
            data = json.loads(data)
        except json.decoder.JSONDecodeError:
            return -1

    return data


def check_asset_consumable(asset, consumer_address, logger, custom_url=None):
    if not asset.nft or "address" not in asset.nft:
        return False, "Asset malformed"

    dt_contract = get_web3().eth.contract(
        abi=ERC721Template.abi, address=asset.nft["address"]
    )

    if dt_contract.caller.getMetaData()[2] != 0:
        return False, "Asset is not consumable."

    code = asset.is_consumable({"type": "address", "value": consumer_address})

    if code == ConsumableCodes.OK:  # is consumable
        return True, ""

    message = f"Error: Access to asset {asset.did} was denied with code: {code}."
    logger.error(message, exc_info=1)

    return False, message


def check_environment_exists(envs, env_id):
    """Checks if environment with id exists in environments list."""
    return bool(get_environment(envs, env_id))


def get_environment(envs, env_id):
    """Gets environment with id exists in environments list."""
    if not envs or not isinstance(envs, list):
        return False

    matching_envs = [env for env in envs if env["id"] == env_id]
    return matching_envs[0] if len(matching_envs) > 0 else None


def sign_for_compute(wallet, owner, job_id=None):
    nonce = datetime.utcnow().timestamp()

    # prepare consumer signature on did
    msg = f"{owner}{job_id}{nonce}" if job_id else f"{owner}{nonce}"
    signature = sign_message(msg, wallet)

    return nonce, signature


def check_url_valid(service, file_index, data):
    provider_wallet = get_provider_wallet()

    url_object = get_service_files_list(service, provider_wallet)[file_index]
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
