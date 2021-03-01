#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging
import mimetypes
import os
from cgi import parse_header

import requests
from flask import Response
from ocean_lib.models.data_token import DataToken
from ocean_lib.ocean.util import to_base_18
from ocean_lib.web3_internal.utils import add_ethereum_prefix_and_hash_msg
from ocean_lib.web3_internal.web3_provider import Web3Provider
from ocean_lib.web3_internal.web3helper import Web3Helper
from ocean_provider.constants import BaseURLs
from ocean_provider.util_url import is_safe_url
from ocean_provider.utils.basics import (
    get_asset_from_metadatastore,
    get_config,
    get_provider_wallet,
)
from ocean_provider.utils.encryption import do_decrypt
from ocean_utils.agreements.service_agreement import ServiceAgreement
from osmosis_driver_interface.osmosis import Osmosis
from websockets import ConnectionClosed

logger = logging.getLogger(__name__)


def get_metadata_url():
    return get_config().aquarius_url


def get_request_data(request, url_params_only=False):
    if url_params_only:
        return request.args
    return request.args if request.args else request.json


def build_download_response(
    request, requests_session, url, download_url, content_type=None
):
    try:
        if not is_safe_url(url):
            raise ValueError(f"Unsafe url {url}")
        download_request_headers = {}
        download_response_headers = {}
        is_range_request = bool(request.range)

        if is_range_request:
            download_request_headers = {"Range": request.headers.get("range")}
            download_response_headers = download_request_headers

        response = requests_session.get(
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


def get_asset_files_list(asset, wallet):
    try:
        encrypted_files = asset.encrypted_files
        if encrypted_files.startswith("{"):
            encrypted_files = json.loads(encrypted_files)["encryptedDocument"]
        files_str = do_decrypt(encrypted_files, wallet)
        if not files_str:
            return None
        logger.debug(f"Got decrypted files str {files_str}")
        files_list = json.loads(files_str)
        if not isinstance(files_list, list):
            raise TypeError(f"Expected a files list, got {type(files_list)}.")

        return files_list
    except Exception as e:
        logger.error(f"Error decrypting asset files for asset {asset.did}: {str(e)}")
        raise


def get_asset_url_at_index(url_index, asset, wallet):
    logger.debug(
        f"get_asset_url_at_index(): url_index={url_index}, "
        f"did={asset.did}, provider={wallet.address}"
    )
    try:
        files_list = get_asset_urls(asset, wallet)
        if not files_list:
            return None
        if url_index >= len(files_list):
            raise ValueError(f'url index "{url_index}"" is invalid.')
        return files_list[url_index]

    except Exception as e:
        logger.error(
            f"Error decrypting url at index {url_index} for "
            f"asset {asset.did}: {str(e)}"
        )
        raise


def get_asset_urls(asset, wallet):
    """Returns list of urls of the files included in this `asset` in order."""
    logger.debug(f"get_asset_urls(): did={asset.did}, provider={wallet.address}")
    try:
        files_list = get_asset_files_list(asset, wallet)
        if not files_list:
            return None
        input_urls = []
        for i, file_meta_dict in enumerate(files_list):
            if not file_meta_dict or not isinstance(file_meta_dict, dict):
                raise TypeError(
                    f"Invalid file meta at index {i}, expected a dict, got a "
                    f"{type(file_meta_dict)}."
                )
            if "url" not in file_meta_dict:
                raise ValueError(
                    f'The "url" key is not found in the '
                    f"file dict {file_meta_dict} at index {i}."
                )

            input_urls.append(file_meta_dict["url"])

        return input_urls
    except Exception as e:
        logger.error(f"Error decrypting urls for asset {asset.did}: {str(e)}")
        raise


def get_asset_download_urls(asset, wallet, config_file):
    return [get_download_url(url, config_file) for url in get_asset_urls(asset, wallet)]


def get_download_url(url, config_file):
    try:
        logger.info("Connecting through Osmosis to generate the signed url.")
        osm = Osmosis(url, config_file)
        download_url = osm.data_plugin.generate_url(url)
        logger.debug(f"Osmosis generated the url: {download_url}")
        return download_url
    except Exception as e:
        logger.error(f"Error generating url (using Osmosis): {str(e)}")
        raise


def get_compute_endpoint():
    return get_config().operator_service_url + "/api/v1/operator/compute"


def get_compute_address():
    try:
        compute_info = requests.get(get_config().operator_service_url).json()
        return compute_info.get("address", None)
    except Exception as e:
        logger.error(f"Error getting CtD address: {str(e)}")
        return None


def check_required_attributes(required_attributes, data, method):
    assert isinstance(data, dict), "invalid payload format."
    logger.info("got %s request: %s" % (method, data))
    if not data:
        logger.error("%s request failed: data is empty." % method)
        return "payload seems empty.", 400
    for attr in required_attributes:
        if attr not in data:
            logger.error(
                "%s request failed: required attr %s missing." % (method, attr)
            )
            return '"%s" is required in the call to %s' % (attr, method), 400
    return None, None


def validate_order(sender, token_address, num_tokens, tx_id, did, service_id):
    dt_contract = DataToken(token_address)

    amount = to_base_18(num_tokens)
    num_tries = 3
    i = 0
    while i < num_tries:
        i += 1
        try:
            tx, order_event, transfer_event = dt_contract.verify_order_tx(
                Web3Provider.get_web3(), tx_id, did, service_id, amount, sender
            )
            return tx, order_event, transfer_event
        except ConnectionClosed:
            if i == num_tries:
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


def process_consume_request(data: dict):
    did = data.get("documentId")
    token_address = data.get("dataToken")
    consumer_address = data.get("consumerAddress")
    service_id = data.get("serviceId")
    service_type = data.get("serviceType")

    # grab asset for did from the metadatastore associated with
    # the Data Token address
    asset = get_asset_from_metadatastore(get_metadata_url(), did)
    service = ServiceAgreement.from_ddo(service_type, asset)
    if service.type != service_type:
        raise AssertionError(
            f"Requested service with id {service_id} has type {service.type} "
            f"which does not match the requested service type {service_type}."
        )

    return asset, service, did, consumer_address, token_address


def process_compute_request(data):
    provider_wallet = get_provider_wallet()
    did = data.get("documentId")
    owner = data.get("consumerAddress")
    job_id = data.get("jobId")
    tx_id = data.get("transferTxId")
    body = dict()
    body["providerAddress"] = provider_wallet.address
    if owner is not None:
        body["owner"] = owner
    if job_id is not None:
        body["jobId"] = job_id
    if tx_id is not None:
        body["agreementId"] = tx_id
    if did is not None:
        body["documentId"] = did

    msg_to_sign = (
        f"{provider_wallet.address}"
        f'{body.get("jobId", "")}'
        f'{body.get("documentId", "")}'
    )  # noqa
    msg_hash = add_ethereum_prefix_and_hash_msg(msg_to_sign)
    body["providerSignature"] = Web3Helper.sign_hash(msg_hash, provider_wallet)

    return body


def build_stage_output_dict(output_def, service_endpoint, owner, provider_wallet):
    config = get_config()
    if BaseURLs.ASSETS_URL in service_endpoint:
        service_endpoint = service_endpoint.split(BaseURLs.ASSETS_URL)[0]

    return dict(
        {
            "nodeUri": output_def.get("nodeUri", config.network_url),
            "brizoUri": output_def.get("brizoUri", service_endpoint),
            "brizoAddress": output_def.get("brizoAddress", provider_wallet.address),
            "metadata": output_def.get(
                "metadata",
                dict(
                    {
                        "main": {"name": "Compute job output"},
                        "additionalInformation": {
                            "description": "Output from running the compute job."
                        },
                    }
                ),
            ),
            "metadataUri": config.aquarius_url,
            "owner": output_def.get("owner", owner),
            "publishOutput": output_def.get("publishOutput", 1),
            "publishAlgorithmLog": output_def.get("publishAlgorithmLog", 1),
            "whitelist": output_def.get("whitelist", []),
        }
    )


def filter_dictionary(dictionary, keys):
    """Filters a dictionary from a list of keys."""
    return {key: dictionary[key] for key in dictionary if key in keys}


def filter_dictionary_starts_with(dictionary, prefix):
    """Filters a dictionary from a key prefix."""
    return {key: dictionary[key] for key in dictionary if key.startswith(prefix)}


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


def get_service_at_index(asset, index):
    """Gets asset's service at index."""
    matching_services = [s for s in asset.services if s.index == int(index)]

    if not matching_services:
        return None

    return matching_services[0]
