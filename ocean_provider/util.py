import io
import json
import logging
import mimetypes
import os
from cgi import parse_header

from flask import Response

from osmosis_driver_interface.osmosis import Osmosis

from ocean_provider.contracts.custom_contract import DataTokenContract
from ocean_provider.utils.accounts import verify_signature
from ocean_provider.utils.data_token import get_asset_for_data_token
from ocean_provider.utils.encryption import do_decrypt
from ocean_provider.utils.web3 import web3

logger = logging.getLogger(__name__)


def get_request_data(request, url_params_only=False):
    if url_params_only:
        return request.args
    return request.args if request.args else request.json


def build_download_response(request, requests_session, url, download_url, content_type):
    try:
        download_request_headers = {}
        download_response_headers = {}

        is_range_request = bool(request.range)

        if is_range_request:
            download_request_headers = {"Range": request.headers.get('range')}
            download_response_headers = download_request_headers

        response = requests_session.get(download_url, headers=download_request_headers, stream=True)

        if not is_range_request:
            filename = url.split("/")[-1]

            content_disposition_header = response.headers.get('content-disposition')
            if content_disposition_header:
                _, content_disposition_params = parse_header(content_disposition_header)
                content_filename = content_disposition_params.get('filename')
                if content_filename:
                    filename = content_filename

            content_type_header = response.headers.get('content-type')
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
                "Content-Disposition": f'attachment;filename={filename}',
                "Access-Control-Expose-Headers": f'Content-Disposition'
            }

        return Response(
            io.BytesIO(response.content).read(),
            response.status_code,
            headers=download_response_headers,
            content_type=content_type
        )
    except Exception as e:
        logger.error(f'Error preparing file download response: {str(e)}')
        raise


def get_asset_files_list(asset, account):
    try:
        files_str = do_decrypt(
            asset.encrypted_files,
            account,
        )
        logger.debug(f'Got decrypted files str {files_str}')
        files_list = json.loads(files_str)
        if not isinstance(files_list, list):
            raise TypeError(f'Expected a files list, got {type(files_list)}.')

        return files_list
    except Exception as e:
        logger.error(f'Error decrypting asset files for asset {asset.did}: {str(e)}')
        raise


def get_asset_url_at_index(url_index, asset, account):
    logger.debug(f'get_asset_url_at_index(): url_index={url_index}, did={asset.did}, provider={account.address}')
    try:
        files_list = get_asset_urls(asset, account)
        if url_index >= len(files_list):
            raise ValueError(f'url index "{url_index}"" is invalid.')
        return files_list[url_index]

    except Exception as e:
        logger.error(f'Error decrypting url at index {url_index} for asset {asset.did}: {str(e)}')
        raise


def get_asset_urls(asset, account):
    logger.debug(f'get_asset_urls(): did={asset.did}, provider={account.address}')
    try:
        files_list = get_asset_files_list(asset, account)
        input_urls = []
        for i, file_meta_dict in enumerate(files_list):
            if not file_meta_dict or not isinstance(file_meta_dict, dict):
                raise TypeError(f'Invalid file meta at index {i}, expected a dict, got a '
                                f'{type(file_meta_dict)}.')
            if 'url' not in file_meta_dict:
                raise ValueError(f'The "url" key is not found in the '
                                 f'file dict {file_meta_dict} at index {i}.')

            input_urls.append(file_meta_dict['url'])

        return input_urls
    except Exception as e:
        logger.error(f'Error decrypting urls for asset {asset.did}: {str(e)}')
        raise


def get_asset_download_urls(asset, account, config_file):
    return [get_download_url(url, config_file)
            for url in get_asset_urls(asset, account)]


def get_download_url(url, config_file):
    try:
        logger.info('Connecting through Osmosis to generate the signed url.')
        osm = Osmosis(url, config_file)
        download_url = osm.data_plugin.generate_url(url)
        logger.debug(f'Osmosis generated the url: {download_url}')
        return download_url
    except Exception as e:
        logger.error(f'Error generating url (using Osmosis): {str(e)}')
        raise


def check_required_attributes(required_attributes, data, method):
    assert isinstance(data, dict), 'invalid payload format.'
    logger.info('got %s request: %s' % (method, data))
    if not data:
        logger.error('%s request failed: data is empty.' % method)
        return 'payload seems empty.', 400
    for attr in required_attributes:
        if attr not in data:
            logger.error('%s request failed: required attr %s missing.' % (method, attr))
            return '"%s" is required in the call to %s' % (attr, method), 400
    return None, None


def validate_token_transfer(sender, receiver, token_address, num_tokens, tx_id):
    tx = web3().eth.getTransaction(tx_id)
    if not tx:
        raise AssertionError('Transaction is not found, or is not yet verified.')

    if tx['from'] != sender or tx['to'] != token_address:
        raise AssertionError(
            f'Sender and receiver in the transaction {tx_id} '
            f'do not match the expected consumer and provider addresses.'
        )

    block = tx['blockNumber']
    dt_contract = DataTokenContract(token_address)
    transfer_event = dt_contract.get_transfer_event(block, sender, receiver)
    if not transfer_event:
        raise AssertionError(f'Invalid transaction {tx_id}.')

    if transfer_event.args['from'] != sender or transfer_event.args['to'] != receiver:
        raise AssertionError(f'The transfer event from/to do not match the expected values.')

    balance = dt_contract.contract_concise.balanceOf.call(receiver, block_identifier=block-1)
    new_balance = dt_contract.contract_concise.balanceOf.call(receiver, block_identifier=block)
    total = new_balance - balance
    assert total == transfer_event.args.value, f'Balance increment does not match the Transfer event value.'

    if total < num_tokens:
        raise AssertionError(
            f'The transfered number of data tokens {total} does not match '
            f'the expected amount of {num_tokens} tokens')

    return True


def process_consume_request(data, method, additional_params=None, require_signature=True):
    required_attributes = [
        'documentId',
        'serviceId',
        'serviceType',
        'tokenAddress',
        'consumerAddress'
    ]
    if additional_params:
        required_attributes += additional_params

    if require_signature:
        required_attributes.append('signature')

    msg, status = check_required_attributes(
        required_attributes, data, method)
    if msg:
        raise AssertionError(msg)

    did = data.get('documentId')
    token_address = data.get('tokenAddress')
    consumer_address = data.get('consumerAddress')
    service_id = data.get('serviceId')
    service_type = data.get('serviceType')

    # grab asset for did from the metadatastore associated with the Data Token address
    asset = get_asset_for_data_token(token_address, did)
    service = asset.get_service_by_index(service_id)
    if service.type != service_type:
        raise AssertionError(
            f'Requested service with id {service_id} has type {service.type} which '
            f'does not match the requested service type {service_type}.'
        )

    if require_signature:
        # Raises ValueError when signature is invalid
        signature = data.get('signature')
        verify_signature(consumer_address, signature, did)

    return asset, service, did, consumer_address, token_address
