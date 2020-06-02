import io
import json
import logging
import mimetypes
import os
import site
from cgi import parse_header
from os import getenv

from flask import Response
from ocean_keeper.contract_handler import ContractHandler
from ocean_keeper.utils import get_account

from ocean_keeper.web3_provider import Web3Provider
from ocean_utils.aquarius.aquarius import Aquarius
from ocean_utils.ddo.ddo import DDO
from osmosis_driver_interface.osmosis import Osmosis
from web3 import Web3

from ocean_provider.config import Config
from ocean_provider.utils.data_token import get_data_token_concise_contract, get_transfer_event
from ocean_provider.utils.encryption import do_decrypt

logger = logging.getLogger(__name__)


def setup_network(config_file=None):
    config = Config(filename=config_file) if config_file else get_config()
    keeper_url = config.keeper_url
    artifacts_path = get_keeper_path(config)

    ContractHandler.set_artifacts_path(artifacts_path)
    Web3Provider.init_web3(keeper_url)
    init_account_envvars()

    account = get_account(0)
    if account is None:
        raise AssertionError(f'Ocean Provider cannot run without a valid '
                             f'ethereum account. Account address was not found in the environment'
                             f'variable `PROVIDER_ADDRESS`. Please set the following environment '
                             f'variables and try again: `PROVIDER_ADDRESS`, [`PROVIDER_PASSWORD`, '
                             f'and `PROVIDER_KEYFILE` or `PROVIDER_ENCRYPTED_KEY`] or `PROVIDER_KEY`.')

    if not account._private_key and not (account.password and account._encrypted_key):
        raise AssertionError(f'Ocean Provider cannot run without a valid '
                             f'ethereum account with either a `PROVIDER_PASSWORD` '
                             f'and `PROVIDER_KEYFILE`/`PROVIDER_ENCRYPTED_KEY` '
                             f'or private key `PROVIDER_KEY`. Current account has password {account.password}, '
                             f'keyfile {account.key_file}, encrypted-key {account._encrypted_key} '
                             f'and private-key {account._private_key}.')


def init_account_envvars():
    os.environ['PARITY_ADDRESS'] = os.getenv('PROVIDER_ADDRESS', '')
    os.environ['PARITY_PASSWORD'] = os.getenv('PROVIDER_PASSWORD', '')
    os.environ['PARITY_KEY'] = os.getenv('PROVIDER_KEY', '')
    os.environ['PARITY_KEYFILE'] = os.getenv('PROVIDER_KEYFILE', '')
    os.environ['PARITY_ENCRYPTED_KEY'] = os.getenv('PROVIDER_ENCRYPTED_KEY', '')


def get_config():
    config_file = os.getenv('CONFIG_FILE', 'config.ini')
    return Config(filename=config_file)


def get_request_data(request, url_params_only=False):
    if url_params_only:
        return request.args
    return request.args if request.args else request.json


def get_env_property(env_variable, property_name):
    return getenv(
        env_variable,
        get_config().get('osmosis', property_name)
    )


def get_keeper_path(config):
    path = config.keeper_path
    if not os.path.exists(path):
        if os.getenv('VIRTUAL_ENV'):
            path = os.path.join(os.getenv('VIRTUAL_ENV'), 'artifacts')
        else:
            path = os.path.join(site.PREFIXES[0], 'artifacts')

    return path


def web3():
    return Web3Provider.get_web3(get_config().keeper_url)


def get_metadata(ddo):
    try:
        for service in ddo['service']:
            if service['type'] == 'Metadata':
                return service['metadata']
    except Exception as e:
        logger.error("Error getting the metatada: %s" % e)


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
        files_list = get_asset_files_list(asset, account)
        if url_index >= len(files_list):
            raise ValueError(f'url index "{url_index}"" is invalid.')

        file_meta_dict = files_list[url_index]
        if not file_meta_dict or not isinstance(file_meta_dict, dict):
            raise TypeError(f'Invalid file meta at index {url_index}, expected a dict, got a '
                            f'{type(file_meta_dict)}.')
        if 'url' not in file_meta_dict:
            raise ValueError(f'The "url" key is not found in the '
                             f'file dict {file_meta_dict} at index {url_index}.')

        return file_meta_dict['url']

    except Exception as e:
        logger.error(f'Error decrypting url at index {url_index} for asset {asset.did}: {str(e)}')
        raise


def get_asset_urls(asset, account, config_file):
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

            url = file_meta_dict['url']
            input_urls.append(get_download_url(url, config_file))

        return input_urls
    except Exception as e:
        logger.error(f'Error decrypting urls for asset {asset.did}: {str(e)}')
        raise


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


def get_metadata_store_url(token_address):
    # grab the metadatastore URL from the DataToken contract (token_address)
    metadata_url = ''
    return metadata_url


def get_asset_from_metadatastore(metadatastore, document_id):
    Aquarius()
    return DDO()


def get_asset_for_data_token(token_address, document_id):
    return get_asset_from_metadatastore(
        get_metadata_store_url(token_address),
        document_id
    )


def validate_token_transfer(sender, receiver, token_address, num_tokens, tx_id):
    tx = Web3.eth.getTransaction(tx_id)
    if not tx:
        raise AssertionError('Transaction is not found, or is not yet verified.')

    if tx['from'] != sender or tx['to'] != token_address:
        raise AssertionError(
            f'Sender and receiver in the transaction {tx_id} '
            f'do not match the expected consumer and provider addresses.'
        )

    block = tx['blockNumber']
    dt_contract = get_data_token_concise_contract(token_address)
    transfer_event = get_transfer_event(dt_contract, block, sender, receiver)
    if not transfer_event:
        raise AssertionError(f'Invalid transaction {tx_id}.')

    if transfer_event.args['from'] != sender or transfer_event.args['to'] != receiver:
        raise AssertionError(f'The transfer event from/to do not match the expected values.')

    balance = dt_contract.balanceOf.call(receiver, block_identifier=block-1)
    new_balance = dt_contract.balanceOf.call(receiver, block_identifier=block)
    total = new_balance - balance
    assert total == transfer_event.args.value, f'Balance increment does not match the Transfer event value.'

    if total < num_tokens:
        raise AssertionError(
            f'The transfered number of data tokens {total} does not match '
            f'the expected amount of {num_tokens} tokens')

    return True
