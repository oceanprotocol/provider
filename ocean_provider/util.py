import io
import json
import logging
import mimetypes
import os
import site
from cgi import parse_header
from datetime import datetime
from os import getenv

from eth_utils import remove_0x_prefix
from flask import Response
from ocean_provider.contract_handler import ContractHandler
from ocean_provider.event_filter import EventFilter
from ocean_provider.utils import add_ethereum_prefix_and_hash_msg, get_account
from ocean_provider.web3_provider import Web3Provider
from ocean_utils.agreements.service_types import ServiceTypes
from ocean_utils.did import did_to_id
from ocean_utils.did_resolver.did_resolver import DIDResolver
from osmosis_driver_interface.osmosis import Osmosis

from ocean_provider.config import Config
from ocean_provider.constants import BaseURLs
from ocean_provider.exceptions import InvalidSignatureError, ServiceAgreementExpired

logger = logging.getLogger(__name__)


def setup_keeper(config_file=None):
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


def do_encrypt(did_id, document, provider_acc, config):
    encrypted_document = ''
    return encrypted_document


def do_decrypt(did_id, encrypted_document, provider_acc, config):
    return ''


def _get_agreement_actor_event(keeper, agreement_id, from_block=0, to_block='latest'):
    _filter = {'agreementId': Web3Provider.get_web3().toBytes(hexstr=agreement_id)}

    event_filter = EventFilter(
        keeper.agreement_manager.AGREEMENT_ACTOR_ADDED_EVENT,
        keeper.agreement_manager.get_event_filter_for_agreement_actor(None).event,
        _filter,
        from_block=from_block,
        to_block=to_block
    )
    event_filter.set_poll_interval(0.5)
    return event_filter


def is_access_granted(agreement_id, did, consumer_address, keeper):
    event_logs = _get_agreement_actor_event(keeper, agreement_id).get_all_entries()
    if not event_logs:
        return False

    actors = [log.args.actor for log in event_logs]
    if not actors:
        return False

    if consumer_address not in actors:
        logger.warning(f'Invalid consumer address {consumer_address} and/or '
                       f'service agreement id {agreement_id} (did {did})'
                       f', agreement actors are {actors}')
        return False

    document_id = did_to_id(did)
    return keeper.access_secret_store_condition.check_permissions(
        document_id, consumer_address
    )


def validate_agreement_condition(agreement_id, did, consumer_address, keeper):
    event_logs = _get_agreement_actor_event(keeper, agreement_id).get_all_entries()
    if not event_logs:
        return False

    actors = [log.args.actor for log in event_logs]
    if not actors:
        return False

    if consumer_address not in actors:
        logger.warning(f'Invalid consumer address {consumer_address} and/or '
                       f'service agreement id {agreement_id} (did {did})'
                       f', agreement actors are {actors}')
        return False

    document_id = did_to_id(did)
    return keeper.compute_execution_condition.was_compute_triggered(
        document_id, consumer_address
    )


def is_token_valid(token):
    return isinstance(token, str) and token.startswith('0x') and len(token.split('-')) == 2


def check_auth_token(token):
    w3 = web3()
    parts = token.split('-')
    if len(parts) < 2:
        return '0x0'
    # :HACK: alert, this should be part of ocean-utils, ocean-keeper, or a stand-alone library
    sig, timestamp = parts
    auth_token_message = get_config().auth_token_message or "Ocean Protocol Authentication"
    default_exp = 24 * 60 * 60
    expiration = int(get_config().auth_token_expiration or default_exp)
    if int(datetime.now().timestamp()) > (int(timestamp) + expiration):
        return '0x0'

    message = f'{auth_token_message}\n{timestamp}'
    address = Keeper.personal_ec_recover(message, sig)
    return w3.toChecksumAddress(address)


def generate_token(account):
    raw_msg = get_config().auth_token_message or "Ocean Protocol Authentication"
    _time = int(datetime.now().timestamp())
    _message = f'{raw_msg}\n{_time}'
    prefixed_msg_hash = add_ethereum_prefix_and_hash_msg(_message)
    return f'{keeper_instance().sign_hash(prefixed_msg_hash, account)}-{_time}'


def verify_signature(keeper, signer_address, signature, original_msg):
    if is_token_valid(signature):
        address = check_auth_token(signature)
    else:
        address = keeper.personal_ec_recover(original_msg, signature)

    if address.lower() == signer_address.lower():
        return True

    msg = f'Invalid signature {signature} for ' \
          f'ethereum address {signer_address} and documentId {original_msg}.'
    raise InvalidSignatureError(msg)


def get_provider_account():
    return get_account(0)


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


def get_latest_keeper_version():
    keeper = keeper_instance()
    keeper_versions = sorted(
        [tuple([int(v) for v in c.version[1:].split('.')]) for c in keeper.contract_name_to_instance.values() if c]
    )
    v_numbers = [str(n) for n in keeper_versions[-1]]
    return 'v' + '.'.join(v_numbers)


def keeper_instance():
    # Init web3 before fetching keeper instance.
    web3()
    return Keeper.get_instance()


def web3():
    return Web3Provider.get_web3(get_config().keeper_url)


def get_metadata(ddo):
    try:
        for service in ddo['service']:
            if service['type'] == 'Metadata':
                return service['metadata']
    except Exception as e:
        logger.error("Error getting the metatada: %s" % e)


def get_agreement_block_time(agreement_id):
    # get starting time from the on-chain agreement's blocknumber
    keeper = keeper_instance()
    w3 = Web3Provider.get_web3()
    agreement = keeper.agreement_manager.get_agreement(agreement_id)
    block_time = w3.eth.getBlock(agreement.block_number_updated).timestamp
    return int(block_time)


def validate_agreement_expiry(service_agreement, start_time):
    timeout = int(service_agreement.attributes['main'].get('timeout', 3600 * 24))
    if timeout == 0:
        return True
    expiry_time = start_time + timeout
    current_time = datetime.now().timestamp()
    if current_time > expiry_time:
        agreement_exp = datetime.fromtimestamp(expiry_time).replace(microsecond=0).isoformat()
        msg = f'Service agreement has expired at {agreement_exp}.'
        raise ServiceAgreementExpired(msg)

    return True


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
        files_str = do_secret_store_decrypt(
            remove_0x_prefix(asset.asset_id),
            asset.encrypted_files,
            account,
            get_config()
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


def get_compute_endpoint():
    return get_config().operator_service_url + '/api/v1/operator/compute'


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


def validate_algorithm_dict(algorithm_dict, algorithm_did):
    if algorithm_did and not algorithm_dict['url']:
        return f'cannot get url for the algorithmDid {algorithm_did}', 400

    if not algorithm_dict['url'] and not algorithm_dict['rawcode']:
        return f'`algorithmMeta` must define one of `url` or `rawcode`, but both seem missing.', 400

    container = algorithm_dict['container']
    # Validate `container` data
    if not (container.get('entrypoint') and container.get('image') and container.get('tag')):
        return f'algorithm `container` must specify values for all of entrypoint, image and tag.', 400

    return None, None


def build_stage_algorithm_dict(algorithm_did, algorithm_meta, provider_account):
    if algorithm_did is not None:
        # use the DID
        algo_asset = DIDResolver(keeper_instance().did_registry).resolve(algorithm_did)
        algo_id = algorithm_did
        raw_code = ''
        algo_url = get_asset_url_at_index(0, algo_asset, provider_account)
        container = algo_asset.metadata['main']['algorithm']['container']
    else:
        algo_id = ''
        algo_url = algorithm_meta.get('url')
        raw_code = algorithm_meta.get('rawcode')
        container = algorithm_meta.get('container')

    return dict({
        'id': algo_id,
        'url': algo_url,
        'rawcode': raw_code,
        'container': container
    })


def build_stage_output_dict(output_def, asset, owner, provider_account):
    config = get_config()
    service_endpoint = asset.get_service(ServiceTypes.CLOUD_COMPUTE).service_endpoint
    if BaseURLs.ASSETS_URL in service_endpoint:
        service_endpoint = service_endpoint.split(BaseURLs.ASSETS_URL)[0]

    return dict({
        'nodeUri': output_def.get('nodeUri', config.keeper_url),
        'providerUri': output_def.get('providerUri', service_endpoint),
        'providerAddress': output_def.get('providerAddress', provider_account.address),
        'metadata': output_def.get('metadata', dict({
            'main': {
                'name': 'Compute job output'
            },
            'additionalInformation': {
                'description': 'Output from running the compute job.'
            }
        })),
        'metadataUri': output_def.get('metadataUri', config.aquarius_url),
        'secretStoreUri': output_def.get('secretStoreUri', config.secret_store_url),
        'owner': output_def.get('owner', owner),
        'publishOutput': output_def.get('publishOutput', 1),
        'publishAlgorithmLog': output_def.get('publishAlgorithmLog', 1),
        'whitelist': output_def.get('whitelist', [])
    })


def build_stage_dict(input_dict, algorithm_dict, output_dict):
    return dict({
        'index': 0,
        'input': [input_dict],
        'compute': {
            'Instances': 1,
            'namespace': "ocean-compute",
            'maxtime': 3600
        },
        'algorithm': algorithm_dict,
        'output': output_dict
    })
