import os
import site

import requests
from ocean_lib.models.data_token import DataToken
from ocean_lib.web3_internal.utils import get_wallet
from ocean_lib.web3_internal.wallet import Wallet
from ocean_utils.aquarius.aquarius import Aquarius
from web3 import WebsocketProvider
from ocean_utils.http_requests.requests_session import get_requests_session as _get_requests_session
from requests_testadapter import Resp

from ocean_provider.config import Config
from ocean_lib.web3_internal.contract_handler import ContractHandler
from ocean_lib.web3_internal.web3_overrides.http_provider import CustomHTTPProvider
from ocean_lib.web3_internal.web3_provider import Web3Provider


def get_artifacts_path(config):
    path = config.artifacts_path
    if not path or not os.path.exists(path):
        if os.getenv('VIRTUAL_ENV'):
            path = os.path.join(os.getenv('VIRTUAL_ENV'), 'artifacts')
        else:
            plath = os.path.join(site.PREFIXES[0], 'artifacts')

    print(f'get_artifacts_path: {config.artifacts_path}, {path}, {site.PREFIXES[0]}')
    return path


def get_config():
    config_file = os.getenv('CONFIG_FILE', 'config.ini')
    return Config(filename=config_file)


def get_env_property(env_variable, property_name):
    return os.getenv(
        env_variable,
        get_config().get('osmosis', property_name)
    )


def get_requests_session():
    requests_session = _get_requests_session()
    requests_session.mount('file://', LocalFileAdapter())
    return requests_session


def init_account_envvars():
    os.environ['PARITY_ADDRESS'] = os.getenv('PROVIDER_ADDRESS', '')
    os.environ['PARITY_PASSWORD'] = os.getenv('PROVIDER_PASSWORD', '')
    os.environ['PARITY_KEY'] = os.getenv('PROVIDER_KEY', '')
    os.environ['PARITY_KEYFILE'] = os.getenv('PROVIDER_KEYFILE', '')
    os.environ['PARITY_ENCRYPTED_KEY'] = os.getenv('PROVIDER_ENCRYPTED_KEY', '')


def get_provider_wallet():
    pk = os.environ.get('PROVIDER_PRIVATE_KEY')
    if pk:
        return Wallet(Web3Provider.get_web3(), private_key=pk)

    return get_wallet(0)


def get_datatoken_minter(asset, datatoken_address):
    publisher = Web3Provider.get_web3().toChecksumAddress(asset.publisher)
    dt = DataToken(datatoken_address)
    if not dt.contract_concise.isMinter(publisher):
        raise AssertionError(f'ddo publisher {publisher} is not the current '
                             f'minter for the DataToken contract at {datatoken_address}.')
    return publisher


def setup_network(config_file=None):
    config = Config(filename=config_file) if config_file else get_config()
    network_url = config.network_url
    artifacts_path = get_artifacts_path(config)

    ContractHandler.set_artifacts_path(artifacts_path)

    if network_url.startswith('http'):
        provider = CustomHTTPProvider
    elif network_url.startswith('wss'):
        provider = WebsocketProvider
    else:
        raise AssertionError(f'Unsupported network url {network_url}. Must start with http or wss.')

    Web3Provider.init_web3(provider=provider(network_url))
    if network_url.startswith('wss'):
        from web3.middleware import geth_poa_middleware
        Web3Provider.get_web3().middleware_stack.inject(geth_poa_middleware, layer=0)

    init_account_envvars()

    wallet = get_provider_wallet()
    if wallet is None:
        raise AssertionError(f'Ocean Provider cannot run without a valid '
                             f'ethereum account. `PROVIDER_PRIVATE_KEY` was not found in the environment '
                             f'variables. \nENV WAS: {sorted(os.environ.items())}')

    if not wallet.private_key:
        raise AssertionError(f'Ocean Provider cannot run without a valid '
                             f'ethereum private key..')


class LocalFileAdapter(requests.adapters.HTTPAdapter):
    def build_response_from_file(self, request):
        file_path = request.url[7:]
        with open(file_path, 'rb') as file:
            buff = bytearray(os.path.getsize(file_path))
            file.readinto(buff)
            resp = Resp(buff)
            r = self.build_response(request, resp)

            return r

    def send(self, request, stream=False, timeout=None,
             verify=True, cert=None, proxies=None):

        return self.build_response_from_file(request)


def get_asset_from_metadatastore(metadata_url, document_id):
    aqua = Aquarius(metadata_url)
    return aqua.get_asset_ddo(document_id)
