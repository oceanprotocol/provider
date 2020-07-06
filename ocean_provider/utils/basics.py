import os
import site

import requests
from ocean_keeper.web3.http_provider import CustomHTTPProvider
from ocean_utils.http_requests.requests_session import get_requests_session as _get_requests_session
from requests_testadapter import Resp
from ocean_keeper.contract_handler import ContractHandler
from ocean_keeper.utils import get_account
from ocean_keeper.web3_provider import Web3Provider
from web3 import WebsocketProvider

from ocean_provider.config import Config


def get_keeper_path(config):
    path = config.keeper_path
    if not path or not os.path.exists(path):
        if os.getenv('VIRTUAL_ENV'):
            path = os.path.join(os.getenv('VIRTUAL_ENV'), 'artifacts')
        else:
            path = os.path.join(site.PREFIXES[0], 'artifacts')

    print(f'get_keeper_path: {config.keeper_path}, {path}, {site.PREFIXES[0]}')
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


def setup_network(config_file=None):
    config = Config(filename=config_file) if config_file else get_config()
    keeper_url = config.keeper_url
    artifacts_path = get_keeper_path(config)

    ContractHandler.set_artifacts_path(artifacts_path)
    print(f'keeper_path: {ContractHandler.artifacts_path}')
    print(f'cwd contents: {os.getcwd()} -- {os.listdir(os.getcwd())}')
    print(f'config keeper path: {config.keeper_path} -> {os.path.exists(config.keeper_path)}')
    print(f'artifacts folder: {os.listdir(config.keeper_path)}')

    if keeper_url.startswith('http'):
        provider = CustomHTTPProvider
    elif keeper_url.startswith('wss'):
        provider = WebsocketProvider
    else:
        raise AssertionError(f'Unsupported network url {keeper_url}. Must start with http or wss.')

    Web3Provider.init_web3(provider=provider(keeper_url))
    from web3.middleware import geth_poa_middleware
    Web3Provider.get_web3().middleware_stack.inject(geth_poa_middleware, layer=0)

    init_account_envvars()

    account = get_account(0)
    if account is None:
        raise AssertionError(f'Ocean Provider cannot run without a valid '
                             f'ethereum account. Account address was not found in the environment'
                             f'variable `PROVIDER_ADDRESS`. Please set the following environment '
                             f'variables and try again: `PROVIDER_ADDRESS`, [`PROVIDER_PASSWORD`, '
                             f'and `PROVIDER_KEYFILE` or `PROVIDER_ENCRYPTED_KEY`] or `PROVIDER_KEY`.'
                             f'ENV WAS: {sorted(os.environ.items())}')

    if not account._private_key and not (account.password and account._encrypted_key):
        raise AssertionError(f'Ocean Provider cannot run without a valid '
                             f'ethereum account with either a `PROVIDER_PASSWORD` '
                             f'and `PROVIDER_KEYFILE`/`PROVIDER_ENCRYPTED_KEY` '
                             f'or private key `PROVIDER_KEY`. Current account has password {account.password}, '
                             f'keyfile {account.key_file}, encrypted-key {account._encrypted_key} '
                             f'and private-key {account._private_key}.')


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

