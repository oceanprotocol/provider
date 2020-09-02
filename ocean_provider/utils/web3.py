
from ocean_lib.web3_internal.web3_provider import Web3Provider
from ocean_provider.utils.basics import get_config


def web3():
    return Web3Provider.get_web3(get_config().network_url)
