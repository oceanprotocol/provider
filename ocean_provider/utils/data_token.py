from ocean_utils.aquarius.aquarius import Aquarius

from ocean_provider.contracts.custom_contract import FactoryContract, DataTokenContract
from ocean_provider.utils.basics import get_config


def get_factory_contract(factory_address=None, abi_path=None, abi=None):
    if not factory_address:
        factory_address = get_config().factory_address
    return FactoryContract(factory_address, abi_path, abi)


def get_data_token_contract(token_address, abi_path=None, abi=None):
    return DataTokenContract(token_address, abi_path, abi)


def get_asset_from_metadatastore(metadata_url, document_id):
    aqua = Aquarius(metadata_url)
    return aqua.get_asset_ddo(document_id)


def get_asset_for_data_token(token_address, document_id):
    return get_asset_from_metadatastore(
        DataTokenContract(token_address).get_metadata_url(),
        document_id
    )
