from ocean_keeper.contract_handler import ContractHandler
from ocean_keeper.web3_provider import Web3Provider
from ocean_utils.aquarius.aquarius import Aquarius
from web3.contract import ConciseContract

from ocean_provider.basics import get_config


def get_token_contract_abi():
    if not ContractHandler.artifacts_path:
        ContractHandler.set_artifacts_path(get_config().keeper_path)

    return ContractHandler.get_contract_dict_by_name(
        'DataTokenTemplate',  # TODO: verify the actual contract name and update accordingly
        ContractHandler.artifacts_path
    )['abi']


def get_data_token_contract(token_address):
    abi = get_token_contract_abi()
    return Web3Provider.get_web3().eth.contract(address=token_address, abi=abi)


def get_data_token_concise_contract(token_address):
    return ConciseContract(get_data_token_contract(token_address))


def get_transfer_event(contract, block_number, sender, receiver):
    event = getattr(contract.events, 'Transfer')
    filter_params = {'from': sender, 'to': receiver}
    event_filter = event().createFilter(
        fromBlock=block_number,
        toBlock=block_number+1,
        argument_filters=filter_params
    )
    logs = event_filter.get_all_entries()
    if not logs:
        return None

    if len(logs) > 1:
        raise AssertionError(f'Expected a single transfer event at '
                             f'block {block_number}, but found {len(logs)} events.')

    return logs[0]


def get_metadata_url(token_address):
    # grab the metadatastore URL from the DataToken contract (token_address)
    data_token_contract = get_data_token_concise_contract(token_address)
    return getattr(data_token_contract, 'blob')()


def get_asset_from_metadatastore(metadata_url, document_id):
    aqua = Aquarius(metadata_url)
    return aqua.get_asset_ddo(document_id)


def get_asset_for_data_token(token_address, document_id):
    return get_asset_from_metadatastore(
        get_metadata_url(token_address),
        document_id
    )
