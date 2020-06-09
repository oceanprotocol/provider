import json
import os

from ocean_keeper import ContractBase
from ocean_keeper.contract_handler import ContractHandler
from ocean_keeper.event_filter import EventFilter
from ocean_keeper.web3_provider import Web3Provider


class CustomContractBase(ContractBase):
    def __init__(self, address, abi_path=None, abi=None):
        name = self.contract_name
        assert name, 'contract_name property needs to be implemented in subclasses.'
        if not abi_path and not abi:
            abi_path = ContractHandler.artifacts_path

        if abi_path and not abi:
            abi = CustomContractBase.read_abi_from_file(
                name,
                abi_path
            )['abi']

        contract = Web3Provider.get_web3().eth.contract(address=address, abi=abi)
        ContractHandler.set(name, contract)
        ContractBase.__init__(self, name)
        assert self.contract == contract
        assert self.contract_concise is not None
        assert self.address == address

    @property
    def contract_name(self):
        return ''

    @staticmethod
    def read_abi_from_file(contract_name, abi_path):
        path = None
        contract_name = contract_name + '.json'
        for name in os.listdir(abi_path):
            if name.lower() == contract_name.lower():
                path = os.path.join(abi_path, contract_name)
                break

        if path:
            with open(path) as f:
                return json.loads(f.read())

        return None


class DataTokenContract(CustomContractBase):
    @property
    def contract_name(self):
        return 'DataTokenTemplate'

    def get_transfer_event(self, block_number, sender, receiver):
        event = getattr(self.events, 'Transfer')
        filter_params = {'from': sender, 'to': receiver}
        event_filter = EventFilter(
            'Transfer',
            event,
            filter_params,
            from_block=block_number,
            to_block=block_number+1
        )

        logs = event_filter.get_all_entries(max_tries=10)
        if not logs:
            return None

        if len(logs) > 1:
            raise AssertionError(f'Expected a single transfer event at '
                                 f'block {block_number}, but found {len(logs)} events.')

        return logs[0]

    def mint(self, to, value, account):
        tx_hash = self.send_transaction(
            'mint',
            (to,
             value),
            transact={'from': account.address,
                      'passphrase': account.password,
                      'account_key': account.key,
                      'value': 100000},
        )
        return tx_hash

    def transfer(self, to, value, account):
        tx_hash = self.send_transaction(
            'transfer',
            (to,
             value),
            transact={'from': account.address,
                      'passphrase': account.password,
                      'account_key': account.key},
        )
        return tx_hash

    def get_metadata_url(self):
        # grab the metadatastore URL from the DataToken contract (@token_address)
        return self.contract_concise.blob()


class FactoryContract(CustomContractBase):
    @property
    def contract_name(self):
        return 'Factory'

    def create_data_token(self, account, metadata_url):
        tx_hash = self.send_transaction(
            'createToken',
            (metadata_url,),
            transact={'from': account.address,
                      'passphrase': account.password,
                      'account_key': account.key},
        )
        tx_receipt = self.get_tx_receipt(tx_hash)
        logs = getattr(self.events, 'TokenRegistered')().processReceipt(tx_receipt)
        # event_log = self.get_token_registered_event(
        #     tx_receipt.blockNumber,
        #     metadata_url,
        #     account.address
        # )
        if not logs:
            return None

        return DataTokenContract(logs[0].args.tokenAddress)

    def get_token_registered_event(self, block_number, metadata_url, sender):
        event = getattr(self.events, 'TokenRegistered')
        filter_params = {}
        event_filter = event().createFilter(
            fromBlock=block_number,
            toBlock=block_number,
            argument_filters=filter_params
        )
        logs = event_filter.get_all_entries()
        for log in logs:
            if log.args.blob == metadata_url and sender == log.args.RegisteredBy:
                return log

        return None
