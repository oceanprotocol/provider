import json

from ocean_provider.web3_internal import ContractBase
from ocean_provider.web3_internal.event_filter import EventFilter


class DataTokenContract(ContractBase):
    CONTRACT_NAME = 'DataTokenTemplate'

    def get_transfer_event(self, block_number, sender, receiver, num_tokens):
        event = getattr(self.events, 'Transfer')
        filter_params = {'from': sender, 'to': receiver, 'value': num_tokens}
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
                      'account_key': account.key}
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

    def get_blob(self):
        return self.contract_concise.blob()

    def get_metadata_url(self):
        # grab the metadatastore URL from the DataToken contract (@token_address)
        url_object = json.loads(self.get_blob())
        assert url_object['t'] == 1, f'This datatoken does not appear to have a metadata store url.'
        return url_object['url']

    def get_simple_url(self):
        url_object = json.loads(self.get_blob())
        assert url_object['t'] == 0, f'This datatoken does not appear to have a direct consume url.'
        return url_object['url']
