from eth_utils import remove_0x_prefix
from ocean_lib.models.data_token import DataToken
from ocean_lib.ocean.util import from_base_18, to_base_18
from ocean_lib.web3_internal.event_filter import EventFilter
from ocean_lib.web3_internal.wallet import Wallet
from ocean_utils.did import did_to_id_bytes


class CustomDataToken(DataToken):
    # amount, did, serviceId, receiver, startedAt, feeCollector, marketFee
    ORDER_STARTED_EVENT = 'OrderStarted'
    # orderTxId, consumer, amount, did, serviceId, provider
    ORDER_FINISHED_EVENT = 'OrderFinished'

    def get_event_logs(self, event_name, filter_args=None, from_block=0, to_block='latest'):
        event = getattr(self.events, event_name)
        filter_params = filter_args or {}
        event_filter = EventFilter(
            event_name,
            event,
            filter_params,
            from_block=from_block,
            to_block=to_block
        )

        logs = event_filter.get_all_entries(max_tries=10)
        if not logs:
            return []

        return logs[0]

    def verify_order_tx(self, web3, tx_id, did, service_id, amount_base, sender, receiver, fee_percentage):
        event = getattr(self.events, self.ORDER_STARTED_EVENT)
        tx_receipt = self.get_tx_receipt(tx_id)
        if tx_receipt.status == 0:
            raise AssertionError(f'order transaction failed.')

        event_logs = event().processReceipt(tx_receipt)
        order_log = event_logs[0] if event_logs else None
        if not order_log:
            raise AssertionError(f'Cannot find the event for the order transaction with tx id {tx_id}.')
        assert len(event_logs) == 1, \
            f'Multiple order events in the same transaction !!! {event_logs}'

        asset_id = remove_0x_prefix(did)
        if order_log.args.did.hex() != asset_id or str(order_log.args.serviceId) != str(service_id):
            raise AssertionError(f'The asset id (DID) or service id in the event does '
                                 f'not match the requested asset. \n'
                                 f'requested: (did={did}, serviceId={service_id}\n'
                                 f'event: (did={order_log.args.did.hex()}, serviceId={order_log.args.serviceId}')

        if order_log.args.receiver != receiver:
            raise AssertionError(f'The order event receiver does not match the expected value.')

        # verify sender of the tx using the Tx record
        tx = web3.eth.getTransaction(tx_id)
        if tx['from'] != sender:
            raise AssertionError(f'sender of order transaction is not the same as the requesting account.')

        transfer_logs = self.events.Transfer().processReceipt(tx_receipt)
        receiver_to_tr = {tr.args.to: tr for tr in transfer_logs}
        if receiver not in receiver_to_tr:
            raise AssertionError(f'receiver {receiver} is not found in the transfer events.')

        transfer = receiver_to_tr[receiver]
        fee = to_base_18(fee_percentage)
        target_value = amount_base - int(amount_base * fee / to_base_18(1.0))
        if abs(transfer.args.value - target_value) > 5:
            raise ValueError(f'transferred value does meet the service cost: '
                             f'service.cost-fee={from_base_18(target_value)}, '
                             f'transferred value={from_base_18(transfer.args.value)}')
        return tx, order_log, transfer

    def startOrder(self, receiver: str, amount: int, did: str, serviceId: int,
                   feeCollector: str, feePercentage: int, from_wallet: Wallet):
        return self.send_transaction(
            'startOrder',
            (receiver, amount, did, serviceId, feeCollector, feePercentage),
            from_wallet
        )

    def finishOrder(self, orderTxId: str, consumer: str, amount: int, did: str,
                    serviceId: int, from_wallet: Wallet):
        return self.send_transaction(
            'finishOrder',
            (orderTxId, consumer, amount, did, serviceId),
            from_wallet
        )
