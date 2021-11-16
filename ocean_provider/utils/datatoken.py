from typing import Optional

from artifacts import ERC20Template
from eth_typing.encoding import HexStr
from eth_typing.evm import HexAddress
from hexbytes import HexBytes
from jsonsempai import magic  # noqa: F401
from web3.contract import Contract
from web3.logs import DISCARD
from web3.main import Web3
from websockets import ConnectionClosed


def get_datatoken_contract(web3: Web3, address: Optional[str] = None) -> Contract:
    """
    Build a web3 Contract instance using the Ocean Protocol ERC20Template ABI.

    This function assumes that the `ERC20Template` stored at index 1 of the
    `ERC721Factory` provides all the functionality needed by Provider,
    especially the `getMetaData` contract method.
    """
    return web3.eth.contract(address=address, abi=ERC20Template.abi)


def get_tx_receipt(web3, tx_hash):
    return web3.eth.wait_for_transaction_receipt(HexBytes(tx_hash), timeout=120)


def verify_order_tx(
    web3: Web3,
    datatoken_address: HexAddress,
    tx_id: HexStr,
    service_id: int,
    amount: int,
    sender: HexAddress,
):
    try:
        tx_receipt = get_tx_receipt(web3, tx_id)
    except ConnectionClosed:
        # try again in this case
        tx_receipt = get_tx_receipt(web3, tx_id)

    if tx_receipt is None:
        raise AssertionError(
            "Failed to get tx receipt for the `startOrder` transaction.."
        )

    if tx_receipt.status == 0:
        raise AssertionError("order transaction failed.")

    datatoken_contract = get_datatoken_contract(web3, datatoken_address)
    event_logs = datatoken_contract.events.OrderStarted().processReceipt(
        tx_receipt, errors=DISCARD
    )
    order_log = event_logs[0] if event_logs else None
    if not order_log:
        raise AssertionError(
            f"Cannot find the event for the order transaction with tx id {tx_id}."
        )
    assert (
        len(event_logs) == 1
    ), f"Multiple order events in the same transaction !!! {event_logs}"

    if order_log.args.serviceId != service_id:
        raise AssertionError(
            f"The service id in the event does "
            f"not match the requested asset. \n"
            f"requested: serviceId={service_id}\n"
            f"event: serviceId={order_log.args.serviceId}"
        )

    if order_log.args.amount < amount:
        raise ValueError(
            f"The amount in the event is less than the amount requested. \n"
            f"requested: amount={amount}\n"
            f"event: amount={order_log.args.amount}"
        )

    if sender not in [order_log.args.consumer, order_log.args.payer]:
        raise ValueError("sender of order transaction is not the consumer/payer.")

    transfer_logs = datatoken_contract.events.Transfer().processReceipt(
        tx_receipt, errors=DISCARD
    )
    receiver_to_transfers = {}
    for tr in transfer_logs:
        if tr.args.to not in receiver_to_transfers:
            receiver_to_transfers[tr.args.to] = []
        receiver_to_transfers[tr.args.to].append(tr)
    receiver = datatoken_contract.caller.getFeeCollector()
    if receiver not in receiver_to_transfers:
        raise AssertionError(
            f"receiver {receiver} is not found in the transfer events."
        )
    transfers = sorted(receiver_to_transfers[receiver], key=lambda x: x.args.value)

    tx = web3.eth.get_transaction(HexBytes(tx_id))

    return tx, order_log, transfers[-1]
