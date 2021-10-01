from eth_utils import remove_0x_prefix
from hexbytes import HexBytes
from web3.logs import DISCARD
from websockets import ConnectionClosed
from ocean_provider.utils.currency import to_wei

from jsonsempai import magic  # noqa: F401
from artifacts import DataTokenTemplate

OPF_FEE_PER_TOKEN = to_wei("0.001")  # 0.1%
MAX_MARKET_FEE_PER_TOKEN = to_wei("0.001")


def get_dt_contract(web3, address):
    abi = DataTokenTemplate.abi

    return web3.eth.contract(address=address, abi=abi)


def get_tx_receipt(web3, tx_hash):
    return web3.eth.wait_for_transaction_receipt(HexBytes(tx_hash), timeout=120)


def mint(web3, contract, receiver_address, amount, minter_wallet):
    contract_fn = contract.functions.mint(receiver_address, amount)
    _transact = {
        "from": minter_wallet.address,
        "account_key": str(minter_wallet.key),
        "chainId": web3.eth.chain_id,
    }

    return contract_fn.transact(_transact).hex()


def verify_order_tx(
    web3,
    contract,
    tx_id: str,
    did: str,
    service_id,
    amount,
    sender: str,
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

    receiver = contract.caller.minter()
    event_logs = contract.events.OrderStarted().processReceipt(
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

    asset_id = remove_0x_prefix(did).lower()
    assert (
        asset_id == remove_0x_prefix(contract.address).lower()
    ), "asset-id does not match the datatoken id."
    if str(order_log.args.serviceId) != str(service_id):
        raise AssertionError(
            f"The asset id (DID) or service id in the event does "
            f"not match the requested asset. \n"
            f"requested: (did={did}, serviceId={service_id}\n"
            f"event: (serviceId={order_log.args.serviceId}"
        )

    target_amount = amount - contract.caller.calculateFee(amount, OPF_FEE_PER_TOKEN)
    if order_log.args.mrktFeeCollector and order_log.args.marketFee > 0:
        max_market_fee = contract.caller.calculateFee(amount, MAX_MARKET_FEE_PER_TOKEN)
        assert order_log.args.marketFee <= (max_market_fee + 5), (
            f"marketFee {order_log.args.marketFee} exceeds the expected maximum "
            f"of {max_market_fee} based on feePercentage="
            f"{MAX_MARKET_FEE_PER_TOKEN} ."
        )
        target_amount = target_amount - order_log.args.marketFee

    # verify sender of the tx using the Tx record
    tx = web3.eth.get_transaction(tx_id)
    if sender not in [order_log.args.consumer, order_log.args.payer]:
        raise AssertionError("sender of order transaction is not the consumer/payer.")
    transfer_logs = contract.events.Transfer().processReceipt(
        tx_receipt, errors=DISCARD
    )
    receiver_to_transfers = {}
    for tr in transfer_logs:
        if tr.args.to not in receiver_to_transfers:
            receiver_to_transfers[tr.args.to] = []
        receiver_to_transfers[tr.args.to].append(tr)
    if receiver not in receiver_to_transfers:
        raise AssertionError(
            f"receiver {receiver} is not found in the transfer events."
        )
    transfers = sorted(receiver_to_transfers[receiver], key=lambda x: x.args.value)
    total = sum(tr.args.value for tr in transfers)
    if total < (target_amount - 5):
        raise ValueError(
            f"transferred value does meet the service cost: "
            f"service.cost - fees={target_amount}, "
            f"transferred value={total}"
        )
    return tx, order_log, transfers[-1]
