import json
import logging
from datetime import datetime
from typing import Optional

from jsonsempai import magic  # noqa: F401
from artifacts import ERC20Template
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from eth_typing.encoding import HexStr
from eth_typing.evm import HexAddress
from hexbytes import HexBytes
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.utils.services import Service
from web3.contract import Contract
from web3.logs import DISCARD
from web3.main import Web3
from websockets import ConnectionClosed

logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)


def get_datatoken_contract(web3: Web3, address: Optional[str] = None) -> Contract:
    """
    Build a web3 Contract instance using the Ocean Protocol ERC20Template ABI.

    This function assumes that the `ERC20Template` stored at index 1 of the
    `ERC721Factory` provides all the functionality needed by Provider,
    especially the `getMetaData` contract method.
    """
    return web3.eth.contract(address=address, abi=ERC20Template.abi)


def _get_tx_receipt(web3, tx_hash):
    return web3.eth.wait_for_transaction_receipt(HexBytes(tx_hash), timeout=120)


def verify_order_tx(
    web3: Web3,
    datatoken_address: HexAddress,
    tx_id: HexStr,
    service: Service,
    amount: int,
    sender: HexAddress,
    extra_data: None,
):
    provider_wallet = get_provider_wallet()
    try:
        tx_receipt = _get_tx_receipt(web3, tx_id)
    except ConnectionClosed:
        # try again in this case
        tx_receipt = _get_tx_receipt(web3, tx_id)
    if tx_receipt is None:
        raise AssertionError(
            "Failed to get tx receipt for the `startOrder` transaction.."
        )

    if tx_receipt.status == 0:
        raise AssertionError("order transaction failed.")

    # check provider fees
    datatoken_contract = get_datatoken_contract(web3, datatoken_address)
    provider_fee_event_logs = datatoken_contract.events.ProviderFee().processReceipt(
        tx_receipt, errors=DISCARD
    )

    provider_fee_order_log = (
        provider_fee_event_logs[0] if provider_fee_event_logs else None
    )
    if not provider_fee_order_log:
        raise AssertionError(
            f"Cannot find the event for the provider fee in tx id {tx_id}."
        )
    if len(provider_fee_event_logs) > 1:
        raise AssertionError(
            f"Multiple order events in the same transaction !!! {provider_fee_order_log}"
        )

    if extra_data:
        provider_data = json.loads(provider_fee_order_log.args.providerData)
        if extra_data["environment"] != provider_data["environment"]:
            raise AssertionError(
                "Mismatch between ordered c2d environment and selected one."
            )

        valid_until = provider_fee_order_log.args.validUntil
        if datetime.utcnow().timestamp() >= valid_until:
            raise AssertionError("Ordered c2d time was exceeded, check validUntil.")

    if Web3.toChecksumAddress(
        provider_fee_order_log.args.providerFeeAddress
    ) != Web3.toChecksumAddress(provider_wallet.address):
        raise AssertionError(
            f"The providerFeeAddress {provider_fee_order_log.args.providerFeeAddress} in the event does "
            f"not match the provider address {provider_wallet.address}\n"
        )

    bts = b"".join(
        [
            provider_fee_order_log.args.r,
            provider_fee_order_log.args.s,
            Web3.toBytes(provider_fee_order_log.args.v - 27),
        ]
    )
    signature = keys.Signature(signature_bytes=bts)
    message_hash = Web3.solidityKeccak(
        ["bytes", "address", "address", "uint256", "uint256"],
        [
            provider_fee_order_log.args.providerData,
            provider_fee_order_log.args.providerFeeAddress,
            provider_fee_order_log.args.providerFeeToken,
            provider_fee_order_log.args.providerFeeAmount,
            provider_fee_order_log.args.validUntil,
        ],
    )

    prefix = "\x19Ethereum Signed Message:\n32"
    signable_hash = Web3.solidityKeccak(
        ["bytes", "bytes"], [Web3.toBytes(text=prefix), Web3.toBytes(message_hash)]
    )
    pk = keys.PrivateKey(provider_wallet.key)
    if not keys.ecdsa_verify(signable_hash, signature, pk.public_key):
        raise AssertionError(
            f"Provider was not able to check the signed message in ProviderFees event\n"
        )

    # check duration
    if provider_fee_order_log.args.validUntil > 0:
        timestamp_now = datetime.utcnow().timestamp()
        if provider_fee_order_log.args.validUntil < timestamp_now:
            raise AssertionError(
                f"Validity in transaction exceeds current UTC timestamp"
            )
    # end check provider fees

    # check if we have an OrderReused event. If so, get orderTxId and switch next checks to use that
    event_logs = datatoken_contract.events.OrderReused().processReceipt(
        tx_receipt, errors=DISCARD
    )
    order_log = event_logs[0] if event_logs else None
    if order_log and order_log.args.orderTxId:
        try:
            tx_receipt = _get_tx_receipt(web3, order_log.args.orderTxId)
        except ConnectionClosed:
            # try again in this case
            tx_receipt = _get_tx_receipt(web3, order_log.args.orderTxId)
        if tx_receipt is None:
            raise AssertionError("Failed to get tx receipt referenced in OrderReused..")
        if tx_receipt.status == 0:
            raise AssertionError("order referenced in OrderReused failed.")

    event_logs = datatoken_contract.events.OrderStarted().processReceipt(
        tx_receipt, errors=DISCARD
    )
    order_log = event_logs[0] if event_logs else None
    if not order_log:
        raise AssertionError(
            f"Cannot find the event for the order transaction with tx id {tx_id}."
        )
    if len(event_logs) > 1:
        raise AssertionError(
            f"Multiple order events in the same transaction !!! {event_logs}"
        )

    if order_log.args.serviceIndex != service.index:
        raise AssertionError(
            f"The service id in the event does "
            f"not match the requested asset. \n"
            f"requested: serviceIndex={service.index}\n"
            f"event: serviceIndex={order_log.args.serviceIndex}"
        )

    if order_log.args.amount < amount:
        raise ValueError(
            f"The amount in the event is less than the amount requested. \n"
            f"requested: amount={amount}\n"
            f"event: amount={order_log.args.amount}"
        )

    if sender not in [order_log.args.consumer, order_log.args.payer]:
        raise ValueError("sender of order transaction is not the consumer/payer.")

    tx = web3.eth.get_transaction(HexBytes(tx_id))

    return tx, order_log, provider_fee_order_log
