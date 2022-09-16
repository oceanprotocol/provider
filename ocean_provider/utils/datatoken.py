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
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.data_nft import get_data_nft_contract
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
    return web3.eth.contract(
        address=web3.toChecksumAddress(address), abi=ERC20Template.abi
    )


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
    allow_expired_provider_fees=False,
):
    """Check order tx and provider fees validity on-chain for the given parameters."""
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

    provider_initialize_timestamp = 0
    if extra_data:
        provider_data = json.loads(provider_fee_order_log.args.providerData)
        if extra_data["environment"] != provider_data["environment"]:
            raise AssertionError(
                "Mismatch between ordered c2d environment and selected one."
            )
        provider_initialize_timestamp = provider_data["timestamp"]

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
            "Provider was not able to check the signed message in ProviderFees event\n"
        )

    timestamp_now = datetime.utcnow().timestamp()
    # check validUntil
    if provider_fee_order_log.args.validUntil > 0 and not allow_expired_provider_fees:
        if timestamp_now >= provider_fee_order_log.args.validUntil:
            # expired validUntil.  let's add the difference between provider_data["timestamp"](time of initializeCompute) and transaction timestamp.
            # Also add 90 secs as buffer, since block.timestamp can be manipulated
            block = web3.eth.get_block(tx_receipt.blockHash, False)
            if provider_initialize_timestamp > 0 and (
                timestamp_now
                >= provider_fee_order_log.args.validUntil
                + (block.timestamp - provider_initialize_timestamp + 90)
            ):
                raise AssertionError("Ordered c2d time was exceeded, check validUntil.")
    # end check provider fees

    # check if we have an OrderReused event. If so, get orderTxId and switch next checks to use that
    start_order_tx_id = tx_receipt.transactionHash
    try:
        event_logs = datatoken_contract.events.OrderReused().processReceipt(
            tx_receipt, errors=DISCARD
        )
    except Exception as e:
        logger.error(e)
    logger.debug(f"Got events log when searching for ReuseOrder : {event_logs}")
    log_timestamp = None
    order_log = event_logs[0] if event_logs else None
    if order_log and order_log.args.orderTxId:
        log_timestamp = order_log.args.timestamp
        try:
            tx_receipt = _get_tx_receipt(web3, order_log.args.orderTxId)
        except ConnectionClosed:
            # try again in this case
            tx_receipt = _get_tx_receipt(web3, order_log.args.orderTxId)
        if tx_receipt is None:
            raise AssertionError("Failed to get tx receipt referenced in OrderReused..")
        if tx_receipt.status == 0:
            raise AssertionError("order referenced in OrderReused failed.")

    logger.debug(f"Search for orderStarted in tx_receipt : {tx_receipt}")

    # this has changed now if the original original_tx was a reuseOrder
    start_order_tx_id = tx_receipt.transactionHash
    try:
        event_logs = datatoken_contract.events.OrderStarted().processReceipt(
            tx_receipt, errors=DISCARD
        )
    except Exception as e:
        logger.error(e)
    logger.debug(f"Got events log when searching for OrderStarted : {event_logs}")
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

    # Check if order expired. timeout == 0 means order is valid forever

    # use orderReused timestamp if it exists
    log_timestamp = (
        log_timestamp if log_timestamp is not None else order_log.args.timestamp
    )
    timestamp_delta = timestamp_now - log_timestamp
    logger.debug(
        f"verify_order_tx: service timeout = {service.timeout}, timestamp delta = {timestamp_delta}"
    )
    if service.timeout != 0:
        if timestamp_delta > service.timeout:
            raise ValueError(
                f"The order has expired. \n"
                f"current timestamp={timestamp_now}\n"
                f"order timestamp={log_timestamp}\n"
                f"timestamp delta={timestamp_delta}\n"
                f"service timeout={service.timeout}"
            )

    if web3.toChecksumAddress(sender) not in [
        web3.toChecksumAddress(order_log.args.consumer),
        web3.toChecksumAddress(order_log.args.payer),
    ]:
        raise ValueError("sender of order transaction is not the consumer/payer.")

    tx = web3.eth.get_transaction(HexBytes(tx_id))

    return tx, order_log, provider_fee_order_log, start_order_tx_id


def validate_order(
    web3,
    sender,
    tx_id,
    asset,
    service,
    extra_data=None,
    allow_expired_provider_fees=False,
):
    did = asset.did
    token_address = service.datatoken_address
    num_tokens = 1

    logger.debug(
        f"validate_order: did={did}, service_id={service.id}, tx_id={tx_id}, "
        f"sender={sender}, num_tokens={num_tokens}, token_address={token_address}"
    )

    nft_contract = get_data_nft_contract(web3, asset.nft["address"])
    assert nft_contract.caller.isDeployed(token_address)

    amount = to_wei(num_tokens)
    num_tries = 3
    i = 0
    while i < num_tries:
        logger.debug(f"validate_order is on trial {i + 1} in {num_tries}.")
        i += 1
        try:
            tx, order_event, provider_fees_event, start_order_tx_id = verify_order_tx(
                web3,
                token_address,
                tx_id,
                service,
                amount,
                sender,
                extra_data,
                allow_expired_provider_fees,
            )
            logger.debug(
                f"validate_order succeeded for: did={did}, service_id={service.id}, tx_id={tx_id}, "
                f"sender={sender}, num_tokens={num_tokens}, token_address={token_address}. "
                f"result is: tx={tx}, order_event={order_event}."
            )

            return tx, order_event, provider_fees_event, start_order_tx_id
        except ConnectionClosed:
            logger.debug("got ConnectionClosed error on validate_order.")
            if i == num_tries:
                logger.debug(
                    "reached max no. of tries, raise ConnectionClosed in validate_order."
                )
                raise
        except Exception:
            raise


def validate_transfer_not_used_for_other_service(
    did, service_id, transfer_tx_id, consumer_address, token_address
):
    logger.debug(
        f"validate_transfer_not_used_for_other_service: "
        f"did={did}, service_id={service_id}, transfer_tx_id={transfer_tx_id},"
        f" consumer_address={consumer_address}, token_address={token_address}"
    )
    return


def record_consume_request(
    did, service_id, order_tx_id, consumer_address, token_address, amount
):
    logger.debug(
        f"record_consume_request: "
        f"did={did}, service_id={service_id}, transfer_tx_id={order_tx_id}, "
        f"consumer_address={consumer_address}, token_address={token_address}, "
        f"amount={amount}"
    )
    return
