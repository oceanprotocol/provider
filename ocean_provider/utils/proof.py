import os

import requests
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.basics import get_provider_wallet, get_web3
from ocean_provider.utils.datatoken import get_datatoken_contract
from ocean_provider.utils.util import sign_and_send
from web3.main import Web3


def send_proof(
    chain_id,
    order_tx_id,
    provider_data,
    consumer_data,
    consumer_signature,
    consumer_address,
    datatoken_address,
):
    if not os.getenv("USE_CHAIN_PROOF") and not os.getenv("USE_HTTP_PROOF"):
        return

    web3 = get_web3(chain_id)
    provider_wallet = get_provider_wallet(chain_id)
    provider_signature = sign_message(provider_data, provider_wallet)

    if os.getenv("USE_HTTP_PROOF"):
        payload = {
            "orderTxId": order_tx_id.hex(),
            "providerData": provider_data,
            "providerSignature": provider_signature,
            "consumerData": consumer_data,
            "consumerSignature": consumer_signature,
            "consumerAddress": consumer_address,
        }

        try:
            requests.post(os.getenv("USE_HTTP_PROOF"), payload)

            return True
        except Exception:
            pass

        return

    datatoken_contract = get_datatoken_contract(web3, datatoken_address)
    provider_message = order_tx_id + Web3.toBytes(text=provider_data)
    provider_signature = sign_message(provider_message, provider_wallet)

    consumer_message = Web3.toBytes(text=consumer_data)

    tx_dict = {
        "from": provider_wallet.address,
    }
    if web3.eth.chain_id == 8996:
        tx_dict["gasPrice"] = web3.eth.gas_price
    else:
        tx_dict["maxPriorityFeePerGas"] = web3.eth.max_priority_fee

    tx = datatoken_contract.functions.orderExecuted(
        order_tx_id,
        Web3.toBytes(text=provider_data),
        provider_signature,
        consumer_message,
        consumer_signature,
        consumer_address,
    ).buildTransaction(tx_dict)

    _, transaction_id = sign_and_send(web3, tx, provider_wallet)

    return transaction_id
