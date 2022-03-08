import os
import requests
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.datatoken import get_datatoken_contract
from ocean_provider.utils.util import sign_send_and_wait_for_receipt  # TODO: move out out test helpers
from web3.main import Web3
from eth_account.messages import encode_defunct


def send_proof(
    web3,
    order_tx_id,
    provider_data,
    consumer_data,
    consumer_signature,
    consumer_address,
    datatoken_address,
):
    if not os.getenv("USE_CHAIN_PROOF") and not os.getenv("USE_HTTP_PROOF"):
        return

    provider_wallet = get_provider_wallet()
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
        except Exception:
            pass

        return

    datatoken_contract = get_datatoken_contract(web3, datatoken_address)
    provider_message = Web3.solidityKeccak(
        ["bytes32", "bytes"],
        [order_tx_id.hex(), provider_data.encode("utf-8")],
    )
    provider_signature = web3.eth.account.sign_message(
        encode_defunct(provider_message),
        private_key=provider_wallet.key
    ).signature.hex()

    # TODO: why not passthrough?
    consumer_message = Web3.solidityKeccak(
        ["bytes"],
        [consumer_data.encode("utf-8")],
    )
    consumer_signature_2 = web3.eth.account.sign_message(
        encode_defunct(consumer_message),
        private_key="0x5d75837394b078ce97bc289fa8d75e21000573520bfa7784a9d28ccaae602bf8"
    ).signature.hex()

    tx = datatoken_contract.functions.orderExecuted(
        order_tx_id,
        provider_data.encode("utf-8"),
        provider_signature,
        consumer_data.encode("utf-8"),
        consumer_signature_2,
        consumer_address,
    ).buildTransaction(
        {"from": provider_wallet.address, "gasPrice": int(web3.eth.gas_price * 1.1)}
    )

    a, b = sign_send_and_wait_for_receipt(web3, tx, provider_wallet)
