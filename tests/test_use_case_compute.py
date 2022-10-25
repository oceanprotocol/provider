import json
import os
import time
from datetime import datetime, timedelta
from jsonsempai import magic  # noqa: F401
from artifacts import ERC721Template, ERC20Template

from eth_account import Account

from ocean_provider.constants import BaseURLs
from ocean_provider.myapp import app
from ocean_provider.utils.compute_environments import get_c2d_environments
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.provider_fees import get_provider_fees
from ocean_provider.utils.services import ServiceType
from ocean_provider.utils.util import sign_send_and_wait_for_receipt
from tests.helpers.compute_helpers import (
    get_compute_job_info,
    get_compute_signature,
    get_web3,
    post_to_compute,
    start_order,
)

from tests.test_compute import _get_registered_asset_with_compute
from tests.test_helpers import get_first_service_by_type, initialize_service


def free_c2d_env():
    environments = get_c2d_environments()

    return next(env for env in environments if float(env["priceMin"]) == float(0))


## Utils declaration ##

client = app.test_client()
publisher_wallet = Account.from_key(os.getenv("TEST_PRIVATE_KEY1"))
consumer_wallet = Account.from_key(os.getenv("TEST_PRIVATE_KEY2"))
web3 = get_web3()
free_c2d_env = free_c2d_env()
valid_until = int((datetime.utcnow() + timedelta(minutes=15)).timestamp())
print(f"chain id for this network is: {web3.eth.chain_id}")
#########################################

print(f"Step 2: Fresh consume the dataset + algo C2D")
dataset, algo, data_nft_dataset, datatoken_dataset, data_nft_algo, datatoken_algo = _get_registered_asset_with_compute(
    publisher_wallet, web3)

sa = get_first_service_by_type(dataset, ServiceType.COMPUTE)
datatoken_contract = web3.eth.contract(
    address=web3.toChecksumAddress(datatoken_dataset), abi=ERC20Template.abi
)
history = web3.eth.fee_history(block_count=1, newest_block="latest")
mint_datatoken_tx = datatoken_contract.functions.mint(publisher_wallet.address, to_wei(50)).buildTransaction({
    "from": publisher_wallet.address, "maxPriorityFeePerGas": web3.eth.max_priority_fee,
    "maxFeePerGas": web3.eth.max_priority_fee + 2 * history["baseFeePerGas"][0],
    "gas": 1000000
})
sign_send_and_wait_for_receipt(web3, mint_datatoken_tx, publisher_wallet)
assert datatoken_contract.caller.balanceOf(publisher_wallet.address) == to_wei(50)
tx_id, _ = start_order(
    web3,
    datatoken_dataset,
    free_c2d_env["consumerAddress"],
    sa.index,
    get_provider_fees(
        dataset.did,
        sa,
        publisher_wallet.address,
        valid_until,
        free_c2d_env["id"],
    ),
    publisher_wallet,
)
nonce, signature = get_compute_signature(
    client, publisher_wallet, dataset.did
)

# Start the compute job
print(f"Step 3: Start compute job")
payload = {
    "dataset": {
        "documentId": dataset.did,
        "serviceId": sa.id,
        "transferTxId": tx_id,
    },
    "algorithm": {"meta": algo.metadata},
    "signature": signature,
    "nonce": nonce,
    "consumerAddress": publisher_wallet.address,
    "environment": free_c2d_env["id"],
}

# response = client.post(
#         r'https://v4.provider.goerli.oceanprotocol.com/api/services/compute',
#         data=json.dumps(payload),
#         content_type="application/json",
# )

response = post_to_compute(client, payload)

assert response.status == "200 OK", f"start compute job failed at step 3: {response.data}"
job_info = response.json[0]
print(f"got response from starting compute job: {job_info}")
job_id = job_info.get("jobId", "")
nonce1, signature1 = get_compute_signature(client, publisher_wallet, dataset.did)
payload = dict(
    {
        "signature": signature1,
        "nonce": nonce1,
        "documentId": dataset.did,
        "consumerAddress": publisher_wallet.address,
        "jobId": job_id,
    }
)

compute_endpoint = BaseURLs.SERVICES_URL + "/compute"
job_info = get_compute_job_info(client, compute_endpoint, payload)
assert job_info, f"Failed to get job info for jobId {job_id} at step 4."
tries = 0
while tries < 200:
    job_info = get_compute_job_info(client, compute_endpoint, payload)
    if job_info["dateFinished"] and float(job_info["dateFinished"]) > 0:
        break
    tries = tries + 1
    time.sleep(5)

assert tries <= 200, "Timeout waiting for the job to be completed"

print(f"Finished monitoring at step 4...")
print(f"Reusing existing order for publisher wallet...")

response = initialize_service(client=client, did=dataset.did, service=sa, from_wallet=publisher_wallet,
                              raw_response=True, reuse_order=tx_id)
assert response.json["validOrder"] == tx_id

print(f"Steps 4-5: Reused order for publisher wallet. Now starting again the compute job")
# Start the compute job
nonce2, signature2 = get_compute_signature(
    client, consumer_wallet, dataset.did
)
payload = {
    "dataset": {
        "documentId": dataset.did,
        "serviceId": sa.id,
        "transferTxId": tx_id,
    },
    "algorithm": {"meta": algo.metadata},
    "signature": signature2,
    "nonce": nonce2,
    "consumerAddress": publisher_wallet.address,
    "environment": free_c2d_env["id"],
}

resp = post_to_compute(client, payload)
assert resp.status == "200 OK", f"start compute job failed at step 5: {resp.data}"

print(f"Switch to consumer wallet")
print(f"Steps 7-8: Consume the same dataset, start a different order and a different compute job.")
history = web3.eth.fee_history(block_count=1, newest_block="latest")
mint_datatoken_tx = datatoken_contract.functions.mint(consumer_wallet.address, to_wei(50)).buildTransaction({
    "from": consumer_wallet.address, "maxPriorityFeePerGas": web3.eth.max_priority_fee,
    "maxFeePerGas": web3.eth.max_priority_fee + 2 * history["baseFeePerGas"][0],
    "gas": 1000000
})
sign_send_and_wait_for_receipt(web3, mint_datatoken_tx, consumer_wallet)
assert datatoken_contract.caller.balanceOf(consumer_wallet.address) == to_wei(50)
tx_id_c, _ = start_order(
    web3,
    datatoken_dataset,
    free_c2d_env["consumerAddress"],
    sa.index,
    response.json["providerFees"],
    consumer_wallet,
)
nonce_c1, signature_c1 = get_compute_signature(
    client, consumer_wallet, dataset.did
)

# Start the compute job
payload = {
    "dataset": {
        "documentId": dataset.did,
        "serviceId": sa.id,
        "transferTxId": tx_id_c,
    },
    "algorithm": {"meta": algo.metadata},
    "signature": signature_c1,
    "nonce": nonce_c1,
    "consumerAddress": consumer_wallet.address,
    "environment": free_c2d_env["id"],
}

response = post_to_compute(client, payload)
assert response.status == "200 OK", f"start compute job failed at step 8: {response.data}"
job_info_c = response.json[0]
print(f"got response from starting compute job: {job_info}")

print(f"Step 9: Waiting time for fetching the job and reusing the previous order for consumer")
job_id_c = job_info_c.get("jobId", "")
nonce_c, signature_c = get_compute_signature(client, consumer_wallet, dataset.did)
payload = dict(
    {
        "signature": signature_c,
        "nonce": nonce_c,
        "documentId": dataset.did,
        "consumerAddress": consumer_wallet.address,
        "jobId": job_id_c,
    }
)

job_info = get_compute_job_info(client, compute_endpoint, payload)
assert job_info, f"Failed to get job info for jobId at step 9 {job_id_c}"
tries = 0
while tries < 200:
    job_info = get_compute_job_info(client, compute_endpoint, payload)
    if job_info["dateFinished"] and float(job_info["dateFinished"]) > 0:
        break
    tries = tries + 1
    time.sleep(5)

assert tries <= 200, "Timeout waiting for the job to be completed"

print(f"Finished monitoring for step 9...")
print(f"Reusing order for consumer wallet...")
response = initialize_service(client=client, did=dataset.did, service=sa, from_wallet=consumer_wallet,
                              raw_response=True, reuse_order=tx_id_c)
assert response.json["validOrder"] == tx_id_c

print(f"Step 10 - Start compute job again for consumer wallet")
nonce3, signature3 = get_compute_signature(
    client, consumer_wallet, dataset.did
)
# Start the compute job
payload = {
    "dataset": {
        "documentId": dataset.did,
        "serviceId": sa.id,
        "transferTxId": tx_id_c,
    },
    "algorithm": {"meta": algo.metadata},
    "signature": signature3,
    "nonce": nonce3,
    "consumerAddress": consumer_wallet.address,
    "environment": free_c2d_env["id"],
}

resp = post_to_compute(client, payload)
assert resp.status == "200 OK", f"start compute job failed at step 10: {resp.data}"

print(f"Step 11-12: Switch back to publisher wallet and reuse order from publisher wallet")
response = initialize_service(client=client, did=dataset.did, service=sa, from_wallet=publisher_wallet,
                              raw_response=True, reuse_order=tx_id_c)
assert response.json["validOrder"] == tx_id_c

print(f"Step 13: Start again the compute job from publisher wallet")
nonce4, signature4 = get_compute_signature(
    client, publisher_wallet, dataset.did
)
# Start the compute job
payload = {
    "dataset": {
        "documentId": dataset.did,
        "serviceId": sa.id,
        "transferTxId": tx_id,
    },
    "algorithm": {"meta": algo.metadata},
    "signature": signature4,
    "nonce": nonce4,
    "consumerAddress": publisher_wallet.address,
    "environment": free_c2d_env["id"],
}

response = post_to_compute(client, payload)
assert response.status == "200 OK", f"start compute job failed at step 13: {response.data}"
