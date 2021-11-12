# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import hashlib
import json
import os
import pathlib
import time
import uuid

import ipfshttpclient
from jsonsempai import magic  # noqa: F401
from artifacts import ERC721Template
from eth_account.signers.local import LocalAccount
from eth_typing.evm import HexAddress
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.basics import (
    get_asset_from_metadatastore,
    get_datatoken_minter,
    get_web3,
)
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.data_nft import get_data_nft_contract
from ocean_provider.utils.data_nft_factory import get_data_nft_factory_contract
from ocean_provider.utils.datatoken import get_tx_receipt, mint, verify_order_tx
from ocean_provider.utils.did import compute_did_from_data_nft_address_and_chain_id
from tests.ddo.ddo_sample1_v4 import json_dict as ddo_sample1_v4
from tests.helpers.ddo_dict_builders import (
    build_credentials_dict,
    build_ddo_dict,
    build_metadata_dict_type_dataset,
    build_service_dict_type_access,
    get_access_service,
)
from web3.main import Web3


def sign_tx(web3, tx, private_key):
    """
    :param web3: Web3 object instance
    :param tx: transaction
    :param private_key: Private key of the account
    :return: rawTransaction (str)
    """
    account = web3.eth.account.from_key(private_key)
    nonce = web3.eth.get_transaction_count(account.address)
    gas_price = int(web3.eth.gas_price * 1.1)
    tx["gasPrice"] = gas_price
    tx["nonce"] = nonce
    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    return signed_tx.rawTransaction


def deploy_contract(w3, _json, private_key, *args):
    """
    :param w3: Web3 object instance
    :param private_key: Private key of the account
    :param _json: Json content of artifact file
    :param *args: arguments to be passed to be constructor of the contract
    :return: address of deployed contract
    """
    account = w3.eth.account.from_key(private_key)
    _contract = w3.eth.contract(abi=_json["abi"], bytecode=_json["bytecode"])
    built_tx = _contract.constructor(*args).buildTransaction({"from": account.address})
    if "gas" not in built_tx:
        built_tx["gas"] = w3.eth.estimate_gas(built_tx)
    raw_tx = sign_tx(w3, built_tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    time.sleep(3)
    try:
        address = w3.eth.get_transaction_receipt(tx_hash)["contractAddress"]
        return address
    except Exception:
        print(f"tx not found: {tx_hash.hex()}")
        raise


def get_ocean_token_address() -> HexAddress:
    # TODO: Return actual ocean address
    return "0x0000000000000000000000000000000000000000"


def deploy_data_nft(
    web3: Web3,
    name: str,
    symbol: str,
    template_index: int,
    additionalERC20Deployer: HexAddress,
    base_uri: str,
    from_wallet: LocalAccount,
) -> HexAddress:
    data_nft_factory = get_data_nft_factory_contract(web3)
    deploy_data_nft_tx = data_nft_factory.functions.deployERC721Contract(
        name, symbol, template_index, additionalERC20Deployer, base_uri
    ).buildTransaction({"from": from_wallet.address})
    deploy_data_nft_tx_signed = sign_tx(web3, deploy_data_nft_tx, from_wallet.key)
    deploy_data_nft_tx_hash = web3.eth.send_raw_transaction(deploy_data_nft_tx_signed)
    deploy_data_nft_receipt = web3.eth.wait_for_transaction_receipt(
        deploy_data_nft_tx_hash
    )
    data_nft_address = (
        data_nft_factory.events.NFTCreated()
        .processReceipt(deploy_data_nft_receipt)[0]
        .args.newTokenAddress
    )
    return data_nft_address


def deploy_datatoken(
    web3: Web3,
    data_nft_address: HexAddress,
    template_index: int,
    name: str,
    symbol: str,
    minter: HexAddress,
    fee_manager: HexAddress,
    publishing_market: HexAddress,
    publishing_market_fee_token: HexAddress,
    cap: int,
    publishing_market_fee_amount: int,
    from_wallet: LocalAccount,
    unused_bytes: bytes = "\x00",
) -> HexAddress:
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    deploy_datatoken_tx = data_nft_contract.functions.createERC20(
        template_index,
        [name, symbol],
        [minter, fee_manager, publishing_market, publishing_market_fee_token],
        [cap, publishing_market_fee_amount],
        unused_bytes,
    ).buildTransaction({"from": from_wallet.address})
    deploy_datatoken_tx_signed = sign_tx(web3, deploy_datatoken_tx, from_wallet.key)
    deploy_datatoken_tx_hash = web3.eth.send_raw_transaction(deploy_datatoken_tx_signed)
    deploy_datatoken_receipt = web3.eth.wait_for_transaction_receipt(
        deploy_datatoken_tx_hash
    )
    datatoken_address = (
        data_nft_contract.events.TokenCreated()
        .processReceipt(deploy_datatoken_receipt)[0]
        .args.newTokenAddress
    )
    return datatoken_address


def get_registered_ddo(wallet):
    web3 = get_web3()
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT 1",
        "DNFT1",
        1,
        "0x0000000000000000000000000000000000000000",
        "",
        wallet,
    )

    # datatoken_address = deploy_datatoken(
    #     web3=web3,
    #     data_nft_address=data_nft_address,
    #     template_index=1,
    #     name="Datatoken 1",
    #     symbol="DT1",
    #     minter=wallet.address,
    #     fee_manager=wallet.address,
    #     publishing_market="0x0000000000000000000000000000000000000000",
    #     publishing_market_fee_token=get_ocean_token_address(),
    #     cap=1000,
    #     publishing_market_fee_amount=0,
    #     from_wallet=wallet,
    # )

    chain_id = web3.eth.chain_id
    did = compute_did_from_data_nft_address_and_chain_id(data_nft_address, chain_id)
    ddo = build_ddo_dict(
        did=did,
        chain_id=chain_id,
        metadata=build_metadata_dict_type_dataset(),
        services=[
            build_service_dict_type_access(
                # TODO: use actual datatoken address
                datatoken_address="0x0000000000000000000000000000000000000000",
                service_endpoint="http://localhost:8030",
                encrypted_files="0x1234",
            )
        ],
        credentials=build_credentials_dict(),
    )

    try:
        send_create_tx(web3, data_nft_address, ddo, bytes([0]), wallet)
    except Exception as e:
        print(f"error publishing ddo {did} in Aquarius: {e}")
        raise

    aqua_root = "http://localhost:5000"
    ddo = wait_for_ddo(aqua_root, did)
    assert ddo, f"resolve did {did} failed."

    return ddo


def send_create_tx(web3, data_nft_address, ddo, flags, account):
    provider_url = "http://localhost:8030"
    provider_address = "0xe2DD09d719Da89e5a3D0F2549c7E24566e947260"
    document = json.dumps(ddo)

    # test asset - we are not compressing nor encrypting
    encrypted_data = document.encode("utf-8")
    dataHash = hashlib.sha256(document.encode("UTF-8")).hexdigest()

    dt_contract = get_web3().eth.contract(
        abi=ERC721Template.abi, address=data_nft_address
    )

    txn_hash = dt_contract.functions.setMetaData(
        0, provider_url, provider_address, flags, encrypted_data, dataHash
    ).transact({"from": account.address})
    txn_receipt = get_web3().eth.wait_for_transaction_receipt(txn_hash)

    return txn_receipt


def get_dataset_ddo_with_access_service(client, wallet):
    return get_registered_ddo(wallet)


def get_dataset_ddo_with_multiple_files(client, wallet):
    metadata = get_sample_ddo_with_multiple_files()["service"][0]["attributes"]
    for i in range(3):
        metadata["main"]["files"][i]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")
    return get_registered_ddo(client, wallet, metadata, service)


def get_dataset_ddo_disabled(client, wallet):
    metadata = get_sample_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")

    return get_registered_ddo(client, wallet, metadata, service, disabled=True)


def get_dataset_ddo_with_denied_consumer(client, wallet, consumer_addr):
    metadata = get_sample_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")

    return get_registered_ddo(
        client,
        wallet,
        metadata,
        service,
        custom_credentials={"deny": [{"type": "address", "values": [consumer_addr]}]},
    )


def get_sample_algorithm_ddo():
    path = get_resource_path("ddo", "ddo_sample_algorithm.json")
    assert path.exists(), f"{path} does not exist!"
    with open(path, "r") as file_handle:
        metadata = file_handle.read()
    return json.loads(metadata)


def get_sample_ddo_with_compute_service():
    path = get_resource_path("ddo", "ddo_with_compute_service.json")
    assert path.exists(), f"{path} does not exist!"
    with open(path, "r") as file_handle:
        metadata = file_handle.read()
    return json.loads(metadata)


def get_dataset_with_invalid_url_ddo(client, wallet):
    metadata = get_invalid_url_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")
    return get_registered_ddo(client, wallet, metadata, service)


def get_dataset_with_ipfs_url_ddo(client, wallet):
    metadata = get_ipfs_url_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")
    return get_registered_ddo(client, wallet, metadata, service)


def get_algorithm_ddo(client, wallet):
    metadata = get_sample_algorithm_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")
    return get_registered_ddo(client, wallet, metadata, service)


def get_algorithm_ddo_different_provider(client, wallet):
    metadata = get_sample_algorithm_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata, diff_provider=True)
    metadata["main"].pop("cost")
    return get_registered_ddo(client, wallet, metadata, service)


def get_nonce(client, address):
    endpoint = BaseURLs.ASSETS_URL + "/nonce"
    response = client.get(
        endpoint + "?" + f"&userAddress={address}", content_type="application/json"
    )
    assert (
        response.status_code == 200 and response.data
    ), f"get nonce endpoint failed: response status {response.status}, data {response.data}"

    value = response.json if response.json else json.loads(response.data)
    return value["nonce"]


def mint_tokens_and_wait(data_token_contract, receiver_wallet, minter_wallet):
    web3 = get_web3()
    dtc = data_token_contract
    tx_id = mint(web3, dtc, receiver_wallet.address, to_wei(50), minter_wallet)
    get_tx_receipt(web3, tx_id)
    time.sleep(2)

    def verify_supply(mint_amount=to_wei(50)):
        supply = dtc.caller.totalSupply()
        if supply <= 0:
            _tx_id = mint(
                web3, dtc, receiver_wallet.address, mint_amount, minter_wallet
            )
            get_tx_receipt(web3, _tx_id)
            supply = dtc.caller.totalSupply()
        return supply

    while True:
        try:
            s = verify_supply()
            if s > 0:
                break
        except (ValueError, Exception):
            pass


def get_resource_path(dir_name, file_name):
    base = os.path.realpath(__file__).split(os.path.sep)[1:-1]
    if dir_name:
        return pathlib.Path(os.path.join(os.path.sep, *base, dir_name, file_name))
    else:
        return pathlib.Path(os.path.join(os.path.sep, *base, file_name))


def get_sample_ddo():
    return ddo_sample1_v4


def get_sample_ddo_with_multiple_files():
    path = get_resource_path("ddo", "ddo_sa_sample_multiple_files.json")
    assert path.exists(), f"{path} does not exist!"
    with open(path, "r") as file_handle:
        metadata = file_handle.read()
    return json.loads(metadata)


def get_invalid_url_ddo():
    path = get_resource_path("ddo", "ddo_sample_invalid_url.json")
    assert path.exists(), f"{path} does not exist!"
    with open(path, "r") as file_handle:
        metadata = file_handle.read()
    return json.loads(metadata)


def get_ipfs_url_ddo():
    path = get_resource_path("ddo", "ddo_sample_ipfs_url.json")
    assert path.exists(), f"{path} does not exist!"
    with open(path, "r") as file_handle:
        metadata = file_handle.read()
    client = ipfshttpclient.connect("/dns/172.15.0.16/tcp/5001/http")
    cid = client.add("./tests/resources/ddo_sample_file.txt")["Hash"]
    url = f"ipfs://{cid}"
    metadata_json = json.loads(metadata)
    metadata_json["service"][0]["attributes"]["main"]["files"][0]["url"] = url
    return metadata_json


def wait_for_ddo(metadata_cache_url, did, timeout=30):
    start = time.time()
    ddo = None
    while not ddo:
        ddo = get_asset_from_metadatastore(metadata_cache_url, did)

        if not ddo:
            time.sleep(0.2)

        if time.time() - start > timeout:
            break

    return ddo


def send_order(client, ddo, datatoken, service, cons_wallet, expect_failure=False):
    init_endpoint = BaseURLs.ASSETS_URL + "/initialize"
    # initialize the service
    payload = dict(
        {
            "documentId": ddo.did,
            "serviceId": service.index,
            "serviceType": service.type,
            "dataToken": datatoken.address,
            "consumerAddress": cons_wallet.address,
        }
    )

    request_url = (
        init_endpoint + "?" + "&".join([f"{k}={v}" for k, v in payload.items()])
    )

    response = client.get(request_url)

    if expect_failure:
        assert response.status == "400 BAD REQUEST"
        return

    assert response.status == "200 OK"

    tx_params = response.json
    num_tokens = tx_params["numTokens"]
    nonce = tx_params.get("nonce")
    receiver = tx_params["to"]
    assert tx_params["from"] == cons_wallet.address
    assert receiver == get_datatoken_minter(datatoken.address)
    assert tx_params["dataToken"] == ddo.data_token_address
    assert nonce is not None, f"expecting a `nonce` value in the response, got {nonce}"
    # Transfer tokens to provider account
    amount = to_wei(str(num_tokens))

    contract_fn = datatoken.functions.startOrder(
        cons_wallet.address,
        amount,
        int(service.index),
        "0xF9f2DB837b3db03Be72252fAeD2f6E0b73E428b9",
    )

    web3 = get_web3()
    _transact = {
        "from": cons_wallet.address,
        "account_key": str(cons_wallet.key),
        "chainId": web3.eth.chain_id,
    }
    tx_id = contract_fn.transact(_transact).hex()

    verify_order_tx(
        web3, datatoken, tx_id, ddo.asset_id, service.index, amount, cons_wallet.address
    )
    return tx_id
