# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import os
import pathlib
import time
import uuid
from hashlib import sha256

import ipfshttpclient
from eth_account.signers.local import LocalAccount
from eth_typing.evm import HexAddress
from flask.testing import FlaskClient
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.basics import (
    get_asset_from_metadatastore,
    get_config,
    get_web3,
)
from ocean_provider.utils.data_nft import Flags, MetadataState, get_data_nft_contract
from ocean_provider.utils.data_nft_factory import (
    CHAIN_ID_TO_NETWORK_NAME,
    get_data_nft_factory_contract,
)
from ocean_provider.utils.datatoken import get_datatoken_contract
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
from web3.types import TxParams, TxReceipt

BLACK_HOLE_ADDRESS = "0x0000000000000000000000000000000000000000"


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


def get_ocean_token_address(web3: Web3) -> HexAddress:
    address_file = pathlib.Path(get_config().address_file).expanduser().resolve()
    with open(address_file) as f:
        address_json = json.load(f)

    chain_id = web3.eth.chain_id
    network_name = CHAIN_ID_TO_NETWORK_NAME.get(chain_id)
    if not network_name:
        raise ValueError(f"Unsupported chain id: {chain_id}")

    return address_json[network_name]["Ocean"]


def sign_send_and_wait_for_receipt(
    web3: Web3, transaction: TxParams, from_account: LocalAccount
) -> TxReceipt:
    """Returns the transaction id and transaction receipt."""
    transaction_signed = sign_tx(web3, transaction, from_account.key)
    transaction_hash = web3.eth.send_raw_transaction(transaction_signed)
    return (transaction_hash, web3.eth.wait_for_transaction_receipt(transaction_hash))


def deploy_data_nft(
    web3: Web3,
    name: str,
    symbol: str,
    template_index: int,
    additional_erc20_deployer: HexAddress,
    base_uri: str,
    from_wallet: LocalAccount,
) -> HexAddress:
    data_nft_factory = get_data_nft_factory_contract(web3)
    deploy_data_nft_tx = data_nft_factory.functions.deployERC721Contract(
        name, symbol, template_index, additional_erc20_deployer, base_uri
    ).buildTransaction({"from": from_wallet.address})
    _, deploy_data_nft_receipt = sign_send_and_wait_for_receipt(
        web3, deploy_data_nft_tx, from_wallet
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
    unused_bytes: bytes = b"\x00",
) -> HexAddress:
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    deploy_datatoken_tx = data_nft_contract.functions.createERC20(
        template_index,
        [name, symbol],
        [minter, fee_manager, publishing_market, publishing_market_fee_token],
        [cap, publishing_market_fee_amount],
        [unused_bytes],
    ).buildTransaction({"from": from_wallet.address})
    _, deploy_datatoken_receipt = sign_send_and_wait_for_receipt(
        web3, deploy_datatoken_tx, from_wallet
    )
    datatoken_address = (
        data_nft_contract.events.TokenCreated()
        .processReceipt(deploy_datatoken_receipt)[0]
        .args.newTokenAddress
    )
    return datatoken_address


def mint_100_datatokens(
    web3: Web3,
    datatoken_address: HexAddress,
    receiver_address: HexAddress,
    from_wallet: LocalAccount,
) -> int:
    """Mint 100 datatokens to the receiver address and return totalSupply"""
    datatoken_contract = get_datatoken_contract(web3, datatoken_address)
    mint_datatoken_tx = datatoken_contract.functions.mint(
        receiver_address, 100
    ).buildTransaction({"from": from_wallet.address})
    sign_send_and_wait_for_receipt(web3, mint_datatoken_tx, from_wallet)
    return datatoken_contract.caller.totalSupply()


def get_registered_asset(from_wallet):
    web3 = get_web3()
    data_nft_address = deploy_data_nft(
        web3=web3,
        name="Data NFT 1",
        symbol="DNFT1",
        template_index=1,
        additional_erc20_deployer=BLACK_HOLE_ADDRESS,
        base_uri="",
        from_wallet=from_wallet,
    )

    datatoken_address = deploy_datatoken(
        web3=web3,
        data_nft_address=data_nft_address,
        template_index=1,
        name="Datatoken 1",
        symbol="DT1",
        minter=from_wallet.address,
        fee_manager=from_wallet.address,
        publishing_market=BLACK_HOLE_ADDRESS,
        publishing_market_fee_token=get_ocean_token_address(web3),
        cap=1000,
        publishing_market_fee_amount=0,
        from_wallet=from_wallet,
    )

    # TODO: Encrypt files

    chain_id = web3.eth.chain_id
    did = compute_did_from_data_nft_address_and_chain_id(data_nft_address, chain_id)
    ddo = build_ddo_dict(
        did=did,
        chain_id=chain_id,
        metadata=build_metadata_dict_type_dataset(),
        services=[
            build_service_dict_type_access(
                datatoken_address=datatoken_address,
                service_endpoint="http://localhost:8030",
                encrypted_files="0x1234",
            )
        ],
        credentials=build_credentials_dict(),
    )

    ddo_string = json.dumps(ddo)
    ddo_bytes = ddo_string.encode("utf-8")
    # TODO: Compress and encrypt DDO
    encrypted_ddo = ddo_bytes
    ddo_hash = sha256(ddo_bytes).hexdigest()

    set_metadata(
        web3,
        MetadataState.ACTIVE,
        "http://localhost:8030",
        from_wallet.address,
        data_nft_address,
        Flags.PLAIN.to_byte(),
        encrypted_ddo,
        ddo_hash,
        from_wallet,
    )

    aqua_root = "http://localhost:5000"
    asset = wait_for_asset(aqua_root, did)
    assert asset, f"resolve did {did} failed."

    return asset


def set_metadata(
    web3: Web3,
    state: MetadataState,
    provider_url: str,
    provider_address: HexAddress,
    data_nft_address: HexAddress,
    flags: bytes,
    encrypted_ddo: bytes,
    ddo_hash: str,
    from_wallet: LocalAccount,
):
    """Publish encrypted DDO on-chain by calling the ERC721Template setMetaData
    contract function"""
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    transaction = data_nft_contract.functions.setMetaData(
        state, provider_url, provider_address, flags, encrypted_ddo, ddo_hash
    ).buildTransaction({"from": from_wallet.address})
    return sign_send_and_wait_for_receipt(web3, transaction, from_wallet)


def get_dataset_asset_with_access_service(client, wallet):
    return get_registered_asset(wallet)


def get_dataset_ddo_with_multiple_files(client, wallet):
    metadata = get_sample_ddo_with_multiple_files()["service"][0]["attributes"]
    for i in range(3):
        metadata["main"]["files"][i]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")
    return get_registered_asset(client, wallet, metadata, service)


def get_dataset_ddo_disabled(client, wallet):
    metadata = get_sample_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")

    return get_registered_asset(client, wallet, metadata, service, disabled=True)


def get_dataset_ddo_with_denied_consumer(client, wallet, consumer_addr):
    metadata = get_sample_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")

    return get_registered_asset(
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
    return get_registered_asset(client, wallet, metadata, service)


def get_dataset_with_ipfs_url_ddo(client, wallet):
    metadata = get_ipfs_url_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")
    return get_registered_asset(client, wallet, metadata, service)


def get_algorithm_ddo(client, wallet):
    metadata = get_sample_algorithm_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata)
    metadata["main"].pop("cost")
    return get_registered_asset(client, wallet, metadata, service)


def get_algorithm_ddo_different_provider(client, wallet):
    metadata = get_sample_algorithm_ddo()["service"][0]["attributes"]
    metadata["main"]["files"][0]["checksum"] = str(uuid.uuid4())
    service = get_access_service(wallet.address, metadata, diff_provider=True)
    metadata["main"].pop("cost")
    return get_registered_asset(client, wallet, metadata, service)


def get_nonce(client, address):
    endpoint = BaseURLs.SERVICES_URL + "/nonce"
    response = client.get(
        endpoint + "?" + f"&userAddress={address}", content_type="application/json"
    )
    assert (
        response.status_code == 200 and response.data
    ), f"get nonce endpoint failed: response status {response.status}, data {response.data}"

    value = response.json if response.json else json.loads(response.data)
    return value["nonce"]


def mint_tokens_and_wait(datatoken_contract, receiver_wallet, minter_wallet):
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


def wait_for_asset(metadata_cache_url, did, timeout=30):
    start = time.time()
    ddo = None
    while not ddo:
        ddo = get_asset_from_metadatastore(metadata_cache_url, did)

        if not ddo:
            time.sleep(0.2)

        if time.time() - start > timeout:
            break

    return ddo


def initialize_service(
    client: FlaskClient,
    did: str,
    service_id: int,
    service_type: str,
    datatoken_address: HexAddress,
    from_wallet: LocalAccount,
):
    return client.get(
        BaseURLs.ASSETS_URL + "/initialize",
        json={
            "documentId": did,
            "serviceId": service_id,
            "serviceType": service_type,
            "dataToken": datatoken_address,
            "consumerAddress": from_wallet.address,
        },
    )


def start_order(
    web3: Web3,
    datatoken_address: HexAddress,
    consumer: HexAddress,
    amount: int,
    service_index: int,
    consumeFeeAddress: HexAddress,
    consumeFeeToken: HexAddress,
    consumeFeeAmount: int,
    from_wallet: LocalAccount,
):
    datatoken_contract = get_datatoken_contract(web3, datatoken_address)
    start_order_tx = datatoken_contract.functions.startOrder(
        consumer,
        amount,
        service_index,
        consumeFeeAddress,
        consumeFeeToken,
        consumeFeeAmount,
    ).buildTransaction({"from": from_wallet.address})
    return sign_send_and_wait_for_receipt(web3, start_order_tx, from_wallet)
