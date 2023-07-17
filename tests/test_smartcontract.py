#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import os

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.address import get_contract_address
from ocean_provider.utils.provider_fees import get_provider_fees
from ocean_provider.utils.services import ServiceType
from tests.helpers.nonce import build_nonce
from tests.test_helpers import (
    get_first_service_by_type,
    get_registered_asset,
    mint_100_datatokens,
    start_order,
)


@pytest.mark.integration
def test_download_smartcontract_asset(client, publisher_wallet, consumer_wallet, web3):
    # publish asset, that calls Router's swapOceanFee function (does not need params)
    router_address = get_contract_address(os.getenv("ADDRESS_FILE"), "Router", 8996)
    abi = {
        "inputs": [],
        "name": "swapOceanFee",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
    unencrypted_files_list = [
        {
            "type": "smartcontract",
            "address": router_address,
            "abi": abi,
            "chainId": 8996,
        }
    ]
    asset = get_registered_asset(
        publisher_wallet, unencrypted_files_list=unencrypted_files_list
    )
    service = get_first_service_by_type(asset, ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )
    tx_id, _ = start_order(
        web3,
        service.datatoken_address,
        consumer_wallet.address,
        service.index,
        get_provider_fees(asset, service, consumer_wallet.address, 0),
        consumer_wallet,
    )

    payload = {
        "documentId": asset.did,
        "serviceId": service.id,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    download_endpoint = BaseURLs.SERVICES_URL + "/download"

    # Consume using url index and signature (with nonce)
    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        service.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 200, f"{response.data}"


@pytest.mark.integration
def test_download_smartcontract_asset_with_userdata(
    client, publisher_wallet, consumer_wallet, web3
):
    # publish asset, that calls Router's getOPCFee for a provided  baseToken userdata
    router_address = get_contract_address(os.getenv("ADDRESS_FILE"), "Router", 8996)
    abi = {
        "inputs": [{"internalType": "address", "name": "baseToken", "type": "address"}],
        "name": "getOPCFee",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
    unencrypted_files_list = [
        {
            "type": "smartcontract",
            "address": router_address,
            "abi": abi,
            "chainId": 8996,
        }
    ]
    asset = get_registered_asset(
        publisher_wallet,
        unencrypted_files_list=unencrypted_files_list,
        custom_userdata=[
            {
                "name": "baseToken",
                "type": "text",
                "label": "baseToken",
                "required": True,
                "description": "baseToken to check for fee",
            }
        ],
    )
    service = get_first_service_by_type(asset, ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )
    tx_id, _ = start_order(
        web3,
        service.datatoken_address,
        consumer_wallet.address,
        service.index,
        get_provider_fees(asset, service, consumer_wallet.address, 0),
        consumer_wallet,
    )

    payload = {
        "documentId": asset.did,
        "serviceId": service.id,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "fileIndex": 0,
        "userdata": json.dumps({"baseToken": asset.nftAddress.lower()}),
    }

    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    # Consume using url index and signature (with nonce)
    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        service.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 200, f"{response.data}"


@pytest.mark.integration
def test_download_smartcontract_asset_with_pure_function(
    client, publisher_wallet, consumer_wallet, web3
):
    # publish dummy asset, to get a datatoken deployed
    dummy_asset = get_registered_asset(publisher_wallet)
    dummy_service = get_first_service_by_type(dummy_asset, ServiceType.ACCESS)
    # create abi for getId
    abi = {
        "inputs": [],
        "name": "getId",
        "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
        "stateMutability": "pure",
        "type": "function",
    }

    unencrypted_files_list = [
        {
            "type": "smartcontract",
            "address": dummy_service.datatoken_address,
            "abi": abi,
            "chainId": 8996,
        }
    ]
    asset = get_registered_asset(
        publisher_wallet, unencrypted_files_list=unencrypted_files_list
    )
    service = get_first_service_by_type(asset, ServiceType.ACCESS)
    mint_100_datatokens(
        web3, service.datatoken_address, consumer_wallet.address, publisher_wallet
    )
    tx_id, _ = start_order(
        web3,
        service.datatoken_address,
        consumer_wallet.address,
        service.index,
        get_provider_fees(asset, service, consumer_wallet.address, 0),
        consumer_wallet,
    )

    payload = {
        "documentId": asset.did,
        "serviceId": service.id,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    download_endpoint = BaseURLs.SERVICES_URL + "/download"

    # Consume using url index and signature (with nonce)
    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        service.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 200, f"{response.data}"
