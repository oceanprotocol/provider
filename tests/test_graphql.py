#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
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
def test_download_graphql_asset(client, publisher_wallet, consumer_wallet, web3):
    unencrypted_files_list = [
        {
            "type": "graphql",
            "url": "http://172.15.0.15:8030/graphql",
            "query": """
                        query {
                            indexingStatuses {
                              subgraph
                              chains
                              node
                            }
                        }
                        """,
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
def test_download_graphql_asset_with_userdata(
    client, publisher_wallet, consumer_wallet, web3
):
    unencrypted_files_list = [
        {
            "type": "graphql",
            "url": "http://172.15.0.15:8030/graphql",
            "query": """
                    query GetSubgraph($name: [String!]){
                          indexingStatuses(subgraphs: $name) {
                            subgraph
                            chains
                            node
                          }
                        }
                    """,
        }
    ]
    asset = get_registered_asset(
        publisher_wallet,
        unencrypted_files_list=unencrypted_files_list,
        custom_userdata=[
            {
                "name": "name",
                "type": "text",
                "label": "name",
                "required": True,
                "description": "Subgraph indexing status",
                "default": ["subgraph"],
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
        "userdata": json.dumps({"name": ["subgraph"]}),
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
    reply = json.loads(response.data)
    assert len(reply["data"]) == 1
    assert "indexingStatuses" in reply["data"].keys()
