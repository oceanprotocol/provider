#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
import logging
import os
import time
from unittest.mock import patch

import pytest
from eth_account import Account
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.currency import to_wei
from ocean_provider.utils.data_nft_factory import get_data_nft_factory_address
from ocean_provider.utils.datatoken import get_datatoken_contract
from ocean_provider.utils.provider_fees import get_provider_fees
from ocean_provider.utils.services import ServiceType
from tests.helpers.compute_helpers import (
    get_future_valid_until,
    build_and_send_ddo_with_compute_service,
)
from tests.helpers.constants import ARWEAVE_TRANSACTION_ID
from tests.helpers.nonce import build_nonce
from tests.test_auth import create_token
from tests.test_helpers import (
    approve_multiple_tokens,
    get_dataset_ddo_with_multiple_files,
    get_first_service_by_type,
    get_registered_asset,
    get_service_by_index,
    mint_100_datatokens,
    mint_multiple_tokens,
    start_multiple_order,
    start_order,
    try_download,
    get_ocean_token_address,
)

logger = logging.getLogger(__name__)


@pytest.mark.integration
@pytest.mark.parametrize(
    "userdata,erc20_enterprise",
    [(False, False), ("valid", False), ("invalid", False), (False, True)],
)
def test_download_service(
    client, publisher_wallet, consumer_wallet, web3, userdata, erc20_enterprise
):
    asset = get_registered_asset(publisher_wallet, erc20_enterprise=erc20_enterprise)
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

    if userdata:
        payload["userdata"] = (
            '{"surname":"XXX", "age":12}' if userdata == "valid" else "cannotdecode"
        )

    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    # Consume using url index and signature (withOUT nonce), should fail
    payload["signature"] = sign_message(asset.did, consumer_wallet)
    print(">>>> Expecting request error from the download endpoint <<<<")

    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 400, f"{response.data}"

    # Consume using auth token
    token = create_token(client, consumer_wallet)
    nonce = build_nonce(consumer_wallet.address)
    payload["nonce"] = nonce
    payload.pop("signature")
    response = client.get(
        download_endpoint, query_string=payload, headers={"AuthToken": token}
    )
    assert response.status == "200 OK"

    # Consume using url index and signature (with nonce)
    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        service.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 200, f"{response.data}"

    # Try to access service though unsupported method, should fail
    response = client.head(
        service.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 405, f"{response.data}"

    if not userdata and not erc20_enterprise:
        nonce = build_nonce(consumer_wallet.address)
        _msg = f"{asset.did}{nonce}"
        payload["signature"] = sign_message(_msg, consumer_wallet)
        payload["nonce"] = nonce
        payload["transferTxId"] = "0x123"  # some dummy
        response = client.get(download_endpoint, query_string=payload)
        assert response.status_code == 400, f"{response.data}"


@pytest.mark.integration
def test_download_multiple_orders(client, publisher_wallet, consumer_wallet, web3):
    nft_factory_address = get_data_nft_factory_address(web3)
    # create an asset with one services using standard template
    asset1 = get_registered_asset(publisher_wallet, erc20_enterprise=False)
    service1 = get_first_service_by_type(asset1, ServiceType.ACCESS)

    # create an asset with two services using enterprise
    asset2 = get_registered_asset(
        publisher_wallet, erc20_enterprise=True, no_of_services=2
    )
    service2 = get_first_service_by_type(asset2, ServiceType.ACCESS)
    service3 = get_service_by_index(asset2, 1)

    mint_multiple_tokens(
        web3,
        [
            service1.datatoken_address,
            service2.datatoken_address,
            service3.datatoken_address,
        ],
        consumer_wallet.address,
        publisher_wallet,
    )
    approve_multiple_tokens(
        web3,
        [
            service1.datatoken_address,
            service2.datatoken_address,
            service3.datatoken_address,
        ],
        nft_factory_address,
        1,
        consumer_wallet,
    )
    tx_id, _ = start_multiple_order(
        web3,
        [
            (
                service1.datatoken_address,
                consumer_wallet.address,
                service1.index,
                get_provider_fees(asset1, service1, consumer_wallet.address, 0),
                (
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                    0,
                ),
            ),
            (
                service2.datatoken_address,
                consumer_wallet.address,
                service2.index,
                get_provider_fees(asset2, service2, consumer_wallet.address, 0),
                (
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                    0,
                ),
            ),
            (
                service3.datatoken_address,
                consumer_wallet.address,
                service3.index,
                get_provider_fees(asset2, service3, consumer_wallet.address, 0),
                (
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                    0,
                ),
            ),
        ],
        consumer_wallet,
    )
    # check to see if we can get all 3 files
    try_download(client, asset1, service1, consumer_wallet, tx_id, False)
    try_download(client, asset2, service2, consumer_wallet, tx_id, False)
    try_download(client, asset2, service3, consumer_wallet, tx_id, False)


@pytest.mark.integration
@pytest.mark.parametrize("timeout", [0, 1, 3600])
def test_download_timeout(client, publisher_wallet, consumer_wallet, web3, timeout):
    """
    If timeout == 0, order is valid forever
    else reject request if current timestamp - order timestamp > timeout
    """
    asset = get_registered_asset(publisher_wallet, timeout=timeout)
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

    # Sleep for 1 second (give the order time to expire)
    time.sleep(1)

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

    # Expect failure if timeout is 1 second. Expect success otherwise
    if timeout == 1:
        assert response.status_code == 400, f"{response.data}"
    else:
        assert response.status_code == 200, f"{response.data}"


@pytest.mark.unit
def test_empty_payload(client):
    consume = client.get(
        BaseURLs.SERVICES_URL + "/download", data=None, content_type="application/json"
    )
    assert consume.status_code == 400


@pytest.mark.integration
def test_download_multiple_files(client, publisher_wallet, consumer_wallet, web3):
    asset = get_dataset_ddo_with_multiple_files(client, publisher_wallet)
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

    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"

    # Consume using url index and auth token
    # (let the provider do the decryption)
    payload = {
        "documentId": asset.did,
        "serviceId": service.id,
        "consumerAddress": consumer_wallet.address,
        "signature": sign_message(_msg, consumer_wallet),
        "transferTxId": tx_id,
        "fileIndex": 0,
        "nonce": nonce,
    }
    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"

    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["fileIndex"] = 1
    payload["nonce"] = nonce
    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"

    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["fileIndex"] = 2
    payload["nonce"] = nonce
    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"


@pytest.mark.integration
def test_download_compute_asset_by_c2d(client, publisher_wallet, consumer_wallet, web3):
    asset = get_dataset_ddo_with_multiple_files(
        client, publisher_wallet, service_type="compute"
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

    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"

    payload = {
        "documentId": asset.did,
        "serviceId": service.id,
        "consumerAddress": consumer_wallet.address,
        "signature": sign_message(_msg, consumer_wallet),
        "transferTxId": tx_id,
        "fileIndex": 0,
        "nonce": nonce,
    }

    def other_service(_):
        new_service = copy.deepcopy(service)
        new_service.type = "compute"
        return new_service

    with patch("ocean_provider.routes.consume.get_c2d_environments") as mock:
        mock.return_value = [{"consumerAddress": consumer_wallet.address}]
        with patch(
            "ocean_provider.utils.asset.Asset.get_service_by_id",
            side_effect=other_service,
        ):
            download_endpoint = BaseURLs.SERVICES_URL + "/download"
            response = client.get(download_endpoint, query_string=payload)
            assert response.status_code == 200, f"{response.data}"


@pytest.mark.integration
def test_download_compute_asset_by_user_fails(
    client, publisher_wallet, consumer_wallet, web3
):
    asset = get_dataset_ddo_with_multiple_files(client, publisher_wallet)
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

    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"

    payload = {
        "documentId": asset.did,
        "serviceId": service.id,
        "consumerAddress": consumer_wallet.address,
        "signature": sign_message(_msg, consumer_wallet),
        "transferTxId": tx_id,
        "fileIndex": 0,
        "nonce": nonce,
    }

    def other_service(_):
        new_service = copy.deepcopy(service)
        new_service.type = "compute"
        return new_service

    with patch("ocean_provider.routes.consume.get_c2d_environments") as mock:
        mock.return_value = [
            {"consumerAddress": "0x0000000000000000000000000000000000000123"}
        ]
        with patch(
            "ocean_provider.utils.asset.Asset.get_service_by_id",
            side_effect=other_service,
        ):
            download_endpoint = BaseURLs.SERVICES_URL + "/download"
            response = client.get(download_endpoint, query_string=payload)
            assert response.status_code == 400, f"{response.data}"
            assert (
                response.json["error"]
                == f"Provider Ganache: Service with index={service.id} is not an access service."
            )


def test_download_arweave(client, publisher_wallet, consumer_wallet, web3):
    unencrypted_files_list = [
        {
            "type": "arweave",
            "transactionId": ARWEAVE_TRANSACTION_ID,
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

    # Consume using index and signature (with nonce)
    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        service.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 200, f"{response.data}"
    assert (
        response.data.decode("utf-8").partition("\n")[0]
        == "% 1. Title: Branin Function"
    )


@pytest.mark.integration
def test_consume_algo_with_credentials(
    client, publisher_wallet, consumer_wallet, free_c2d_env, web3
):
    valid_until = get_future_valid_until()
    deployer_wallet = Account.from_key(os.getenv("FACTORY_DEPLOYER_PRIVATE_KEY"))
    fee_token = get_datatoken_contract(web3, get_ocean_token_address(web3))
    fee_token.functions.mint(consumer_wallet.address, to_wei(80)).transact(
        {"from": deployer_wallet.address}
    )
    # Use case 1: Consume an algorithm asset by an address which is in the denied list
    algo_credentials = {
        "allow": [],
        "deny": [{"type": "address", "values": [consumer_wallet.address]}],
    }

    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        consumer_wallet,
        True,
        custom_algo_credentials=algo_credentials,
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
        fee_token_args=(fee_token, to_wei(80)),
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    mint_100_datatokens(
        web3, sa_compute.datatoken_address, consumer_wallet.address, publisher_wallet
    )
    tx_id, _ = start_order(
        web3,
        sa_compute.datatoken_address,
        consumer_wallet.address,
        sa_compute.index,
        get_provider_fees(alg_ddo, sa_compute, consumer_wallet.address, 0),
        consumer_wallet,
    )

    payload = {
        "documentId": alg_ddo.did,
        "serviceId": sa_compute.id,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{alg_ddo.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        sa_compute.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 400, f"{response.data}"
    assert (
        response.json["error"]
        == f"Provider Ganache: Error: Access to asset {alg_ddo.did} was denied with code: ConsumableCodes.CREDENTIAL_IN_DENY_LIST."
    )

    # Use case 2: Consume an algorithm asset by an address which is not in the allowed list

    algo_credentials = {
        "allow": [{"type": "address", "values": [consumer_wallet.address]}],
        "deny": [],
    }

    ddo, tx_id, alg_ddo, alg_tx_id = build_and_send_ddo_with_compute_service(
        client,
        publisher_wallet,
        deployer_wallet,
        True,
        custom_algo_credentials=algo_credentials,
        c2d_address=free_c2d_env["consumerAddress"],
        valid_until=valid_until,
        c2d_environment=free_c2d_env["id"],
        fee_token_args=(fee_token, to_wei(80)),
    )
    sa_compute = get_first_service_by_type(alg_ddo, ServiceType.ACCESS)
    mint_100_datatokens(
        web3, sa_compute.datatoken_address, deployer_wallet.address, publisher_wallet
    )
    tx_id, _ = start_order(
        web3,
        sa_compute.datatoken_address,
        deployer_wallet.address,
        sa_compute.index,
        get_provider_fees(alg_ddo, sa_compute, deployer_wallet.address, 0),
        deployer_wallet,
    )

    payload = {
        "documentId": alg_ddo.did,
        "serviceId": sa_compute.id,
        "consumerAddress": deployer_wallet.address,
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    nonce = build_nonce(deployer_wallet.address)
    _msg = f"{alg_ddo.did}{nonce}"
    payload["signature"] = sign_message(_msg, deployer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        sa_compute.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 400, f"{response.data}"
    assert (
        response.json["error"]
        == f"Provider Ganache: Error: Access to asset {alg_ddo.did} was denied with code: ConsumableCodes.CREDENTIAL_NOT_IN_ALLOW_LIST."
    )

    # Use case 3: Consume asset by allowed address
    mint_100_datatokens(
        web3, sa_compute.datatoken_address, consumer_wallet.address, publisher_wallet
    )
    tx_id, _ = start_order(
        web3,
        sa_compute.datatoken_address,
        consumer_wallet.address,
        sa_compute.index,
        get_provider_fees(alg_ddo, sa_compute, consumer_wallet.address, 0),
        consumer_wallet,
    )

    payload = {
        "documentId": alg_ddo.did,
        "serviceId": sa_compute.id,
        "consumerAddress": consumer_wallet.address,
        "transferTxId": tx_id,
        "fileIndex": 0,
    }

    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    nonce = build_nonce(consumer_wallet.address)
    _msg = f"{alg_ddo.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        sa_compute.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 200, f"{response.data}"
