#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import copy
import time
from datetime import datetime
from unittest.mock import patch

import pytest
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.provider_fees import get_provider_fees
from ocean_provider.utils.services import ServiceType
from tests.helpers.constants import ARWEAVE_TRANSACTION_ID
from tests.test_auth import create_token
from tests.test_helpers import (
    get_dataset_ddo_with_multiple_files,
    get_first_service_by_type,
    get_registered_asset,
    mint_100_datatokens,
    start_order,
)


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
        get_provider_fees(asset.did, service, consumer_wallet.address, 0),
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
    nonce = str(datetime.utcnow().timestamp())
    payload["nonce"] = nonce
    payload.pop("signature")
    response = client.get(
        download_endpoint, query_string=payload, headers={"AuthToken": token}
    )
    assert response.status == "200 OK"

    # Consume using url index and signature (with nonce)
    nonce = str(datetime.utcnow().timestamp())
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["nonce"] = nonce
    response = client.get(
        service.service_endpoint + download_endpoint, query_string=payload
    )
    assert response.status_code == 200, f"{response.data}"

    if not userdata and not erc20_enterprise:
        nonce = str(datetime.utcnow().timestamp())
        _msg = f"{asset.did}{nonce}"
        payload["signature"] = sign_message(_msg, consumer_wallet)
        payload["nonce"] = nonce
        payload["transferTxId"] = "0x123"  # some dummy
        response = client.get(download_endpoint, query_string=payload)
        assert response.status_code == 400, f"{response.data}"


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
        get_provider_fees(asset.did, service, consumer_wallet.address, 0),
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
    nonce = str(datetime.utcnow().timestamp())
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
        get_provider_fees(asset.did, service, consumer_wallet.address, 0),
        consumer_wallet,
    )

    nonce = str(datetime.utcnow().timestamp())
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

    nonce = str(datetime.utcnow().timestamp())
    _msg = f"{asset.did}{nonce}"
    payload["signature"] = sign_message(_msg, consumer_wallet)
    payload["fileIndex"] = 1
    payload["nonce"] = nonce
    download_endpoint = BaseURLs.SERVICES_URL + "/download"
    response = client.get(download_endpoint, query_string=payload)
    assert response.status_code == 200, f"{response.data}"

    nonce = str(datetime.utcnow().timestamp())
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
        get_provider_fees(asset.did, service, consumer_wallet.address, 0),
        consumer_wallet,
    )

    nonce = str(datetime.utcnow().timestamp())
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
        get_provider_fees(asset.did, service, consumer_wallet.address, 0),
        consumer_wallet,
    )

    nonce = str(datetime.utcnow().timestamp())
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
                == f"Service with index={service.id} is not an access service."
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
        get_provider_fees(asset.did, service, consumer_wallet.address, 0),
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
    nonce = str(datetime.utcnow().timestamp())
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
