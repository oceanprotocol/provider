import hashlib
import json

from artifacts import ERC721Template
from eth_account.signers.local import LocalAccount
from flask.testing import FlaskClient
from ocean_provider.utils.data_nft import Flags, MetadataState, get_data_nft_contract
from ocean_provider.utils.data_nft_factory import get_data_nft_factory_contract
from tests.ddo.ddo_sample1_v4 import json_dict as ddo_sample1_v4
from tests.test_helpers import sign_tx
from web3.main import Web3


def test_encryptDDO_and_decryptDDO(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
):
    # Deploy data_nft
    data_nft_factory = get_data_nft_factory_contract(web3)
    deploy_data_nft_tx = data_nft_factory.functions.deployERC721Contract(
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        "0x0000000000000000000000000000000000000000",
        "",
    ).buildTransaction({"from": publisher_wallet.address})
    deploy_data_nft_tx_signed = sign_tx(web3, deploy_data_nft_tx, publisher_wallet.key)
    deploy_data_nft_tx_id = web3.eth.send_raw_transaction(deploy_data_nft_tx_signed)
    deploy_data_nft_receipt = web3.eth.wait_for_transaction_receipt(
        deploy_data_nft_tx_id
    )
    data_nft_address = (
        data_nft_factory.events.NFTCreated()
        .processReceipt(deploy_data_nft_receipt)[0]
        .args.newTokenAddress
    )

    # Calculate DDO Hash
    ddo = ddo_sample1_v4
    ddo_string = json.dumps(ddo)
    ddo_bytes = ddo_string.encode("utf-8")
    ddo_hash = hashlib.sha256(ddo_bytes).hexdigest()

    # Encrypt DDO
    encryptDDO_response = client.post(
        "/api/v1/services/encryptDDO",
        json={
            "documentId": ddo["id"],
            "document": ddo_string,
            "publisherAddress": publisher_wallet.address,
        },
    )
    encrypted_ddo = encryptDDO_response.data

    assert encrypted_ddo
    assert encryptDDO_response.status_code == 201
    assert encryptDDO_response.get_json() is None

    # Set metadata
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    set_metadata_tx = data_nft_contract.functions.setMetaData(
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        Flags.ENCRYPTED.to_byte(),
        encrypted_ddo,
        ddo_hash,
    ).buildTransaction({"from": publisher_wallet.address})
    set_metadata_tx_signed = sign_tx(web3, set_metadata_tx, publisher_wallet.key)
    set_metadata_tx_id = web3.eth.send_raw_transaction(set_metadata_tx_signed)
    set_metadata_receipt = web3.eth.wait_for_transaction_receipt(set_metadata_tx_id)

    # Create data nft contract without address
    abi = ERC721Template.abi
    data_nft_contract_no_address = web3.eth.contract(abi=abi)
    data_nft_address_2 = (
        data_nft_contract_no_address.events.MetadataCreated()
        .processReceipt(set_metadata_receipt)[0]
        .address
    )
    print(data_nft_address_2)
