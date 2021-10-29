import hashlib
import json
import lzma

from eth_account.signers.local import LocalAccount
from eth_typing.evm import HexAddress
from flask.testing import FlaskClient
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.data_nft import Flags, MetadataState, get_data_nft_contract
from ocean_provider.utils.data_nft_factory import get_data_nft_factory_contract
from tests.ddo.ddo_sample1_v4 import json_dict as ddo_sample1_v4
from tests.test_helpers import get_nonce, sign_tx
from web3.main import Web3


def test_encrypt_and_decrypt_unencrypted(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
    consumer_wallet: LocalAccount,
):
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        "0x0000000000000000000000000000000000000000",
        "",
        publisher_wallet,
    )

    # Calculate DDO Hash
    ddo = ddo_sample1_v4
    ddo_string = json.dumps(ddo)
    ddo_bytes = ddo_string.encode("utf-8")
    ddo_hash_hexstr = Web3.toHex(hashlib.sha256(ddo_bytes).digest())

    # Set metadata
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    set_metadata_tx = data_nft_contract.functions.setMetaData(
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        Flags.PLAIN.to_byte(),
        ddo_bytes,
        ddo_hash_hexstr,
    ).buildTransaction({"from": publisher_wallet.address})
    set_metadata_tx_signed = sign_tx(web3, set_metadata_tx, publisher_wallet.key)
    set_metadata_tx_hash = web3.eth.send_raw_transaction(set_metadata_tx_signed)

    # Set common decrypt arguments
    decrypter_address = consumer_wallet.address
    chain_id = 1337

    # Decrypt DDO using transactionId
    set_metadata_tx_id = Web3.toHex(set_metadata_tx_hash)
    previous_nonce = int(get_nonce(client, consumer_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = f"{set_metadata_tx_id}{decrypter_address}{chain_id}{nonce}"
    signature = sign_message(message_to_be_signed, consumer_wallet)
    decrypt_response = client.post(
        "/api/v1/services/decrypt",
        json={
            "decrypterAddress": consumer_wallet.address,
            "chainId": chain_id,
            "transactionId": set_metadata_tx_id,
            "nonce": nonce,
            "signature": signature,
        },
    )
    decrypted_ddo = decrypt_response.data.decode("utf-8")
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypted_ddo == ddo_string
    assert decrypt_response.get_json() is None

    # Decrypt DDO using dataNftAddress, encryptedDocument, flags, and documentHash
    previous_nonce = int(get_nonce(client, consumer_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = f"{data_nft_address}{decrypter_address}{chain_id}{nonce}"
    signature = sign_message(message_to_be_signed, consumer_wallet)
    decrypt_response = client.post(
        "/api/v1/services/decrypt",
        json={
            "decrypterAddress": consumer_wallet.address,
            "chainId": chain_id,
            "dataNftAddress": data_nft_address,
            "encryptedDocument": Web3.toHex(ddo_bytes),
            "flags": Flags.PLAIN,  # Can't pass bytes in JSON so pass as int
            "documentHash": ddo_hash_hexstr,
            "nonce": nonce,
            "signature": signature,
        },
    )
    decrypted_ddo = decrypt_response.data.decode("utf-8")
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypted_ddo == ddo_string
    assert decrypt_response.get_json() is None


def test_encrypt_and_decrypt_with_only_encryption(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
    consumer_wallet: LocalAccount,
):
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        "0x0000000000000000000000000000000000000000",
        "",
        publisher_wallet,
    )

    # Calculate DDO Hash
    ddo = ddo_sample1_v4
    ddo_string = json.dumps(ddo)
    ddo_bytes = ddo_string.encode("utf-8")
    ddo_hash_hexstr = Web3.toHex(hashlib.sha256(ddo_bytes).digest())

    # Encrypt DDO
    encrypt_response = client.post(
        "/api/v1/services/encrypt",
        data=ddo_string,
        content_type="application/octet-stream",
    )
    # Interpret response.data as utf-8 encoded HexStr
    encrypted_ddo_hexstr = encrypt_response.data.decode("utf-8")
    assert encrypted_ddo_hexstr.startswith("0x")
    assert encrypt_response.status_code == 201
    assert encrypt_response.content_type == "text/plain"
    assert encrypt_response.data
    assert encrypt_response.get_json() is None

    # Set metadata
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    set_metadata_tx = data_nft_contract.functions.setMetaData(
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        Flags.ENCRYPTED.to_byte(),
        encrypted_ddo_hexstr,
        ddo_hash_hexstr,
    ).buildTransaction({"from": publisher_wallet.address})
    set_metadata_tx_signed = sign_tx(web3, set_metadata_tx, publisher_wallet.key)
    set_metadata_tx_hash = web3.eth.send_raw_transaction(set_metadata_tx_signed)

    # Set common decrypt arguments
    decrypter_address = consumer_wallet.address
    chain_id = 1337

    # Decrypt DDO using transactionId
    set_metadata_tx_id = Web3.toHex(set_metadata_tx_hash)
    previous_nonce = int(get_nonce(client, consumer_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = f"{set_metadata_tx_id}{decrypter_address}{chain_id}{nonce}"
    signature = sign_message(message_to_be_signed, consumer_wallet)
    decrypt_response = client.post(
        "/api/v1/services/decrypt",
        json={
            "decrypterAddress": consumer_wallet.address,
            "chainId": chain_id,
            "transactionId": set_metadata_tx_id,
            "nonce": nonce,
            "signature": signature,
        },
    )
    decrypted_ddo = decrypt_response.data.decode("utf-8")
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypted_ddo == ddo_string
    assert decrypt_response.get_json() is None

    # Decrypt DDO using dataNftAddress, encryptedDocument, flags, and documentHash
    previous_nonce = int(get_nonce(client, consumer_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = f"{data_nft_address}{decrypter_address}{chain_id}{nonce}"
    signature = sign_message(message_to_be_signed, consumer_wallet)
    decrypt_response = client.post(
        "/api/v1/services/decrypt",
        json={
            "decrypterAddress": consumer_wallet.address,
            "chainId": chain_id,
            "dataNftAddress": data_nft_address,
            "encryptedDocument": encrypted_ddo_hexstr,
            "flags": Flags.ENCRYPTED,  # Can't pass bytes in JSON so pass as int
            "documentHash": ddo_hash_hexstr,
            "nonce": nonce,
            "signature": signature,
        },
    )
    decrypted_ddo = decrypt_response.data.decode("utf-8")
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypted_ddo == ddo_string
    assert decrypt_response.get_json() is None


def test_encrypt_and_decrypt_with_compression_and_encryption(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
    consumer_wallet: LocalAccount,
):
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        "0x0000000000000000000000000000000000000000",
        "",
        publisher_wallet,
    )

    # Calculate DDO Hash
    ddo = ddo_sample1_v4
    ddo_string = json.dumps(ddo)
    ddo_bytes = ddo_string.encode("utf-8")
    ddo_hash_hexstr = Web3.toHex(hashlib.sha256(ddo_bytes).digest())

    # Compress DDO
    ddo_compressed = lzma.compress(ddo_bytes)

    # Encrypt DDO
    encrypt_response = client.post(
        "/api/v1/services/encrypt",
        data=ddo_compressed,
        content_type="application/octet-stream",
    )
    encrypted_ddo = encrypt_response.data.decode("utf-8")
    assert encrypt_response.status_code == 201
    assert encrypt_response.content_type == "text/plain"
    assert encrypted_ddo
    assert encrypt_response.get_json() is None

    # Set metadata
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    set_metadata_tx = data_nft_contract.functions.setMetaData(
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        (Flags.ENCRYPTED | Flags.COMPRESSED).to_byte(),
        encrypted_ddo,
        ddo_hash_hexstr,
    ).buildTransaction({"from": publisher_wallet.address})
    set_metadata_tx_signed = sign_tx(web3, set_metadata_tx, publisher_wallet.key)
    set_metadata_tx_hash = web3.eth.send_raw_transaction(set_metadata_tx_signed)

    # Set common decrypt arguments
    decrypter_address = consumer_wallet.address
    chain_id = 1337

    # Decrypt DDO using transactionId
    set_metadata_tx_id = Web3.toHex(set_metadata_tx_hash)
    previous_nonce = int(get_nonce(client, consumer_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = f"{set_metadata_tx_id}{decrypter_address}{chain_id}{nonce}"
    signature = sign_message(message_to_be_signed, consumer_wallet)
    decrypt_response = client.post(
        "/api/v1/services/decrypt",
        json={
            "decrypterAddress": consumer_wallet.address,
            "chainId": chain_id,
            "transactionId": set_metadata_tx_id,
            "nonce": nonce,
            "signature": signature,
        },
    )
    decrypted_ddo = decrypt_response.data.decode("utf-8")
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypted_ddo == ddo_string
    assert decrypt_response.get_json() is None

    # Decrypt DDO using dataNftAddress, encryptedDocument, flags, and documentHash
    previous_nonce = int(get_nonce(client, consumer_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = f"{data_nft_address}{decrypter_address}{chain_id}{nonce}"
    signature = sign_message(message_to_be_signed, consumer_wallet)
    decrypt_response = client.post(
        "/api/v1/services/decrypt",
        json={
            "decrypterAddress": consumer_wallet.address,
            "chainId": chain_id,
            "dataNftAddress": data_nft_address,
            "encryptedDocument": encrypted_ddo,
            "flags": Flags.ENCRYPTED | Flags.COMPRESSED,
            "documentHash": ddo_hash_hexstr,
            "nonce": nonce,
            "signature": signature,
        },
    )
    decrypted_ddo = decrypt_response.data.decode("utf-8")
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypted_ddo == ddo_string
    assert decrypt_response.get_json() is None


def test_encrypt_and_decrypt_with_only_compression(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
    consumer_wallet: LocalAccount,
):
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        "0x0000000000000000000000000000000000000000",
        "",
        publisher_wallet,
    )

    # Calculate DDO Hash
    ddo = ddo_sample1_v4
    ddo_string = json.dumps(ddo)
    ddo_bytes = ddo_string.encode("utf-8")
    ddo_hash_hexstr = Web3.toHex(hashlib.sha256(ddo_bytes).digest())

    # Compress DDO
    ddo_compressed = lzma.compress(ddo_bytes)

    # Set metadata
    data_nft_contract = get_data_nft_contract(web3, data_nft_address)
    set_metadata_tx = data_nft_contract.functions.setMetaData(
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        Flags.COMPRESSED.to_byte(),
        ddo_compressed,
        ddo_hash_hexstr,
    ).buildTransaction({"from": publisher_wallet.address})
    set_metadata_tx_signed = sign_tx(web3, set_metadata_tx, publisher_wallet.key)
    set_metadata_tx_hash = web3.eth.send_raw_transaction(set_metadata_tx_signed)

    # Set common decrypt arguments
    decrypter_address = consumer_wallet.address
    chain_id = 1337

    # Decrypt DDO using transactionId
    set_metadata_tx_id = Web3.toHex(set_metadata_tx_hash)
    previous_nonce = int(get_nonce(client, consumer_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = f"{set_metadata_tx_id}{decrypter_address}{chain_id}{nonce}"
    signature = sign_message(message_to_be_signed, consumer_wallet)
    decrypt_response = client.post(
        "/api/v1/services/decrypt",
        json={
            "decrypterAddress": consumer_wallet.address,
            "chainId": chain_id,
            "transactionId": set_metadata_tx_id,
            "nonce": nonce,
            "signature": signature,
        },
    )
    decrypted_ddo = decrypt_response.data.decode("utf-8")
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypted_ddo == ddo_string
    assert decrypt_response.get_json() is None

    # Decrypt DDO using dataNftAddress, encryptedDocument, flags, and documentHash
    previous_nonce = int(get_nonce(client, consumer_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = f"{data_nft_address}{decrypter_address}{chain_id}{nonce}"
    signature = sign_message(message_to_be_signed, consumer_wallet)
    decrypt_response = client.post(
        "/api/v1/services/decrypt",
        json={
            "decrypterAddress": consumer_wallet.address,
            "chainId": chain_id,
            "dataNftAddress": data_nft_address,
            "encryptedDocument": Web3.toHex(ddo_compressed),
            "flags": Flags.COMPRESSED,
            "documentHash": ddo_hash_hexstr,
            "nonce": nonce,
            "signature": signature,
        },
    )
    decrypted_ddo = decrypt_response.data.decode("utf-8")
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypted_ddo == ddo_string
    assert decrypt_response.get_json() is None


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
