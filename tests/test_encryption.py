import hashlib
import json
import lzma

from eth_account.signers.local import LocalAccount
from eth_typing.encoding import HexStr
from eth_typing.evm import HexAddress
from flask.testing import FlaskClient
from ocean_provider.constants import BaseURLs
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.data_nft import Flags, MetadataState
from tests.ddo.ddo_sample1_v4 import json_dict as ddo_sample1_v4
from tests.test_helpers import (
    BLACK_HOLE_ADDRESS,
    deploy_data_nft,
    get_nonce,
    set_metadata,
)
from web3.main import Web3


def test_decrypt_with_plain_input(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
    consumer_wallet: LocalAccount,
):
    """
    Test the decrypt endpoint using plain (unencrypted, uncompressed) input data
    """
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        BLACK_HOLE_ADDRESS,
        "",
        publisher_wallet,
    )

    # Calculate DDO Hash
    ddo = ddo_sample1_v4
    ddo_string = json.dumps(ddo)
    ddo_bytes = ddo_string.encode("utf-8")
    ddo_bytes_hexstr = Web3.toHex(ddo_bytes)
    ddo_hash_hexstr = Web3.toHex(hashlib.sha256(ddo_bytes).digest())

    set_metadata_tx_id, _ = set_metadata(
        web3,
        data_nft_address,
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        Flags.PLAIN.to_byte(),
        ddo_bytes_hexstr,
        ddo_hash_hexstr,
        publisher_wallet,
    )

    # Set common decrypt arguments
    chain_id = 1337

    # Decrypt DDO using transactionId
    decrypt_response = decrypt_ddo_using_transaction_id(
        client, consumer_wallet, set_metadata_tx_id, chain_id
    )
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypt_response.data.decode("utf-8") == ddo_string
    assert decrypt_response.get_json() is None

    # Decrypt DDO using dataNftAddress, encryptedDocument, flags, and documentHash
    decrypt_response = decrypt_ddo_using_decrypt_args(
        client,
        consumer_wallet,
        data_nft_address,
        chain_id,
        ddo_bytes_hexstr,
        0,
        ddo_hash_hexstr,
    )
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypt_response.data.decode("utf-8") == ddo_string
    assert decrypt_response.get_json() is None


def test_decrypt_with_compressed_input(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
    consumer_wallet: LocalAccount,
):
    """
    Test the decrypt endpoint with input data that is compressed but not
    encrypted.
    """
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        BLACK_HOLE_ADDRESS,
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
    ddo_compressed_hexstr = Web3.toHex(ddo_compressed)

    set_metadata_tx_id, _ = set_metadata(
        web3,
        data_nft_address,
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        Flags.COMPRESSED.to_byte(),
        ddo_compressed_hexstr,
        ddo_hash_hexstr,
        publisher_wallet,
    )

    # Set common decrypt arguments
    chain_id = 1337

    # Decrypt DDO using transactionId
    decrypt_response = decrypt_ddo_using_transaction_id(
        client, consumer_wallet, set_metadata_tx_id, chain_id
    )
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypt_response.data.decode("utf-8") == ddo_string
    assert decrypt_response.get_json() is None

    # Decrypt DDO using dataNftAddress, encryptedDocument, flags, and documentHash
    decrypt_response = decrypt_ddo_using_decrypt_args(
        client,
        consumer_wallet,
        data_nft_address,
        chain_id,
        ddo_compressed_hexstr,
        Flags.COMPRESSED,
        ddo_hash_hexstr,
    )
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypt_response.data.decode("utf-8") == ddo_string
    assert decrypt_response.get_json() is None


def test_encrypt_and_decrypt_with_only_encryption(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
    consumer_wallet: LocalAccount,
):
    """
    Test the encrypt and decrypt endpoints. Send the decrypt endpoint data that
    is only encrypted, not compressed.
    """
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        BLACK_HOLE_ADDRESS,
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
        BaseURLs.SERVICES_URL + "/encrypt",
        data=ddo_string,
        content_type="application/octet-stream",
    )
    # Interpret response.data as utf-8 encoded HexStr
    encrypted_ddo = encrypt_response.data.decode("utf-8")
    assert encrypted_ddo.startswith("0x")
    assert encrypt_response.status_code == 201
    assert encrypt_response.content_type == "text/plain"
    assert encrypted_ddo
    assert encrypt_response.get_json() is None

    set_metadata_tx_id, _ = set_metadata(
        web3,
        data_nft_address,
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        Flags.ENCRYPTED.to_byte(),
        encrypted_ddo,
        ddo_hash_hexstr,
        publisher_wallet,
    )

    # Set common decrypt arguments
    chain_id = 1337

    # Decrypt DDO using transactionId
    decrypt_response = decrypt_ddo_using_transaction_id(
        client, consumer_wallet, set_metadata_tx_id, chain_id
    )
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypt_response.data.decode("utf-8") == ddo_string
    assert decrypt_response.get_json() is None

    # Decrypt DDO using dataNftAddress, encryptedDocument, flags, and documentHash
    decrypt_response = decrypt_ddo_using_decrypt_args(
        client,
        consumer_wallet,
        data_nft_address,
        chain_id,
        encrypted_ddo,
        Flags.ENCRYPTED,
        ddo_hash_hexstr,
    )
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypt_response.data.decode("utf-8") == ddo_string
    assert decrypt_response.get_json() is None


def test_encrypt_and_decrypt_with_compression_and_encryption(
    client: FlaskClient,
    web3: Web3,
    publisher_wallet: LocalAccount,
    provider_wallet: LocalAccount,
    consumer_wallet: LocalAccount,
):
    """
    Test the encrypt and decrypt endpoints. Send the decrypt endpoint data that
    is compressed and encrypted.
    """
    data_nft_address = deploy_data_nft(
        web3,
        "Data NFT Name",
        "DATANFTSYMBOL",
        1,
        BLACK_HOLE_ADDRESS,
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
        BaseURLs.SERVICES_URL + "/encrypt",
        data=ddo_compressed,
        content_type="application/octet-stream",
    )
    encrypted_ddo = encrypt_response.data.decode("utf-8")
    assert encrypted_ddo.startswith("0x")
    assert encrypt_response.status_code == 201
    assert encrypt_response.content_type == "text/plain"
    assert encrypted_ddo
    assert encrypt_response.get_json() is None

    set_metadata_tx_id, _ = set_metadata(
        web3,
        data_nft_address,
        MetadataState.ACTIVE,
        "http://localhost:8030",
        provider_wallet.address,
        (Flags.ENCRYPTED | Flags.COMPRESSED).to_byte(),
        encrypted_ddo,
        ddo_hash_hexstr,
        publisher_wallet,
    )

    # Set common decrypt arguments
    chain_id = 1337

    # Decrypt DDO using transactionId
    decrypt_response = decrypt_ddo_using_transaction_id(
        client, consumer_wallet, set_metadata_tx_id, chain_id
    )
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypt_response.data.decode("utf-8") == ddo_string
    assert decrypt_response.get_json() is None

    # Decrypt DDO using dataNftAddress, encryptedDocument, flags, and documentHash
    decrypt_response = decrypt_ddo_using_decrypt_args(
        client,
        consumer_wallet,
        data_nft_address,
        chain_id,
        encrypted_ddo,
        Flags.ENCRYPTED | Flags.COMPRESSED,
        ddo_hash_hexstr,
    )
    assert decrypt_response.status_code == 201
    assert decrypt_response.content_type == "text/plain"
    assert decrypt_response.data.decode("utf-8") == ddo_string
    assert decrypt_response.get_json() is None


def decrypt_ddo_using_transaction_id(
    client: FlaskClient,
    decrypter_wallet: LocalAccount,
    set_metadata_tx_id: HexStr,
    chain_id: int,
):
    previous_nonce = int(get_nonce(client, decrypter_wallet.address))
    nonce = previous_nonce + 1
    message_to_be_signed = (
        f"{set_metadata_tx_id}{decrypter_wallet.address}{chain_id}{nonce}"
    )
    signature = sign_message(message_to_be_signed, decrypter_wallet)
    return client.post(
        BaseURLs.SERVICES_URL + "/decrypt",
        json={
            "decrypterAddress": decrypter_wallet.address,
            "chainId": chain_id,
            "transactionId": set_metadata_tx_id,
            "nonce": nonce,
            "signature": signature,
        },
    )


def decrypt_ddo_using_decrypt_args(
    client: FlaskClient,
    decrypter_wallet: LocalAccount,
    data_nft_address: HexAddress,
    chain_id: int,
    encrypted_ddo: HexStr,
    flags: int,
    ddo_hash_hexstr: HexStr,
):
    nonce = get_next_nonce(client, decrypter_wallet)
    message_to_be_signed = (
        f"{data_nft_address}{decrypter_wallet.address}{chain_id}{nonce}"
    )
    signature = sign_message(message_to_be_signed, decrypter_wallet)
    return client.post(
        BaseURLs.SERVICES_URL + "/decrypt",
        json={
            "decrypterAddress": decrypter_wallet.address,
            "chainId": chain_id,
            "dataNftAddress": data_nft_address,
            "encryptedDocument": encrypted_ddo,
            "flags": flags,
            "documentHash": ddo_hash_hexstr,
            "nonce": nonce,
            "signature": signature,
        },
    )


def get_next_nonce(client, wallet):
    previous_nonce = int(get_nonce(client, wallet.address))
    return previous_nonce + 1
