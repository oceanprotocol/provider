#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import hashlib
import json
import logging
from typing import Tuple
from ocean_provider.utils.asset import Asset
import werkzeug

from eth_account.signers.local import LocalAccount
from eth_keys import KeyAPI
from eth_keys.backends import NativeECCBackend
from eth_typing.encoding import HexStr
from ocean_provider.utils.encryption import do_decrypt
from ocean_provider.utils.services import Service
from web3 import Web3
from web3.types import TxParams, TxReceipt

logger = logging.getLogger(__name__)
keys = KeyAPI(NativeECCBackend)


def get_request_data(request):
    try:
        return request.args if request.args else request.json
    except werkzeug.exceptions.BadRequest:
        return {}


def msg_hash(message: str):
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def get_service_files_list(
    service: Service, provider_wallet: LocalAccount, asset: Asset = None
) -> list:
    version = asset.version if asset is not None and asset.version else "4.0.0"
    if asset is None or version == "4.0.0":
        return get_service_files_list_old_structure(service, provider_wallet)

    try:
        files_str = do_decrypt(service.encrypted_files, provider_wallet)
        if not files_str:
            return None

        files_json = json.loads(files_str)

        for key in ["datatokenAddress", "nftAddress", "files"]:
            if key not in files_json:
                raise Exception(f"Key {key} not found in files.")

        if Web3.toChecksumAddress(
            files_json["datatokenAddress"]
        ) != Web3.toChecksumAddress(service.datatoken_address):
            raise Exception(
                f"Mismatch of datatoken. Got {files_json['datatokenAddress']} vs expected {service.datatoken_address}"
            )

        if Web3.toChecksumAddress(files_json["nftAddress"]) != Web3.toChecksumAddress(
            asset.nftAddress
        ):
            raise Exception(
                f"Mismatch of dataNft. Got {files_json['nftAddress']} vs expected {asset.nftAddress}"
            )

        files_list = files_json["files"]
        if not isinstance(files_list, list):
            raise TypeError(f"Expected a files list, got {type(files_list)}.")

        return files_list
    except Exception as e:
        logger.error(f"Error decrypting service files {Service}: {str(e)}")
        return None


def get_service_files_list_old_structure(
    service: Service, provider_wallet: LocalAccount
) -> list:
    try:
        files_str = do_decrypt(service.encrypted_files, provider_wallet)
        if not files_str:
            return None
        logger.debug(f"Got decrypted files str {files_str}")
        files_list = json.loads(files_str)
        if not isinstance(files_list, list):
            raise TypeError(f"Expected a files list, got {type(files_list)}.")

        return files_list
    except Exception as e:
        logger.error(f"Error decrypting service files {Service}: {str(e)}")
        return None


def sign_tx(web3, tx, private_key):
    """
    :param web3: Web3 object instance
    :param tx: transaction
    :param private_key: Private key of the account
    :return: rawTransaction (str)
    """
    account = web3.eth.account.from_key(private_key)
    nonce = web3.eth.get_transaction_count(account.address)
    tx["nonce"] = nonce
    signed_tx = web3.eth.account.sign_transaction(tx, private_key)

    return signed_tx.rawTransaction


def sign_and_send(
    web3: Web3, transaction: TxParams, from_account: LocalAccount
) -> Tuple[HexStr, TxReceipt]:
    """Returns the transaction id and transaction receipt."""
    transaction_signed = sign_tx(web3, transaction, from_account.key)
    transaction_hash = web3.eth.send_raw_transaction(transaction_signed)
    transaction_id = Web3.toHex(transaction_hash)

    return transaction_hash, transaction_id


def sign_send_and_wait_for_receipt(
    web3: Web3, transaction: TxParams, from_account: LocalAccount
) -> Tuple[HexStr, TxReceipt]:
    """Returns the transaction id and transaction receipt."""
    transaction_hash, transaction_id = sign_and_send(web3, transaction, from_account)

    return (transaction_id, web3.eth.wait_for_transaction_receipt(transaction_hash))
