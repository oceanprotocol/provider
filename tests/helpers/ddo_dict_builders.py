#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import uuid
from datetime import datetime
from typing import Any, Dict

from eth_typing.encoding import HexStr
from eth_typing.evm import HexAddress
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.utils.encryption import do_encrypt
from web3.main import Web3

"""Test helpers for building service dicts to be used in DDOs"""


def build_ddo_dict(
    did: str,
    nft_address: str,
    chain_id: int,
    metadata: Dict[str, Any],
    services: Dict[str, Any],
    credentials: Dict[str, Any],
) -> dict:
    """Build a ddo dict, used for testing. See for details:
    https://github.com/oceanprotocol/docs/blob/v4main/content/concepts/did-ddo.md#ddo
    """
    return {
        "@context": ["https://w3id.org/did/v1"],
        "id": did,
        "version": "4.1.0",
        "nftAddress": nft_address,
        "chainId": chain_id,
        "metadata": metadata,
        "services": services,
        "credentials": credentials,
    }


def get_current_iso_timestamp() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat()


def _build_service_dict_untyped(
    datatoken_address: HexAddress,
    service_endpoint: str,
    encrypted_files: HexStr,
    timeout: int,
) -> dict:
    """Build a service dict with required attributes only. See for details:
    https://github.com/oceanprotocol/docs/blob/v4main/content/concepts/did-ddo.md#services
    """
    return {
        "id": str(uuid.uuid4()),
        "name": "name doesn't affect tests",
        "description": "decription doesn't affect tests",
        "datatokenAddress": datatoken_address,
        "serviceEndpoint": service_endpoint,
        "files": encrypted_files,
        "timeout": timeout,
    }


def build_service_dict_type_access(
    datatoken_address: HexAddress,
    service_endpoint: str,
    encrypted_files: HexStr,
    timeout: int = 3600,  # 1 hour
) -> dict:
    """Build an access service dict, used for testing"""
    access_service = _build_service_dict_untyped(
        datatoken_address, service_endpoint, encrypted_files, timeout
    )
    access_service["type"] = "access"
    return access_service


def _build_untyped_metadata_dict() -> dict:
    """Build an untyped metadata dict, used for testing"""
    return {
        "created": f"{get_current_iso_timestamp()}",
        "updated": f"{get_current_iso_timestamp()}",
        "description": "Asset description",
        "copyrightHolder": "Asset copyright holder",
        "name": "Asset name",
        "author": "Asset Author",
        "license": "CC-0",
        "links": ["https://google.com"],
        "contentLanguage": "en-US",
        "categories": ["category 1"],
        "tags": ["tag 1"],
        "additionalInformation": {},
    }


def build_metadata_dict_type_dataset() -> dict:
    """Build metadata dict of type "dataset", used for testing."""
    dataset_metadata = _build_untyped_metadata_dict()
    dataset_metadata["type"] = "dataset"
    return dataset_metadata


def build_metadata_dict_type_algorithm() -> dict:
    """Build metadata dict of type "algorithm", used for testing."""
    algorithm_metadata = _build_untyped_metadata_dict()
    algorithm_metadata["type"] = "algorithm"
    algorithm_metadata["algorithm"] = build_algorithm_dict()
    return algorithm_metadata


def build_algorithm_dict() -> dict:
    """Build an algorithm dict, used for testing."""
    return {
        "language": "python",
        "version": "4.1.0",
        "container": build_container_dict(),
    }


def build_container_dict() -> dict:
    """Build a container dict, used for testing"""
    return {
        "entrypoint": "run.sh",
        "image": "my-docker-image",
        "tag": "latest",
        "checksum": "44e10daa6637893f4276bb8d7301eb35306ece50f61ca34dcab550",
    }


def build_credentials_dict() -> dict:
    """Build a credentials dict, used for testing."""
    return {"allow": [], "deny": []}


def get_compute_service(
    address,
    price,
    datatoken_address,
    trusted_algos=None,
    trusted_publishers=None,
    timeout=3600,
):
    trusted_algos = [] if not trusted_algos else trusted_algos
    trusted_publishers = [] if not trusted_publishers else trusted_publishers
    compute_service_attributes = {
        "namespace": "test",
        "allowRawAlgorithm": True,
        "allowNetworkAccess": False,
        "publisherTrustedAlgorithmPublishers": trusted_publishers,
        "publisherTrustedAlgorithms": trusted_algos,
    }

    unencrypted_files_list = {
        "datatokenAddress": datatoken_address,
        "type": "compute",
        "files": [
            {
                "type": "url",
                "method": "GET",
                "url": "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt",
            }
        ],
    }

    encrypted_files_str = json.dumps(unencrypted_files_list, separators=(",", ":"))
    encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), get_provider_wallet()
    )

    return {
        "id": "compute_1",
        "type": "compute",
        "name": "compute_1",
        "description": "compute_1",
        "datatokenAddress": datatoken_address,
        "timeout": timeout,
        "serviceEndpoint": "http://172.15.0.4:8030/",
        "files": encrypted_files,
        "compute": compute_service_attributes,
    }


def get_compute_service_no_rawalgo(address, price, datatoken_address, timeout=3600):
    compute_service_attributes = {
        "namespace": "test",
        "allowRawAlgorithm": False,
        "allowNetworkAccess": False,
        "publisherTrustedAlgorithmPublishers": [],
        "publisherTrustedAlgorithms": [],
    }

    unencrypted_files_list = {
        "datatokenAddress": datatoken_address,
        "type": "compute",
        "files": [
            {
                "type": "url",
                "method": "GET",
                "url": "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt",
            }
        ],
    }

    encrypted_files_str = json.dumps(unencrypted_files_list, separators=(",", ":"))
    encrypted_files = do_encrypt(
        Web3.toHex(text=encrypted_files_str), get_provider_wallet()
    )

    return {
        "id": "compute_1",
        "type": "compute",
        "name": "compute_1",
        "description": "compute_1",
        "datatokenAddress": datatoken_address,
        "timeout": timeout,
        "serviceEndpoint": "http://172.15.0.4:8030/",
        "files": encrypted_files,
        "compute": compute_service_attributes,
    }
