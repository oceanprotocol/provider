import hashlib
import json

from ocean_lib.common.agreements.service_factory import ServiceDescriptor
from ocean_lib.common.agreements.service_types import ServiceTypes
from ocean_provider.constants import BaseURLs


def get_access_service_descriptor(address, metadata, diff_provider=False):
    access_service_attributes = {
        "main": {
            "name": "dataAssetAccessServiceAgreement",
            "creator": address,
            "cost": metadata["main"]["cost"],
            "timeout": 3600,
            "datePublished": metadata["main"]["dateCreated"],
        }
    }

    base_provider_url = "some_different_provider" if diff_provider else "localhost:8030"
    url_structure = f"http://{base_provider_url}{BaseURLs.ASSETS_URL}/download"

    return ServiceDescriptor.access_service_descriptor(
        access_service_attributes, url_structure
    )


def get_compute_service_descriptor(address, price, metadata):
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": address,
            "cost": price,
            "timeout": 3600,
            "datePublished": metadata["main"]["dateCreated"],
            "privacy": {
                "allowRawAlgorithm": True,
                "allowAllPublishedAlgorithms": True,
                "publisherTrustedAlgorithms": [],
                "allowNetworkAccess": False,
            },
        }
    }

    return ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
    )


def get_compute_service_descriptor_no_rawalgo(address, price, metadata):
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": address,
            "cost": price,
            "privacy": {
                "allowRawAlgorithm": False,
                "allowAllPublishedAlgorithms": False,
                "publisherTrustedAlgorithms": [],
                "allowNetworkAccess": True,
            },
            "timeout": 3600,
            "datePublished": metadata["main"]["dateCreated"],
        }
    }

    return ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
    )


def get_compute_service_descriptor_specific_algo_dids(address, price, metadata, algos):
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": address,
            "cost": price,
            "privacy": {
                "allowRawAlgorithm": False,
                "allowAllPublishedAlgorithms": False,
                "publisherTrustedAlgorithms": [],
                "allowNetworkAccess": True,
            },
            "timeout": 3600,
            "datePublished": metadata["main"]["dateCreated"],
        }
    }

    for algo in algos:
        service = algo.get_service(ServiceTypes.METADATA)
        compute_service_attributes["main"]["privacy"][
            "publisherTrustedAlgorithms"
        ].append(
            {
                "did": algo.did,
                "filesChecksum": hashlib.sha256(
                    (
                        service.attributes["encryptedFiles"]
                        + json.dumps(service.main["files"], separators=(",", ":"))
                    ).encode("utf-8")
                ).hexdigest(),
                "containerSectionChecksum": hashlib.sha256(
                    (
                        json.dumps(
                            service.main["algorithm"]["container"],
                            separators=(",", ":"),
                        )
                    ).encode("utf-8")
                ).hexdigest(),
            }
        )

    return ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
    )


def get_compute_service_descriptor_allow_all_published(address, price, metadata):
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": address,
            "cost": price,
            "privacy": {
                "allowRawAlgorithm": False,
                "allowNetworkAccess": True,
                "allowAllPublishedAlgorithms": True,
                "publisherTrustedAlgorithms": [],
            },
            "timeout": 3600,
            "datePublished": metadata["main"]["dateCreated"],
        }
    }

    return ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
    )
