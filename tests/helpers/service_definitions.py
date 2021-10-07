import hashlib
import json

from ocean_provider.constants import BaseURLs
from ocean_provider.utils.services import Service


def get_access_service(address, metadata, diff_provider=False):
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

    return Service(
        service_endpoint=url_structure,
        service_type="access",
        index=3,
        attributes=access_service_attributes,
    )


def get_compute_service(address, price, metadata):
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

    return Service(
        service_endpoint=f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
        service_type="compute",
        index=4,
        attributes=compute_service_attributes,
    )


def get_compute_service_no_rawalgo(address, price, metadata):
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

    return Service(
        service_endpoint=f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
        service_type="compute",
        index=4,
        attributes=compute_service_attributes,
    )


def get_compute_service_specific_algo_dids(address, price, metadata, algos):
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
        service = algo.get_service("metadata")
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

    return Service(
        service_endpoint=f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
        service_type="compute",
        index=4,
        attributes=compute_service_attributes,
    )


def get_compute_service_specific_algo_publishers(address, price, metadata, publishers):
    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": address,
            "cost": price,
            "privacy": {
                "allowRawAlgorithm": False,
                "allowAllPublishedAlgorithms": False,
                "publisherTrustedAlgorithms": [],
                "publisherTrustedAlgorithmPublishers": publishers,
                "allowNetworkAccess": True,
            },
            "timeout": 3600,
            "datePublished": metadata["main"]["dateCreated"],
        }
    }

    return Service(
        service_endpoint=f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
        service_type="compute",
        index=4,
        attributes=compute_service_attributes,
    )


def get_compute_service_allow_all_published(address, price, metadata):
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

    return Service(
        service_endpoint=f"http://localhost:8030{BaseURLs.ASSETS_URL}/compute",
        service_type="compute",
        index=4,
        attributes=compute_service_attributes,
    )
