from copy import deepcopy
from typing import Any, Dict, Optional

from eth_typing.encoding import HexStr
from eth_typing.evm import HexAddress


class ServiceType:
    ACCESS = "access"
    COMPUTE = "compute"


class Service:
    def __init__(
        self,
        index: int,
        service_id: str,
        service_type: ServiceType,
        datatoken_address: HexAddress,
        service_endpoint: str,
        encrypted_files: HexStr,
        timeout: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        compute_dict: Optional[dict] = None,
    ) -> None:
        """Initialize Service instance.
        If service is type "compute", then, compute_dict should be set
        """
        self.index = index
        self.id = service_id
        self.type = service_type
        self.name = name
        self.description = description
        self.datatoken_address = datatoken_address
        self.service_endpoint = service_endpoint
        self.encrypted_files = encrypted_files
        self.timeout = timeout
        self.compute_dict = compute_dict

    @staticmethod
    def from_json(index: int, service_dict: Dict[str, Any]):
        """Create a Service object from a JSON string."""
        sd = deepcopy(service_dict)
        return Service(
            index=index,
            service_id=sd.pop("id"),
            service_type=sd.pop("type"),
            datatoken_address=sd.pop("datatokenAddress"),
            service_endpoint=sd.pop("serviceEndpoint"),
            encrypted_files=sd.pop("files"),
            timeout=sd.pop("timeout"),
            name=sd.pop("name", None),
            description=sd.pop("description", None),
            compute_dict=sd.pop("compute", None),
        )
