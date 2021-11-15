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
        files: HexStr,
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
        self.files = files
        self.timeout = timeout
        self.compute_dict = compute_dict

    @staticmethod
    def from_json(index: int, service_dict: Dict[str, Any]):
        """Create a Service object from a JSON string."""
        sd = deepcopy(service_dict)
        return Service(
            index,
            sd.pop("id"),
            sd.pop("type"),
            sd.pop("datatokenAddress"),
            sd.pop("serviceEndpoint"),
            sd.pop("files"),
            sd.pop("timeout"),
            sd.pop("name", None),
            sd.pop("description", None),
            sd.pop("compute", None),
        )
