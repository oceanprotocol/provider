import copy

from eth_typing.evm import HexAddress


class Service:
    def __init__(
        self,
        datatoken_address: HexAddress,
        service_endpoint,
        service_type,
        index,
        attributes=None,
    ) -> None:
        """Initialize Service instance."""
        self.datatoken_address = (datatoken_address,)
        self.service_endpoint = service_endpoint
        self.type = service_type or ""
        self.index = index
        self.attributes = attributes or {}

    def as_dictionary(self):
        """Return the service as a python dictionary."""
        attributes = {}
        for key, value in self.attributes.items():
            if isinstance(value, object) and hasattr(value, "as_dictionary"):
                value = value.as_dictionary()
            elif isinstance(value, list):
                value = [
                    v.as_dictionary() if hasattr(v, "as_dictionary") else v
                    for v in value
                ]

            attributes[key] = value

        values = {"type": self.type, "attributes": attributes}
        if self.service_endpoint:
            values["serviceEndpoint"] = self.service_endpoint
        if self.index is not None:
            values["index"] = self.index

        return values

    @staticmethod
    def from_json(service_dict):
        """Create a service object from a JSON string."""
        sd = copy.deepcopy(service_dict)
        _datatoken_address = sd.pop("datatokenAddress")
        _service_endpoint = sd.pop("serviceEndpoint", None)
        _type = sd.pop("type", None)
        _index = sd.pop("index", None)
        _attributes = sd.pop("attributes", None)

        return Service(
            _datatoken_address, _service_endpoint, _type, _index, _attributes
        )
