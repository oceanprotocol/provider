import copy


class Service:
    def __init__(
        self,
        service_endpoint,
        service_type,
        index,
        attributes=None,
    ) -> None:
        """Initialize Service instance."""
        self.service_endpoint = service_endpoint
        self.type = service_type or ""
        self.index = index
        self.attributes = attributes or {}

    @property
    def main(self):
        return self.attributes["main"]

    def get_cost(self) -> float:
        return float(self.main["cost"])

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
        _service_endpoint = sd.pop("serviceEndpoint", None)
        _type = sd.pop("type", None)
        _index = sd.pop("index", None)
        _attributes = sd.pop("attributes", None)

        return Service(_service_endpoint, _type, _index, _attributes)
