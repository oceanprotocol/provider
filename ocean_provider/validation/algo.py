import json

from ocean_provider.myapp import app
from ocean_provider.serializers import StageAlgoSerializer
from ocean_provider.util import (
    build_stage_dict,
    build_stage_output_dict,
    get_asset_download_urls,
    get_metadata_url,
)
from ocean_provider.utils.basics import get_asset_from_metadatastore
from ocean_utils.agreements.service_types import ServiceTypes


class AlgoValidator:
    def __init__(self, consumer_address, provider_wallet, data):
        """Initializes the validator."""
        self.consumer_address = consumer_address
        self.provider_wallet = provider_wallet
        self.data = data
        self.stages = []

    def validate(self):
        """Validates for input and output contents."""
        if not self.validate_input():
            return False

        if not self.validate_output():
            return False

        self.stages.append(
            build_stage_dict(
                self.validated_input_dict,
                self.validated_algo_dict,
                self.validated_output_dict,
            )
        )

        return True

    def validate_input(self, index=0):
        """Validates input dictionary."""

        main_input = [
            {
                key: self.data[key]
                for key in self.data
                if key in ["documentId", "transferTxId", "serviceId"]
            }
        ]

        additional_inputs = self.data.get("additionalInputs")

        try:
            if additional_inputs and isinstance(additional_inputs, str):
                additional_inputs = json.loads(additional_inputs)
        except json.decoder.JSONDecodeError:
            self.error = "Additional input is invalid or can not be decoded."
            return False

        if not additional_inputs:
            additional_inputs = []

        all_data = main_input + additional_inputs
        algo_data = {
            key: self.data[key] for key in self.data if key.startswith("algorithm")
        }

        self.validated_input_dict = []

        for index, input_item in enumerate(all_data):
            input_item.update(algo_data)
            input_item_validator = InputItemValidator(
                self.consumer_address, self.provider_wallet, input_item, index + 1
            )
            status = input_item_validator.validate()
            if not status:
                self.error = (
                    f"Error in input at index {index}: " if index else ""
                ) + input_item_validator.error
                return False

            self.validated_input_dict.append(input_item_validator.validated_input_dict)

            if index == 0:
                self.asset = input_item_validator.asset

        status = self._build_and_validate_algo(algo_data)
        if not status:
            return False

        return True

    def validate_output(self):
        """Validates output dictionary after stage build."""
        output_def = self.data.get("output", dict())

        try:
            if output_def and isinstance(output_def, str):
                output_def = json.loads(output_def)
        except json.decoder.JSONDecodeError:
            self.error = "Output is invalid or can not be decoded."
            return False

        self.validated_output_dict = build_stage_output_dict(
            output_def, self.asset, self.consumer_address, self.provider_wallet
        )

        return True

    def _build_and_validate_algo(self, algo_data):
        """Returns False if invalid, otherwise sets the validated_algo_dict attribute."""
        algorithm_did = algo_data.get("algorithmDid")

        if algorithm_did and not algo_data.get("algorithmMeta"):
            algo = get_asset_from_metadatastore(get_metadata_url(), algorithm_did)
            try:
                asset_type = algo.metadata["main"]["type"]
            except ValueError:
                asset_type = None

            if asset_type != "algorithm":
                self.error = f"DID {algorithm_did} is not a valid algorithm"
                return False

        algorithm_dict = StageAlgoSerializer(
            self.consumer_address, self.provider_wallet, algo_data
        ).serialize()

        valid, error_msg = validate_formatted_algorithm_dict(
            algorithm_dict, algorithm_did
        )

        if not valid:
            self.error = error_msg
            return False

        self.validated_algo_dict = algorithm_dict

        return True


def validate_formatted_algorithm_dict(algorithm_dict, algorithm_did):
    if algorithm_did and not (
        algorithm_dict.get("url") or algorithm_dict.get("remote")
    ):
        return False, f"cannot get url for the algorithmDid {algorithm_did}"

    if (
        not algorithm_dict.get("url")
        and not algorithm_dict.get("rawcode")
        and not algorithm_dict.get("remote")
    ):
        return (
            False,
            "algorithmMeta must define one of `url` or `rawcode` or `remote`, but all seem missing.",
        )  # noqa

    container = algorithm_dict.get("container", {})
    # Validate `container` data
    if not (
        container.get("entrypoint") and container.get("image") and container.get("tag")
    ):
        return (
            False,
            "algorithm `container` must specify values for all of entrypoint, image and tag.",
        )  # noqa

    return True, ""


class InputItemValidator(AlgoValidator):
    def __init__(self, consumer_address, provider_wallet, data, index):
        """Initializes the input item validator."""
        self.consumer_address = consumer_address
        self.provider_wallet = provider_wallet
        self.data = data
        self.index = index

    def validate(self):
        required_keys = ["documentId", "transferTxId", "serviceId"]

        for req_item in required_keys:
            if not self.data.get(req_item) and not (
                req_item == "serviceId" and self.data.get(req_item) == 0
            ):
                self.error = f"No {req_item} in input item."
                return False

        self.did = self.data.get("documentId")
        try:
            self.asset = get_asset_from_metadatastore(get_metadata_url(), self.did)
        except ValueError:
            self.error = f"Asset for did {self.did} not found."
            return False

        matching_services = [
            s for s in self.asset.services if s.index == int(self.data["serviceId"])
        ]
        if matching_services:
            self.service = matching_services[0]
        else:
            self.error = f"Service index {self.data['serviceId']} not found."
            return False

        if self.service.type not in [
            ServiceTypes.ASSET_ACCESS,
            ServiceTypes.CLOUD_COMPUTE,
        ]:
            self.error = "Services in input can only be access or compute."
            return False

        asset_urls = get_asset_download_urls(
            self.asset, self.provider_wallet, config_file=app.config["CONFIG_FILE"]
        )

        if self.service.type == ServiceTypes.CLOUD_COMPUTE and not asset_urls:
            self.error = "Services in input with compute type must be in the same provider you are calling."
            return False

        if self.service.type != ServiceTypes.CLOUD_COMPUTE and self.index == 0:
            self.error = "Service for main asset must be compute."
            return False

        if asset_urls:
            if not self.validate_algo():
                return False

            self.validated_input_dict = dict(
                {"index": self.index, "id": self.did, "url": asset_urls}
            )
        else:
            self.validated_input_dict = dict(
                {
                    "index": self.index,
                    "id": self.did,
                    "remote": {
                        "txid": self.data.get("transferTxId"),
                        "serviceIndex": self.service.index,
                    },
                }
            )

        return True

    def validate_algo(self):
        """Validates algorithm details that allow the algo dict to be built."""
        algorithm_meta = self.data.get("algorithmMeta")
        algorithm_did = self.data.get("algorithmDid")

        privacy_options = self.service.main.get("privacy", {})

        if self.service is None:
            self.error = f"This DID has no compute service {self.did}."
            return False

        if algorithm_meta and privacy_options.get("allowRawAlgorithm", True) is False:
            self.error = f"cannot run raw algorithm on this did {self.did}."
            return False

        trusted_algorithms = privacy_options.get("trustedAlgorithms", [])

        if (
            algorithm_did
            and trusted_algorithms
            and algorithm_did not in trusted_algorithms
        ):
            self.error = f"cannot run raw algorithm on this did {self.did}."
            return False

        return True
