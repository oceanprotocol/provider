#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
from eth_utils import add_0x_prefix
from ocean_provider.myapp import app
from ocean_provider.serializers import StageAlgoSerializer
from ocean_provider.util import (
    build_stage_output_dict,
    decode_from_data,
    filter_dictionary,
    filter_dictionary_starts_with,
    get_asset_download_urls,
    get_metadata_url,
    get_service_at_index,
    record_consume_request,
    validate_order,
    validate_transfer_not_used_for_other_service,
)
from ocean_provider.utils.basics import get_asset_from_metadatastore
from ocean_utils.agreements.service_agreement import ServiceAgreement
from ocean_utils.agreements.service_types import ServiceTypes
from ocean_utils.did import did_to_id


class WorkflowValidator:
    def __init__(self, consumer_address, provider_wallet, data):
        """Initializes the validator."""
        self.consumer_address = consumer_address
        self.provider_wallet = provider_wallet
        self.data = data
        self.workflow = dict({"stages": []})

    def validate(self):
        """Validates for input and output contents."""
        if not self.validate_input():
            return False

        if not self.validate_output():
            return False

        self.workflow["stages"].append(
            {
                "index": 0,
                "input": self.validated_inputs,
                "compute": {
                    "Instances": 1,
                    "namespace": "ocean-compute",
                    "maxtime": 3600,
                },
                "algorithm": self.validated_algo_dict,
                "output": self.validated_output_dict,
            }
        )

        return True

    def validate_input(self, index=0):
        """Validates input dictionary."""
        main_input = [
            filter_dictionary(self.data, ["documentId", "transferTxId", "serviceId"])
        ]
        additional_inputs = decode_from_data(self.data, "additionalInputs")

        if additional_inputs == -1:
            self.error = "Additional input is invalid or can not be decoded."
            return False

        all_data = main_input + additional_inputs
        algo_data = filter_dictionary_starts_with(self.data, "algorithm")

        self.validated_inputs = []

        for index, input_item in enumerate(all_data):
            input_item.update(algo_data)
            input_item_validator = InputItemValidator(
                self.consumer_address, self.provider_wallet, input_item, index
            )

            status = input_item_validator.validate()
            if not status:
                prefix = f"Error in input at index {index}: " if index else ""
                self.error = prefix + input_item_validator.error
                return False

            self.validated_inputs.append(input_item_validator.validated_inputs)

            if index == 0:
                self.service_endpoint = input_item_validator.service.service_endpoint

        status = self._build_and_validate_algo(algo_data)
        if not status:
            return False

        return True

    def validate_output(self):
        """Validates output dictionary after stage build."""
        output_def = decode_from_data(self.data, "output", dec_type="dict")

        if output_def == -1:
            self.error = "Output is invalid or can not be decoded."
            return False

        self.validated_output_dict = build_stage_output_dict(
            output_def,
            self.service_endpoint,
            self.consumer_address,
            self.provider_wallet,
        )

        return True

    def _build_and_validate_algo(self, algo_data):
        """Returns False if invalid, otherwise sets the validated_algo_dict attribute."""
        algorithm_did = algo_data.get("algorithmDid")

        if algorithm_did and not algo_data.get("algorithmMeta"):
            algorithm_token_address = algo_data.get("algorithmDataToken")
            algorithm_tx_id = algo_data.get("algorithmTransferTxId")

            algo = get_asset_from_metadatastore(get_metadata_url(), algorithm_did)
            try:
                asset_type = algo.metadata["main"]["type"]
            except ValueError:
                asset_type = None

            if asset_type != "algorithm":
                self.error = f"DID {algorithm_did} is not a valid algorithm"
                return False

            try:
                service = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, algo)
                _tx, _order_log, _transfer_log = validate_order(
                    self.consumer_address,
                    algorithm_token_address,
                    float(service.get_cost()),
                    algorithm_tx_id,
                    add_0x_prefix(did_to_id(algorithm_did))
                    if algorithm_did.startswith("did:")
                    else algorithm_did,
                    service.index,
                )
                validate_transfer_not_used_for_other_service(
                    algorithm_did,
                    service.index,
                    algorithm_tx_id,
                    self.consumer_address,
                    algorithm_token_address,
                )
                record_consume_request(
                    algorithm_did,
                    service.index,
                    algorithm_tx_id,
                    self.consumer_address,
                    algorithm_token_address,
                    service.get_cost(),
                )
            except Exception:
                self.error = "Algorithm is already in use."
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


class InputItemValidator:
    def __init__(self, consumer_address, provider_wallet, data, index):
        """Initializes the input item validator."""
        self.consumer_address = consumer_address
        self.provider_wallet = provider_wallet
        self.data = data
        self.index = index

    def validate(self):
        required_keys = ["documentId", "transferTxId"]

        for req_item in required_keys:
            if not self.data.get(req_item):
                self.error = f"No {req_item} in input item."
                return False

        if not self.data.get("serviceId") and self.data.get("serviceId") != 0:
            self.error = "No serviceId in input item."
            return False

        self.did = self.data.get("documentId")
        try:
            self.asset = get_asset_from_metadatastore(get_metadata_url(), self.did)
        except ValueError:
            self.error = f"Asset for did {self.did} not found."
            return False

        self.service = get_service_at_index(self.asset, self.data["serviceId"])

        if not self.service:
            self.error = f"Service index {self.data['serviceId']} not found."
            return False

        if self.service.type not in [
            ServiceTypes.ASSET_ACCESS,
            ServiceTypes.CLOUD_COMPUTE,
        ]:
            self.error = "Services in input can only be access or compute."
            return False

        if self.service.type != ServiceTypes.CLOUD_COMPUTE and self.index == 0:
            self.error = "Service for main asset must be compute."
            return False

        asset_urls = get_asset_download_urls(
            self.asset, self.provider_wallet, config_file=app.config["CONFIG_FILE"]
        )

        if self.service.type == ServiceTypes.CLOUD_COMPUTE and not asset_urls:
            self.error = "Services in input with compute type must be in the same provider you are calling."
            return False

        if self.service.type == ServiceTypes.CLOUD_COMPUTE:
            if not self.validate_algo():
                return False

        if asset_urls:
            self.validated_inputs = dict(
                {"index": self.index, "id": self.did, "url": asset_urls}
            )
        else:
            self.validated_inputs = dict(
                {
                    "index": self.index,
                    "id": self.did,
                    "remote": {
                        "txid": self.data.get("transferTxId"),
                        "serviceIndex": self.service.index,
                    },
                }
            )

        return self.validate_usage()

    def validate_algo(self):
        """Validates algorithm details that allow the algo dict to be built."""
        algorithm_meta = self.data.get("algorithmMeta")
        algorithm_did = self.data.get("algorithmDid")

        privacy_options = self.service.main.get("privacy", {})

        if algorithm_meta and privacy_options.get("allowRawAlgorithm", True) is False:
            self.error = f"cannot run raw algorithm on this did {self.did}."
            return False

        trusted_algorithms = privacy_options.get("trustedAlgorithms", [])

        if (
            algorithm_did
            and trusted_algorithms
            and algorithm_did not in trusted_algorithms
        ):
            self.error = f"this algorithm did {algorithm_did} is not trusted."
            return False

        return True

    def validate_usage(self):
        """Verify that the tokens have been transferred to the provider's wallet."""
        tx_id = self.data.get("transferTxId")
        token_address = self.asset._other_values["dataToken"]
        try:
            _tx, _order_log, _transfer_log = validate_order(
                self.consumer_address,
                token_address,
                float(self.service.get_cost()),
                tx_id,
                add_0x_prefix(did_to_id(self.did))
                if self.did.startswith("did:")
                else self.did,
                self.service.index,
            )
            validate_transfer_not_used_for_other_service(
                self.did,
                self.service.index,
                tx_id,
                self.consumer_address,
                token_address,
            )
            record_consume_request(
                self.did,
                self.service.index,
                tx_id,
                self.consumer_address,
                token_address,
                self.service.get_cost(),
            )
        except Exception:
            self.error = f"Order for serviceId {self.service.index} is not valid."
            return False

        return True
