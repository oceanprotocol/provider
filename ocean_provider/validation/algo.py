#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json
import logging

from ocean_provider.constants import BaseURLs
from ocean_provider.file_types.file_types_factory import FilesTypeFactory
from ocean_provider.serializers import StageAlgoSerializer
from ocean_provider.utils.asset import (
    get_asset_from_metadatastore,
    check_asset_consumable,
)
from ocean_provider.utils.address import get_provider_fee_token
from ocean_provider.utils.basics import get_config, get_metadata_url
from ocean_provider.utils.datatoken import (
    record_consume_request,
    validate_order,
    validate_transfer_not_used_for_other_service,
)
from ocean_provider.utils.provider_fees import get_provider_fee_amount
from ocean_provider.utils.util import (
    get_service_files_list,
    msg_hash,
)
from ocean_provider.validation.images import validate_container

logger = logging.getLogger(__name__)


class WorkflowValidator:
    def __init__(self, web3, consumer_address, provider_wallet, data):
        """Initializes the validator."""
        self.web3 = web3
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
        main_input = self.data["dataset"]
        additional_inputs = self.data.get("additionalDatasets", list())

        if not additional_inputs:
            additional_inputs = []

        if not isinstance(additional_inputs, list):
            self.resource = "additional_input"
            self.message = "invalid"
            return False

        all_data = [main_input] + additional_inputs
        algo_data = self.data["algorithm"]

        self.validated_inputs = []
        valid_until_list = []
        provider_fee_amounts = []

        status = self.preliminary_algo_validation()
        if not status:
            return False

        for index, input_item in enumerate(all_data):
            input_item["algorithm"] = algo_data
            input_item_validator = InputItemValidator(
                self.web3,
                self.consumer_address,
                self.provider_wallet,
                input_item,
                {"environment": self.data.get("environment")},
                index,
            )
            input_item_validator.algo_files_checksum = self.algo_files_checksum
            input_item_validator.algo_container_checksum = self.algo_container_checksum

            status = input_item_validator.validate()
            if not status:
                self.resource = input_item_validator.resource
                self.message = input_item_validator.message
                return False

            self.validated_inputs.append(input_item_validator.validated_inputs)
            valid_until_list.append(input_item_validator.valid_until)
            provider_fee_amounts.append(input_item_validator.provider_fee_amount)

            if index == 0:
                self.service_endpoint = input_item_validator.service.service_endpoint

        status = self._build_and_validate_algo(algo_data)
        if not status:
            return False

        if algo_data.get("documentId"):
            valid_until_list.append(self.algo_valid_until)
            provider_fee_amounts.append(self.algo_fee_amount)

        self.valid_until = max(valid_until_list)

        provider_fee_token = get_provider_fee_token(self.web3.chain_id)

        required_provider_fee = get_provider_fee_amount(
            self.valid_until,
            self.data.get("environment"),
            self.web3,
            provider_fee_token,
        )

        paid_provider_fees_index = -1
        for fee in provider_fee_amounts:
            if required_provider_fee <= fee:
                paid_provider_fees_index = provider_fee_amounts.index(fee)

        if paid_provider_fees_index == -1:
            self.resource = "order"
            self.message = "fees_not_paid"
            return False

        self.agreement_id = None
        for index, input_item in enumerate(all_data):
            if index == paid_provider_fees_index:
                self.agreement_id = input_item["transferTxId"]

        if not self.agreement_id:
            self.agreement_id = algo_data["transferTxId"]

        return True

    def validate_output(self):
        """Validates output dictionary after stage build."""
        output_def = decode_from_data(self.data, "output", dec_type="dict")

        if output_def == -1:
            self.resource = "output"
            self.message = "invalid"
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
        algorithm_did = algo_data.get("documentId")
        self.algo_service = None
        algo = None

        if algorithm_did and not algo_data.get("meta"):
            algorithm_tx_id = algo_data.get("transferTxId")
            algorithm_service_id = algo_data.get("serviceId")

            algo = get_asset_from_metadatastore(get_metadata_url(), algorithm_did)

            try:
                self.algo_service = algo.get_service_by_id(algorithm_service_id)
                algorithm_token_address = self.algo_service.datatoken_address

                if self.algo_service.type == "compute":
                    asset_urls = get_service_files_list(
                        self.algo_service, self.provider_wallet, algo
                    )

                    if not asset_urls:
                        self.resource = "algorithm"
                        self.message = "compute_services_not_in_same_provider"
                        return False

                if not self.algo_service:
                    self.resource = "algorithm.serviceId"
                    self.message = "missing"
                    return False
                logger.debug("validate_order called for ALGORITHM usage.")
                _tx, _order_log, _provider_fees_log, start_order_tx_id = validate_order(
                    self.web3,
                    self.consumer_address,
                    algorithm_tx_id,
                    algo,
                    self.algo_service,
                )
                self.algo_valid_until = _provider_fees_log.args.validUntil
                self.algo_fee_amount = _provider_fees_log.args.providerFeeAmount
                validate_transfer_not_used_for_other_service(
                    algorithm_did,
                    self.algo_service.id,
                    algorithm_tx_id,
                    self.consumer_address,
                    algorithm_token_address,
                )
                record_consume_request(
                    algorithm_did,
                    self.algo_service.id,
                    algorithm_tx_id,
                    self.consumer_address,
                    algorithm_token_address,
                    1,
                )
            except Exception as e:
                logger.debug(
                    f"validate_order for ALGORITHM failed with error {str(e)}."
                )
                self.resource = "algorithm"
                self.message = "in_use_or_not_on_chain"
                return False

        algorithm_dict = StageAlgoSerializer(
            self.consumer_address,
            self.provider_wallet,
            algo_data,
            self.algo_service,
            algo,
        ).serialize()

        valid, resource, error_msg = validate_formatted_algorithm_dict(
            algorithm_dict, algorithm_did
        )

        if not valid:
            self.resource = f"algorithm.{resource}" if resource else "algorithm"
            self.message = error_msg
            return False

        self.validated_algo_dict = algorithm_dict

        return True

    def preliminary_algo_validation(self):
        algo_data = self.data["algorithm"]
        algorithm_did = algo_data.get("documentId")
        algorithm_service_id = algo_data.get("serviceId")
        algorithm_meta = algo_data.get("meta")

        if algorithm_did is None and algorithm_meta is None:
            self.resource = "algorithm"
            self.message = "missing_meta_documentId"
            return False

        if not algorithm_did:
            self.algo_files_checksum = None
            self.algo_container_checksum = None
            return True

        try:
            algo_ddo = get_asset_from_metadatastore(get_metadata_url(), algorithm_did)
        except Exception:
            self.resource = "algorithm"
            self.message = "file_unavailable"
            return False

        try:
            asset_type = algo_ddo.metadata["type"]
        except ValueError:
            asset_type = None

        if asset_type != "algorithm":
            self.resource = "algorithm"
            self.message = "not_algo"
            return False

        if not algorithm_service_id:
            self.resource = "algorithm.serviceId"
            self.message = "missing"
            return False

        try:
            service = algo_ddo.get_service_by_id(algo_data.get("serviceId"))
            self.algo_files_checksum, self.algo_container_checksum = get_algo_checksums(
                service, self.provider_wallet, algo_ddo
            )
        except Exception:
            self.resource = "algorithm"
            self.message = "file_unavailable"
            return False

        return True


def get_algo_checksums(algo_service, provider_wallet, algo_ddo):
    compute_url_objects = get_service_files_list(
        algo_service, provider_wallet, algo_ddo
    )

    checksums = [
        FilesTypeFactory.validate_and_create(durl)[1].check_details(with_checksum=True)[
            1
        ]["checksum"]
        for durl in compute_url_objects
    ]

    algo_files_checksum = "".join(checksums).lower()

    algo_container_checksum = msg_hash(
        algo_ddo.metadata["algorithm"]["container"]["entrypoint"]
        + algo_ddo.metadata["algorithm"]["container"]["checksum"]
    )

    return algo_files_checksum, algo_container_checksum


def validate_formatted_algorithm_dict(algorithm_dict, algorithm_did):
    if algorithm_did and not (
        algorithm_dict.get("url") or algorithm_dict.get("remote")
    ):
        return False, "", "did_not_found"

    

    if (
        not algorithm_dict.get("url")
        and not algorithm_dict.get("rawcode")
        and not algorithm_dict.get("remote")
    ):
        return (
            False,
            "",
            "meta_oneof_url_rawcode_remote",
        )  # noqa

    container = algorithm_dict.get("container", {})
    # Validate `container` data
    #for key in ["entrypoint", "image", "checksum"]:
     #   if not container.get(key):
      #      return (
       #         False,
        #        "algorithm `container` must specify values for all of entrypoint, image and checksum.",
         #   )

    return True, "", ""


class InputItemValidator:
    def __init__(
        self,
        web3,
        consumer_address,
        provider_wallet,
        data,
        extra_data,
        index,
        check_usage=True,
    ):
        """Initializes the input item validator."""
        self.web3 = web3
        self.consumer_address = consumer_address
        self.provider_wallet = provider_wallet
        self.data = data
        self.extra_data = extra_data
        self.index = index
        self.check_usage = check_usage
        self.resource = f"datasets[{index}]" if index else "dataset"

    def validate(self):
        required_keys = (
            ["documentId", "transferTxId"] if self.check_usage else ["documentId"]
        )

        for req_item in required_keys:
            if not self.data.get(req_item):
                self.resource += f".{req_item}"
                self.message = "missing"
                return False

        if not self.data.get("serviceId") and self.data.get("serviceId") != 0:
            self.resource += f".serviceId"
            self.message = "missing"
            return False

        self.did = self.data.get("documentId")
        self.asset = get_asset_from_metadatastore(get_metadata_url(), self.did)

        if not self.asset:
            self.resource += f".documentId"
            self.message = "did_not_found"
            return False

        self.service = self.asset.get_service_by_id(self.data["serviceId"])

        if not self.service:
            self.resource += f".serviceId"
            self.message = "not_found"
            return False

        consumable, message = check_asset_consumable(
            self.asset, self.consumer_address, logger, self.service.service_endpoint
        )

        if not consumable:
            self.message = message
            return False

        if self.service.type not in ["access", "compute"]:
            self.resource += f".serviceId"
            self.message = "service_not_access_compute"
            return False

        if self.service.type != "compute" and self.index == 0:
            self.resource += f".serviceId"
            self.message = "main_service_compute"
            return False

        asset_urls = get_service_files_list(
            self.service, self.provider_wallet, self.asset
        )
        if self.service.type == "compute" and not asset_urls:
            self.resource += f".serviceId"
            self.message = "compute_services_not_in_same_provider"
            return False

        if self.service.type == "compute":
            if not self.validate_algo():
                return False

        self.validated_inputs = {
            "index": self.index,
            "id": self.did,
            "remote": {
                "txId": self.data.get("transferTxId"),
                "serviceId": self.service.id,
            },
        }

        userdata = self.data.get("userdata")
        if userdata:
            self.validated_inputs["remote"]["userdata"] = userdata

        return self.validate_usage() if self.check_usage else True

    def _validate_trusted_algos(
        self, algorithm_did, trusted_algorithms, trusted_publishers
    ):
        if not trusted_algorithms and not trusted_publishers:
            return True

        if trusted_publishers:
            algo_ddo = get_asset_from_metadatastore(get_metadata_url(), algorithm_did)
            if algo_ddo.nft["owner"] not in trusted_publishers:
                self.message = "not_trusted_algo_publisher"
                return False

        if trusted_algorithms:
            try:
                did_to_trusted_algo_dict = {
                    algo["did"]: algo for algo in trusted_algorithms
                }
                if algorithm_did not in did_to_trusted_algo_dict:
                    self.message = "not_trusted_algo"
                    return False

            except KeyError:
                self.message = "no_publisherTrustedAlgorithms"
                return False

            trusted_algo_dict = did_to_trusted_algo_dict[algorithm_did]
            allowed_files_checksum = trusted_algo_dict.get("filesChecksum")
            allowed_container_checksum = trusted_algo_dict.get(
                "containerSectionChecksum"
            )

            if (
                allowed_files_checksum
                and self.algo_files_checksum != allowed_files_checksum.lower()
            ):
                self.error = f"filesChecksum for algorithm with did {algo_ddo.did} does not match"
                return True

            if (
                allowed_container_checksum
                and self.algo_container_checksum != allowed_container_checksum
            ):
                self.message = "algorithm_container_checksum_mismatch"
                return False

        return True

    def validate_algo(self):
        """Validates algorithm details that allow the algo dict to be built."""
        algo_data = self.data["algorithm"]
        algorithm_did = algo_data.get("documentId")

        privacy_options = self.service.compute_dict

        if algorithm_did:
            return self._validate_trusted_algos(
                algorithm_did,
                privacy_options.get("publisherTrustedAlgorithms", []),
                privacy_options.get("publisherTrustedAlgorithmPublishers", []),
            )

        allow_raw_algo = privacy_options.get("allowRawAlgorithm", False)
        if allow_raw_algo is False:
            self.message = "no_raw_algo_allowed"
            return False

        return True

    def validate_usage(self):
        """Verify that the tokens have been transferred to the provider's wallet."""
        tx_id = self.data.get("transferTxId")
        token_address = self.service.datatoken_address
        logger.debug("Validating ASSET usage.")

        try:
            _tx, _order_log, _provider_fees_log, start_order_tx_id = validate_order(
                self.web3,
                self.consumer_address,
                tx_id,
                self.asset,
                self.service,
                self.extra_data,
            )
            self.valid_until = _provider_fees_log.args.validUntil
            self.provider_fee_amount = _provider_fees_log.args.providerFeeAmount
            validate_transfer_not_used_for_other_service(
                self.did, self.service.id, tx_id, self.consumer_address, token_address
            )
            record_consume_request(
                self.did,
                self.service.id,
                tx_id,
                self.consumer_address,
                token_address,
                1,
            )
        except Exception as e:
            logger.exception(f"validate_usage failed with {str(e)}.")
            self.resource += ".serviceId"
            self.message = "order_invalid"
            return False

        return True


def build_stage_output_dict(output_def, service_endpoint, owner, provider_wallet):
    config = get_config()
    if BaseURLs.SERVICES_URL in service_endpoint:
        service_endpoint = service_endpoint.split(BaseURLs.SERVICES_URL)[0]

    return dict({"metadataUri": config.aquarius_url})


def decode_from_data(data, key, dec_type="list"):
    """Retrieves a dictionary key as a decoded dictionary or list."""
    default_value = list() if dec_type == "list" else dict()
    data = data.get(key, default_value)

    if data == "":
        return default_value

    if data and isinstance(data, str):
        try:
            data = json.loads(data)
        except json.decoder.JSONDecodeError:
            return -1

    return data
