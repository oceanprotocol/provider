#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import json

from ocean_lib.common.agreements.service_types import ServiceTypesIndices
from ocean_lib.web3_internal.transactions import sign_hash

from ocean_provider.exceptions import RequestNotFound
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.utils.util import msg_hash


class RBACValidator:
    def __init__(
        self,
        request_name,
        request,
    ):
        self.request = request
        action_mapping = self.get_action_mapping()
        if request_name not in action_mapping.keys():
            raise RequestNotFound("Request name is not valid!")
        self.action = action_mapping[request_name]
        self.credentials = {
            "type": "address",
            "address": get_provider_wallet().address,
        }
        self.component = "provider"
        self.provider_address = get_provider_wallet().address

    @staticmethod
    def get_action_mapping():
        return {
            "EncryptRequest": "encryptUrl",
            "InitializeRequest": "initialize",
            "DownloadRequest": "access",
            "ComputeRequest": "compute",
            "ComputeStartRequest": "compute",
        }

    def fails(self):
        return False

    def get_request_dict(self):
        return json.loads(self.request["document"])

    def get_dids(self, service_index: int):
        req_dict = self.get_request_dict()
        assets = list()
        assets.append(req_dict["documentId"])
        return [{"did": asset_did, "serviceId": service_index} for asset_did in assets]

    def get_algos(self):
        req_dict = self.get_request_dict()
        algorithms = list()
        algorithms.append(req_dict["algorithmDid"])
        return [
            {
                "did": algorithm_did,
                "serviceId": ServiceTypesIndices.DEFAULT_COMPUTING_INDEX,
            }
            for algorithm_did in algorithms
        ]

    def get_additional_dids(self):
        req_dict = self.get_request_dict()
        additional_inputs = (
            req_dict["additionalInputs"] if "additionalInputs" in req_dict else []
        )
        return [
            {
                "did": additional_input["documentId"],
                "serviceId": additional_input["serviceId"],
            }
            for additional_input in additional_inputs
        ]

    def build_payload(self):
        payload = {
            "eventType": self.action,
            "component": self.component,
            "providerAddress": self.provider_address,
            "credentials": self.credentials,
        }
        # builds actions like build_encrtyptUrl_payload to update the dictionary
        # with request - specific key-values.
        payload.update(getattr(self, f"build_{self.action}_payload")())
        return payload

    def build_encryptUrl_payload(self):
        message = "encryptUrl" + json.dumps(self.credentials)
        signature = sign_hash(msg_hash(message), get_provider_wallet())

        return {"signature": signature}

    def build_initialize_payload(self):
        dids = self.get_dids(ServiceTypesIndices.DEFAULT_ACCESS_INDEX)
        message = "initialize" + json.dumps(self.credentials)
        signature = sign_hash(msg_hash(message), get_provider_wallet())
        return {
            "signature": signature,
            "dids": dids,
        }

    def build_access_payload(self):
        dids = self.get_dids(ServiceTypesIndices.DEFAULT_ACCESS_INDEX)
        message = "access" + json.dumps(self.credentials)
        signature = sign_hash(msg_hash(message), get_provider_wallet())
        return {
            "signature": signature,
            "dids": dids,
        }

    def build_compute_payload(self):
        dids = self.get_dids(ServiceTypesIndices.DEFAULT_COMPUTING_INDEX)
        algos = self.get_algos()
        additional_dids = (
            self.get_additional_dids() if self.get_additional_dids() else []
        )
        if not additional_dids:
            message = (
                "compute"
                + json.dumps(self.credentials)
                + json.dumps(dids)
                + json.dumps(algos)
            )
            signature = sign_hash(msg_hash(message), get_provider_wallet())
            return {"signature": signature, "dids": dids, "algos": algos}
        message = (
            "compute"
            + json.dumps(self.credentials)
            + json.dumps(dids)
            + json.dumps(algos)
            + json.dumps(additional_dids)
        )
        signature = sign_hash(msg_hash(message), get_provider_wallet())
        return {
            "signature": signature,
            "dids": dids,
            "algos": algos,
            "additionalDids": additional_dids,
        }
