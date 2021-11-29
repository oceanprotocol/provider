#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import json
import os

import requests

from ocean_provider.exceptions import RequestNotFound
from ocean_provider.utils.accounts import sign_message
from ocean_provider.utils.basics import get_provider_wallet


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
        self.provider_address = get_provider_wallet().address
        address = self.request.get(
            "consumerAddress", self.request.get("publisherAddress")
        )
        self.credentials = {"type": "address", "value": address}
        self.component = "provider"

    @staticmethod
    def get_action_mapping():
        return {
            "EncryptRequest": "encryptUrl",
            "InitializeRequest": "initialize",
            "DownloadRequest": "access",
            "ComputeRequest": "compute",
            "ComputeStartRequest": "compute",
        }

    def messages(self):
        return [{"RBAC": "RBAC Validation failed!"}]

    def fails(self):
        payload = self.build_payload()
        response = requests.post(os.getenv("RBAC_SERVER_URL"), json=payload)
        return not response.json()

    def get_dids(self):
        return [
            {"did": self.request["documentId"], "serviceId": self.request["serviceId"]}
        ]

    def get_algos(self):
        if "algorithmDid" not in self.request.keys():
            return []
        return [
            {
                "did": self.request["algorithmDid"],
                "serviceId": self.request["algorithmServiceId"],
            }
        ]

    def get_additional_dids(self):
        if "additionalInputs" not in self.request.keys():
            return []
        additional_inputs = self.request["additionalInputs"]
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
        signature = sign_message(message, get_provider_wallet())

        return {"signature": signature}

    def build_initialize_payload(self):
        message = "initialize" + json.dumps(self.credentials)
        signature = sign_message(message, get_provider_wallet())
        return {
            "signature": signature,
            "dids": self.get_dids(),
        }

    def build_access_payload(self):
        message = "access" + json.dumps(self.credentials)
        signature = sign_message(message, get_provider_wallet())
        return {"signature": signature, "dids": self.get_dids()}

    def build_compute_payload(self):
        dids = self.get_dids()
        algos = self.get_algos()
        algos_text = json.dumps(algos) if algos else ""
        additional_dids = self.get_additional_dids()
        additional_dids_text = json.dumps(additional_dids) if additional_dids else ""
        message = (
            "compute"
            + json.dumps(self.credentials)
            + json.dumps(dids)
            + algos_text
            + additional_dids_text
        )
        signature = sign_message(message, get_provider_wallet())
        compute_payload = {"signature": signature, "dids": dids}
        if algos:
            compute_payload["algos"] = algos
        if additional_dids:
            compute_payload["additionalDids"] = additional_dids
        return compute_payload
