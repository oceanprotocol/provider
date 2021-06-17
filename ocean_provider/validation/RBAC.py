#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import json
from abc import ABC
from typing import Optional

from ocean_lib.common.agreements.service_types import ServiceTypesIndices
from ocean_lib.web3_internal.transactions import sign_hash

from ocean_provider.exceptions import RequestNotFound
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.utils.util import msg_hash


class RBACValidator(ABC):
    def __init__(
        self,
        request_name=None,
        request=None,
        payload: Optional[dict] = None,
        assets: Optional[list] = None,
        algorithms: Optional[list] = None,
    ):
        self.request = request
        self.payload = payload if payload else dict()
        if not request:
            raise RequestNotFound("Request not found.")
        action_mapping = self.get_action_mapping()
        self.action = action_mapping[request_name]
        self.credentials = {
            "type": "address",
            "address": get_provider_wallet().address,
        }
        self.component = "provider"
        self.provider_address = get_provider_wallet().address
        self.assets = assets if assets else []
        self.algorithms = algorithms if algorithms else []
        if request_name in ["ComputeRequest", "ComputeStartRequest"]:
            self.additional_inputs = self.payload["additionalInputs"]

    @staticmethod
    def get_action_mapping():
        action_mapping = {
            "EncryptRequest": "encryptUrl",
            "InitializeRequest": "initialize",
            "DownloadRequest": "access",
            "ComputeRequest": "compute",
            "ComputeStartRequest": "compute",
        }
        return action_mapping

    def fails(self):
        return False

    def get_compute_dict(self):
        return {
            "dids": [
                {
                    "did": asset.did,
                    "serviceId": ServiceTypesIndices.DEFAULT_COMPUTING_INDEX,
                }
                for asset in self.assets
            ],
            "algos": [
                {
                    "did": algorithm.did,
                    "serviceId": ServiceTypesIndices.DEFAULT_COMPUTING_INDEX,
                }
                for algorithm in self.algorithms
            ],
            "additionalDids": [
                {
                    "did": additional_input["documentId"],
                    "serviceId": additional_input["serviceId"],
                }
                for additional_input in self.additional_inputs
            ],
        }

    def get_dids(self):
        return {
            "dids": [
                {
                    "did": asset.did,
                    "serviceId": ServiceTypesIndices.DEFAULT_ACCESS_INDEX,
                }
                for asset in self.assets
            ],
        }

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
        dids = self.get_dids()["dids"]
        message = "initialize" + json.dumps(self.credentials)
        signature = sign_hash(msg_hash(message), get_provider_wallet())
        return {
            "signature": signature,
            "dids": dids,
        }

    def build_access_payload(self):
        dids = self.get_dids()["dids"]
        message = "access" + json.dumps(self.credentials)
        signature = sign_hash(msg_hash(message), get_provider_wallet())
        return {
            "signature": signature,
            "dids": dids,
        }

    def build_compute_payload(self):
        dids = self.get_compute_dict()["dids"]
        algos = self.get_compute_dict()["algos"]
        additional_dids = self.get_compute_dict()["additionalDids"]
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
