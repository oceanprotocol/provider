#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import hashlib
import json
import os

from flask import request as flask_request
from flask_sieve import JsonRequest
from flask_sieve.rules_processor import RulesProcessor
from flask_sieve.validator import Validator
from ocean_lib.assets.asset import Asset
from ocean_lib.common.agreements.service_types import ServiceTypesIndices
from ocean_lib.web3_internal.transactions import sign_hash

from ocean_provider.exceptions import InvalidSignatureError, RequestNotFound
from ocean_provider.utils.basics import get_provider_wallet
from ocean_provider.user_nonce import get_nonce
from ocean_provider.utils.accounts import verify_signature
from ocean_provider.utils.util import get_request_data
from typing import Optional


class CustomJsonRequest(JsonRequest):
    """
    Extension of JsonRequest from Flask Sieve, allows us to set
    a custom Validator with specific rules
    """

    def __init__(self, request=None):
        request = request or flask_request
        request = get_request_data(request)
        class_name = self.__class__.__name__
        if os.getenv("RBAC_SERVER_URL") and class_name in [
            "InitializeRequest",
            "DownloadRequest",
            "ComputeStartRequest",
            "ComputeRequest",
            "FileInfoRequest",
            "EncryptRequest",
        ]:
            self._validator = RBACValidator(request_name=class_name, request=request)
        else:
            self._validator = CustomValidator(
                rules=self.rules(),
                messages={
                    "signature.signature": "Invalid signature provided.",
                    "signature.download_signature": "Invalid signature provided.",
                },
                request=request,
            )


class CustomValidator(Validator):
    """
    Extension of Validator from Flask Sieve, allows us to set
    custom validation rules. Implemented like this because handlers in
    Flask Sieve do not allow access to other parameters, just the value and
    attributes
    """

    def __init__(
        self, rules=None, request=None, custom_handlers=None, messages=None, **kwargs
    ):
        super(CustomValidator, self).__init__(
            rules, request, custom_handlers, messages, **kwargs
        )
        self._processor = CustomRulesProcessor()


class RBACValidator:
    def __init__(self, request_name=None, request=None, assets: Optional[list] = None):
        self._request = request
        if not request:
            raise RequestNotFound("Request not found.")
        action_mapping = {
            "EncryptRequest": "encryptUrl",
            "InitializeRequest": "initialize",
            "DownloadRequest": "access",
            "ComputeRequest": "compute",
            "ComputeStartRequest": "compute",
        }
        self._action = action_mapping[request_name]
        self._credentials = {
            "type": "address",
            "address": get_provider_wallet().address,
        }
        self._component = "provider"
        self._assets = assets

    @property
    def credentials(self):
        return self._credentials

    @property
    def component(self):
        return self._component

    @property
    def action(self):
        return self._action

    @property
    def assets(self):
        return self._assets

    @property
    def request(self):
        return self._request

    def passes(self):
        return True

    def fails(self):
        return False

    def build_payload(self):
        payload = {
            "eventType": self.action,
            "component": self.component,
            "providerAddress": get_provider_wallet().address,
            "credentials": self.credentials,
        }
        payload.update(getattr(self, f"build_{self.action}_payload")())
        return payload

    def build_encryptUrl_payload(self):
        message = "encryptUrl" + json.dumps(self.credentials)
        signature = sign_hash(
            hashlib.sha256(message.encode("utf-8")).hexdigest(), get_provider_wallet()
        )

        return {"signature": signature}

    def build_initialize_payload(self):
        message = "initialize" + json.dumps(self.credentials)
        signature = sign_hash(
            hashlib.sha256(message.encode("utf-8")).hexdigest(), get_provider_wallet()
        )
        return {
            "signature": signature,
            "dids": [
                {
                    "did": asset.did,
                    "serviceId": ServiceTypesIndices.DEFAULT_ACCESS_INDEX,
                }
                for asset in self.assets
            ],
        }

    def build_access_payload(self):
        message = "access" + json.dumps(self.credentials)
        signature = sign_hash(
            hashlib.sha256(message.encode("utf-8")).hexdigest(), get_provider_wallet()
        )
        return {
            "signature": signature,
            "dids": [
                {
                    "did": asset.did,
                    "serviceId": ServiceTypesIndices.DEFAULT_ACCESS_INDEX,
                }
                for asset in self.assets
            ],
        }


class CustomRulesProcessor(RulesProcessor):
    """
    Extension of RulesProcessor from Flask Sieve, allows us to set
    custom validation handlers. Implemented like this because handlers in
    Flask Sieve do not allow access to other parameters, just the value and
    attributes
    """

    def validate_signature(self, value, params, **kwargs):
        """
        Validates a signature using the documentId, jobId and consumerAddress.

        parameters:
          - name: value
            type: string
            description: Value of the field being validated
          - name: params
            type: list
            description: The list of parameters defined for the rule,
                         i.e. names of other fields inside the request.
        """
        self._assert_params_size(size=3, params=params, rule="signature")
        owner = self._attribute_value(params[0]) or ""
        did = self._attribute_value(params[1]) or ""
        job_id = self._attribute_value(params[2]) or ""

        original_msg = f"{owner}{job_id}{did}"
        try:
            verify_signature(owner, value, original_msg, get_nonce(owner))
            return True
        except InvalidSignatureError:
            pass

        return False

    def validate_download_signature(self, value, params, **kwargs):
        """
        Validates a signature using the documentId.

        parameters:
          - name: value
            type: string
            description: Value of the field being validated
          - name: params
            type: list
            description: The list of parameters defined for the rule,
                         i.e. names of other fields inside the request.
        """
        self._assert_params_size(size=2, params=params, rule="signature")
        owner = self._attribute_value(params[0])
        did = self._attribute_value(params[1])
        original_msg = f"{did}"
        try:
            verify_signature(owner, value, original_msg, get_nonce(owner))
            return True
        except InvalidSignatureError:
            pass

        return False


class NonceRequest(CustomJsonRequest):
    def rules(self):
        return {"userAddress": ["required"]}


class EncryptRequest(CustomJsonRequest):
    def rules(self):
        return {
            "documentId": ["required"],
            "document": ["required"],
            "publisherAddress": ["required"],
        }


class FileInfoRequest(CustomJsonRequest):
    def rules(self):
        return {
            "url": ["required_without:did"],
            "did": ["required_without:url", "regex:^did:op"],
        }


class ComputeRequest(CustomJsonRequest):
    def rules(self):
        return {
            "consumerAddress": ["bail", "required"],
            "signature": ["required", "signature:consumerAddress,documentId,jobId"],
        }


class UnsignedComputeRequest(CustomJsonRequest):
    def rules(self):
        return {"consumerAddress": ["bail", "required"]}


class ComputeStartRequest(CustomJsonRequest):
    def rules(self):
        return {
            "documentId": ["bail", "required"],
            "serviceId": ["required"],
            "consumerAddress": ["bail", "required"],
            "transferTxId": ["required"],
            "output": ["required"],
            "algorithmMeta": ["required_without:algorithmDid"],
            "algorithmDid": [
                "required_without:algorithmMeta",
                "required_with_all:algorithmDataToken,algorithmTransferTxId",
            ],
            "signature": ["required", "signature:consumerAddress,documentId,jobId"],
        }


class DownloadRequest(CustomJsonRequest):
    def rules(self):
        return {
            "documentId": ["bail", "required"],
            "serviceId": ["required"],
            "dataToken": ["required"],
            "consumerAddress": ["bail", "required"],
            "transferTxId": ["bail", "required"],
            "fileIndex": ["required"],
            "signature": ["required", "download_signature:consumerAddress,documentId"],
        }


class InitializeRequest(CustomJsonRequest):
    def rules(self):
        return {
            "documentId": ["required"],
            "serviceId": ["required"],
            "serviceType": ["required"],
            "dataToken": ["required"],
            "consumerAddress": ["required"],
        }
