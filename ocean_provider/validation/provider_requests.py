#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#

import os

from flask import request as flask_request
from flask_sieve import JsonRequest, ValidationException
from flask_sieve.rules_processor import RulesProcessor
from flask_sieve.validator import Validator
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.user_nonce import get_nonce
from ocean_provider.utils.accounts import verify_signature
from ocean_provider.utils.util import get_request_data
from ocean_provider.validation.RBAC import RBACValidator


class CustomJsonRequest(JsonRequest):
    """
    Extension of JsonRequest from Flask Sieve, allows us to set
    a custom Validator with specific rules
    """

    def __init__(self, request=None):
        request = request or flask_request
        request = get_request_data(request)
        class_name = self.__class__.__name__
        self._validators = list()
        action_mapping = RBACValidator.get_action_mapping()
        if os.getenv("RBAC_SERVER_URL") and class_name in action_mapping.keys():
            self._validators.append(
                RBACValidator(request_name=class_name, request=request)
            )
        self._validators.append(
            CustomValidator(
                rules=self.rules(),
                messages={
                    "signature.signature": "Invalid signature provided.",
                    "signature.download_signature": "Invalid signature provided.",
                    "signature.decrypt_signature": "Invalid signature provided.",
                },
                request=request,
            )
        )

    def validate(self):
        for validator in self._validators:
            if validator.fails():
                raise ValidationException(validator.messages())
        return True


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

    def validate_decrypt_signature(self, value, params, **kwargs):
        """
        Validates a signature using the decrypterAddress.

        parameters:
          - name: value
            type: string
            description: Value of the field being validated
          - name: params
            type: list
            description: The list of parameters defined for the rule,
                         i.e. names of other fields inside the request.
        """
        self._assert_params_size(size=4, params=params, rule="signature")
        transaction_id = self._attribute_value(params[0])
        data_nft_address = self._attribute_value(params[1])
        decrypter_address = self._attribute_value(params[2])
        chain_id = self._attribute_value(params[3])
        nonce = self._attribute_value(params[4])

        if transaction_id:
            original_msg = f"{transaction_id}{decrypter_address}{chain_id}"
        else:
            original_msg = f"{data_nft_address}{decrypter_address}{chain_id}"

        try:
            verify_signature(decrypter_address, value, original_msg, nonce)
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


class DecryptRequest(CustomJsonRequest):
    def rules(self):
        return {
            "decrypterAddress": ["required"],
            "chainId": ["required"],
            "transactionId": [
                "required_without:dataNftAddress,encryptedDocument,flags,documentHash"
            ],
            "dataNftAddress": [
                "required_without:transactionId",
                "required_with:encryptedDocument,flags,documentHash",
            ],
            "encryptedDocument": [
                "required_without:transactionId",
                "required_with:dataNftAddress,flags,documentHash",
            ],
            "flags": [
                "required_without:transactionId",
                "required_with:dataNftAddress,encryptedDocument,documentHash",
            ],
            "documentHash": [
                "required_without:transactionId",
                "required_with:dataNftAddress,encryptedDocument,flags",
            ],
            "nonce": ["required"],
            "signature": [
                "bail",
                "required",
                "decrypt_signature:transactionId,dataNftAddress,decrypterAddress,chainId,nonce",
            ],
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


class ComputeGetResult(CustomJsonRequest):
    def rules(self):
        return {
            "jobId": ["bail", "required"],
            "index": ["bail", "required"],
            "consumerAddress": ["bail", "required"],
            "signature": ["bail", "required", "signature:consumerAddress,index,jobId"],
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
