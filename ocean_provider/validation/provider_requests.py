#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import logging
from datetime import datetime
import os

from flask import request as flask_request
from flask_sieve import JsonRequest, ValidationException
from flask_sieve.rules_processor import RulesProcessor
from flask_sieve.validator import Validator

from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.utils.accounts import verify_signature, verify_nonce
from ocean_provider.utils.util import get_request_data
from ocean_provider.user_nonce import is_token_valid
from ocean_provider.validation.RBAC import RBACValidator

logger = logging.getLogger(__name__)


ALLOWED_FILE_TYPES = ["ipfs", "url", "arweave", "graphql"]


class CustomJsonRequest(JsonRequest):
    """
    Extension of JsonRequest from Flask Sieve, allows us to set
    a custom Validator with specific rules
    """

    def __init__(self, request=None):
        request = request or flask_request
        headers = request.headers
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
                    "expiration.timestamp": "Invalid timestamp provided.",
                },
                request=request,
                headers=headers,
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
        self,
        rules=None,
        request=None,
        custom_handlers=None,
        messages=None,
        headers=None,
        **kwargs,
    ):
        super(CustomValidator, self).__init__(
            rules, request, custom_handlers, messages, **kwargs
        )
        self._processor = CustomRulesProcessor()
        self._processor.headers = headers


class CustomRulesProcessor(RulesProcessor):
    """
    Extension of RulesProcessor from Flask Sieve, allows us to set
    custom validation handlers. Implemented like this because handlers in
    Flask Sieve do not allow access to other parameters, just the value and
    attributes
    """

    def check_auth_header(self, value, owner, nonce):
        """
        Checks AuthToken header and returns an int representing the check result.
        Values meaning:
          - 0 means the check needs to continue inside validate_signature,
        since a signature is present and should override any auth token checks.
          - 1 means the check is conclusively OK, the auth headers are correct
        and signature is not present, meaning we can skip further validate_signature checks
          - -1 means the check has conclusively failed, the auth headers are incorrect or
        expired, and the request should be rejected.
        """
        if value:
            return 0

        if self.headers and self.headers.get("AuthToken"):
            valid, _ = is_token_valid(self.headers["AuthToken"], owner)
            return 1 if valid and verify_nonce(owner, nonce) else -1

        return -1

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
        nonce = self._attribute_value(params[3]) or ""

        cont = self.check_auth_header(value, owner, nonce)
        if abs(cont) == 1:
            return cont > 0

        original_msg = f"{owner}{job_id}{did}"
        try:
            verify_signature(owner, value, original_msg, nonce)
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
        self._assert_params_size(size=3, params=params, rule="signature")
        owner = self._attribute_value(params[0])
        did = self._attribute_value(params[1])
        nonce = self._attribute_value(params[2])

        cont = self.check_auth_header(value, owner, nonce)
        if abs(cont) == 1:
            return cont > 0

        original_msg = f"{did}"
        try:
            verify_signature(owner, value, original_msg, nonce)
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

        cont = self.check_auth_header(value, decrypter_address, nonce)
        if abs(cont) == 1:
            return cont > 0

        logger.info(
            f"Successfully retrieve params for decrypt: transaction_id={transaction_id},"
            f"data_nft_address={data_nft_address}, decrypter_address={decrypter_address},"
            f"chain_id={chain_id}, nonce={nonce}."
        )

        if transaction_id:
            first_arg = transaction_id
        else:
            first_arg = data_nft_address

        original_msg = f"{first_arg}{decrypter_address}{chain_id}"

        try:
            verify_signature(decrypter_address, value, original_msg, nonce)
            logger.info("Correct signature.")
            return True
        except InvalidSignatureError:
            pass

        return False

    def validate_timestamp(self, value, **kwargs):
        try:
            datetime.fromtimestamp(int(value))
            timestamp_now = int(datetime.utcnow().timestamp())

            return int(value) > timestamp_now
        except Exception:
            return False


class NonceRequest(CustomJsonRequest):
    def rules(self):
        return {"userAddress": ["required"]}


class DecryptRequest(CustomJsonRequest):
    def rules(self):
        return {
            "decrypterAddress": ["required"],
            "chainId": ["required"],
            "dataNftAddress": ["required"],
            "transactionId": [
                "required_without:dataNftAddress,encryptedDocument,flags,documentHash"
            ],
            "encryptedDocument": [
                "required_without:transactionId",
                "required_with:flags,documentHash",
            ],
            "flags": [
                "required_without:transactionId",
                "required_with:encryptedDocument,documentHash",
            ],
            "documentHash": [
                "required_without:transactionId",
                "required_with:encryptedDocument,flags",
            ],
            "nonce": ["required", "numeric"],
            "signature": [
                "bail",
                "decrypt_signature:transactionId,dataNftAddress,decrypterAddress,chainId,nonce",
            ],
        }


class FileInfoRequest(CustomJsonRequest):
    def rules(self):
        return {
            "type": ["required_without:did", f"in:{','.join(ALLOWED_FILE_TYPES)}"],
            "did": ["required_without:type", "regex:^did:op"],
            "hash": ["required_if:type,ipfs"],
            "url": ["required_if:type,url"],
            "transactionId": ["required_if:type,arweave"],
            "serviceId": ["required_without:type"],
        }


class ComputeRequest(CustomJsonRequest):
    def rules(self):
        return {
            "consumerAddress": ["bail", "required"],
            "nonce": ["bail", "required", "numeric"],
            "signature": [
                "signature:consumerAddress,documentId,jobId,nonce",
            ],
        }


class UnsignedComputeRequest(CustomJsonRequest):
    def rules(self):
        return {"consumerAddress": ["bail", "required"]}


class ComputeStartRequest(CustomJsonRequest):
    def rules(self):
        return {
            "dataset.documentId": ["bail", "required"],
            "dataset.serviceId": ["bail", "required"],
            "dataset.transferTxId": ["required"],
            "algorithm.documentId": [
                "required_without:algorithm.meta",
                "required_with_all:algorithm.serviceId,algorithm.transferTxId",
            ],
            "algorithm.meta": ["required_without:algorithm.documentId"],
            "consumerAddress": ["bail", "required"],
            "nonce": ["bail", "required", "numeric"],
            "signature": [
                "bail",
                "signature:consumerAddress,dataset.documentId,jobId,nonce",
            ],
        }


class ComputeGetResult(CustomJsonRequest):
    def rules(self):
        return {
            "jobId": ["bail", "required"],
            "index": ["bail", "required"],
            "consumerAddress": ["bail", "required"],
            "nonce": ["bail", "required", "numeric"],
            "signature": [
                "bail",
                "signature:consumerAddress,index,jobId,nonce",
            ],
        }


class DownloadRequest(CustomJsonRequest):
    def rules(self):
        return {
            "documentId": ["bail", "required"],
            "serviceId": ["required"],
            "consumerAddress": ["bail", "required"],
            "transferTxId": ["bail", "required"],
            "fileIndex": ["required"],
            "nonce": ["bail", "required", "numeric"],
            "signature": [
                "download_signature:consumerAddress,documentId,nonce",
            ],
        }


class InitializeRequest(CustomJsonRequest):
    def rules(self):
        return {
            "documentId": ["required"],
            "serviceId": ["required"],
            "consumerAddress": ["required"],
            "fileIndex": ["sometimes", "integer", "min:0"],
            "transferTxId": ["sometimes"],
        }


class InitializeComputeRequest(CustomJsonRequest):
    def rules(self):
        return {
            "datasets": ["required"],
            "algorithm.documentId": [
                "required_without:algorithm.meta",
                "required_with_all:algorithm.serviceId,algorithm.transferTxId",
            ],
            "algorithm.meta": ["required_without:algorithm.documentId"],
            "compute.env": ["required"],
            "compute.validUntil": ["required", "integer"],
            "consumerAddress": ["required"],
        }


class CreateTokenRequest(CustomJsonRequest):
    def rules(self):
        return {
            "address": ["bail", "required"],
            "expiration": ["bail", "required", "integer", "timestamp"],
            "nonce": ["bail", "required", "numeric"],
            "signature": [
                "required",
                "signature:address,,,nonce",
            ],
        }


class DeleteTokenRequest(CustomJsonRequest):
    def rules(self):
        return {
            "address": ["bail", "required"],
            "token": ["bail", "required"],
            "nonce": ["bail", "required", "numeric"],
            "signature": [
                "required",
                "signature:address,,,nonce",
            ],
        }
