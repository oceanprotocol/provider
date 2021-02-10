from flask import request as flask_request
from flask_sieve import JsonRequest
from flask_sieve.rules_processor import RulesProcessor
from flask_sieve.validator import Validator
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.user_nonce import get_nonce
from ocean_provider.util import get_request_data
from ocean_provider.utils.accounts import verify_signature


class CustomJsonRequest(JsonRequest):
    """
    Extension of JsonRequest from Flask Sieve, allows us to set
    a custom Validator with specific rules
    """

    def __init__(self, request=None):
        request = request or flask_request
        request = get_request_data(request)
        self._validator = CustomValidator(
            rules=self.rules(),
            messages={
                "signature.signature": "Invalid signature provided.",
                "signature.compute_signature": "Invalid signature provided.",
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


class CustomRulesProcessor(RulesProcessor):
    """
    Extension of RulesProcessor from Flask Sieve, allows us to set
    custom validation handlers. Implemented like this because handlers in
    Flask Sieve do not allow access to other parameters, just the value and
    attributes
    """

    def validate_signature(self, value, params, **kwargs):
        """
        Validates a signature using the documentId and/or the consumerAddress.

        parameters:
          - name: value
            type: string
            description: Value of the field being validated
          - name: params
            type: list
            description: The list of parameters defined for the rule,
                         i.e. names of other fields inside the request.
                         The last item in the params list is the rule to be
                         used for checking. 'consumer_did' concatenates
                         consumer address and did for the original message,
                         'did' only adds the did to the original_message
        """
        self._assert_params_size(size=3, params=params, rule="signature")
        owner = self._attribute_value(params[0])
        did = self._attribute_value(params[1])
        rule = params[2]
        original_msg = f"{owner}{did}" if rule == "consumer_did" else f"{did}"
        try:
            verify_signature(owner, value, original_msg, get_nonce(owner))
            return True
        except InvalidSignatureError:
            return False

        return False

    def validate_compute_signature(self, value, params, **kwargs):
        """
        Validates a signature using the owner, jobId, and documentId.

        parameters:
          - name: value
            type: string
            description: Value of the field being validated
          - name: params
            type: list
            description: The list of parameters defined for the rule,
                         i.e. names of other fields inside the request.
        """
        self._assert_params_size(size=3, params=params, rule="compute_signature")

        if not value:
            return True

        owner = self._attribute_value(params[0])
        did = self._attribute_value(params[1])
        jobId = self._attribute_value(params[2])
        original_msg = f"{owner}{jobId}{did}"
        try:
            verify_signature(owner, value, original_msg, get_nonce(owner))
            return True
        except InvalidSignatureError:
            return False

        return False


class NonceRequest(CustomJsonRequest):
    def rules(self):
        return {"userAddress": ["required"]}


class SimpleFlowConsumeRequest(CustomJsonRequest):
    def rules(self):
        return {
            "consumerAddress": ["required"],
            "dataToken": ["required"],
            "transferTxId": ["required"],
        }


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
            "signature": ["required", "signature:consumerAddress,documentId,only_did"],
        }


class UnsignedComputeRequest(CustomJsonRequest):
    def rules(self):
        return {
            "consumerAddress": ["bail", "required"],
            "jobId": ["required"],
            "signature": [
                "nullable",
                "compute_signature:consumerAddress,documentId,jobId",
            ],
        }


class ComputeStartRequest(CustomJsonRequest):
    def rules(self):
        return {
            "documentId": ["bail", "required"],
            "serviceId": ["required"],
            "serviceType": ["required"],
            "dataToken": ["required"],
            "consumerAddress": ["bail", "required"],
            "transferTxId": ["required"],
            "output": ["required"],
            "algorithmMeta": ["required_without:algorithmDid"],
            "algorithmDid": [
                "required_without:algorithmMeta",
                "required_with_all:algorithmDataToken,algorithmTransferTxId",
            ],
            "signature": [
                "required",
                "signature:consumerAddress,documentId,consumer_did",
            ],
        }


class DownloadRequest(CustomJsonRequest):
    def rules(self):
        return {
            "documentId": ["bail", "required"],
            "serviceId": ["required"],
            "serviceType": ["required"],
            "dataToken": ["required"],
            "consumerAddress": ["bail", "required"],
            "transferTxId": ["bail", "required"],
            "fileIndex": ["required"],
            "signature": ["required", "signature:consumerAddress,documentId,only_did"],
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
