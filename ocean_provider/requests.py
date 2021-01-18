from flask import request as flask_request
from flask_sieve import JsonRequest
from flask_sieve.validator import Validator

from ocean_provider.util import get_request_data


class CustomJsonRequest(JsonRequest):
    def __init__(self, request=None):
        request = request or flask_request
        request = get_request_data(request)
        self._validator = Validator(rules=self.rules(), request=request)


class NonceRequest(CustomJsonRequest):
    def rules(self):
        return {
            'userAddress': ['required'],
        }


class SimpleFlowConsumeRequest(CustomJsonRequest):
    def rules(self):
        return {
            'consumerAddress': ['required'],
            'dataToken': ['required'],
            'transferTxId': ['required']
        }


class EncryptRequest(CustomJsonRequest):
    def rules(self):
        return {
            'documentId': ['required'],
            'document': ['required'],
            'publisherAddress': ['required']
        }


class FileInfoRequest(CustomJsonRequest):
    def rules(self):
        return {
            'url': ['required_without:did'],
            'did': ['required_without:url', 'regex:^did:op']
        }
