from eth_utils import add_0x_prefix
from flask import request as flask_request
from flask_sieve import JsonRequest
from flask_sieve.rules_processor import RulesProcessor
from flask_sieve.validator import Validator
from ocean_utils.did import did_to_id

from ocean_provider.access_token import (check_unique_access_token,
                                         get_access_token)
from ocean_provider.exceptions import InvalidSignatureError
from ocean_provider.user_nonce import get_nonce
from ocean_provider.util import get_request_data
from ocean_provider.utils.accounts import verify_signature
from ocean_provider.utils.encryption import get_address_from_public_key


class CustomJsonRequest(JsonRequest):
    """
    Extension of JsonRequest from Flask Sieve, allows us to set
    a custom Validator with specific rules
    """
    def __init__(self, request=None):
        request = request or flask_request
        request = get_request_data(request)
        self._validator = CustomValidator(rules=self.rules(), messages={
            'signature.signature': 'Invalid signature provided.',
            'signature.download_signature': 'Invalid signature provided.',
            'transferTxId.access_token': 'There is already a token with these parameters',  # noqa
        }, request=request)


class CustomValidator(Validator):
    """
    Extension of Validator from Flask Sieve, allows us to set
    custom validation rules. Implemented like this because handlers in
    Flask Sieve do not allow access to other parameters, just the value and
    attributes
    """
    def __init__(
        self, rules=None, request=None, custom_handlers=None, messages=None,
        **kwargs
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
        self._assert_params_size(size=3, params=params, rule='signature')
        owner = self._attribute_value(params[0])
        did = self._attribute_value(params[1])
        rule = params[2]
        original_msg = f'{owner}{did}' if rule == 'consumer_did' else f'{did}'
        try:
            verify_signature(
                owner, value, original_msg, get_nonce(owner)
            )
            return True
        except InvalidSignatureError:
            return False

        return False

    def validate_download_signature(self, value, params, **kwargs):
        """
        Validates a download signature using the documentId.

        parameters:
          - name: value
            type: string
            description: Value of the field being validated
          - name: params
            type: list
            description: The list of parameters defined for the rule,
                         i.e. names of other fields inside the request.
                         Should be owner, did and tx_id.
        """
        self._assert_params_size(size=3, params=params, rule='signature')
        owner = self._attribute_value(params[0])
        did = self._attribute_value(params[1])
        tx_id = self._attribute_value(params[2])
        original_msg = f'{did}'

        if did.startswith('did:'):
            did = add_0x_prefix(did_to_id(did))

        _, access_token = get_access_token(
            owner.lower(), did, tx_id
        )
        nonce = access_token if access_token else get_nonce(owner)

        try:
            verify_signature(owner, value, original_msg, nonce)
            return True
        except InvalidSignatureError:
            return False

        return False

    def validate_access_token(self, value, params, **kwargs):
        """
        Validates if an access token can be generated with the params.

        parameters:
          - name: value
            type: string
            description: Value of the field being validated
          - name: params
            type: list
            description: The list of parameters defined for the rule,
                         i.e. names of other fields inside the request.
                         Should be documentId, consumerAddress, delegatePublicKey
        """
        self._assert_params_size(size=3, params=params, rule='access_token')
        did = self._attribute_value(params[0])
        if did.startswith('did:'):
            did = add_0x_prefix(did_to_id(did))

        consumer_address = self._attribute_value(params[1])
        delegate_public_key = self._attribute_value(params[2])
        delegate_address = get_address_from_public_key(delegate_public_key)
        tx_id = value

        return check_unique_access_token(
            did, consumer_address, tx_id, delegate_address
        )


class NonceRequest(CustomJsonRequest):
    def rules(self):
        return {'userAddress': ['required'], }


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


class ComputeRequest(CustomJsonRequest):
    def rules(self):
        return {
            'consumerAddress': ['bail', 'required'],
            'signature': [
                'required',
                'signature:consumerAddress,documentId,only_did'
            ]
        }


class ComputeStartRequest(CustomJsonRequest):
    def rules(self):
        return {
            'documentId': ['bail', 'required'],
            'serviceId': ['required'],
            'serviceType': ['required'],
            'dataToken': ['required'],
            'consumerAddress': ['bail', 'required'],
            'transferTxId': ['required'],
            'output': ['required'],
            'algorithmMeta': ['required_without:algorithmDid'],
            'algorithmDid': [
                'required_without:algorithmMeta',
                'required_with_all:algorithmDataToken,algorithmTransferTxId'
            ],
            'signature': [
                'required',
                'signature:consumerAddress,documentId,consumer_did'
            ],
        }


class AccessTokenRequest(CustomJsonRequest):
    def rules(self):
        return {
            'documentId': ['bail', 'required'],
            'serviceId': ['required'],
            'serviceType': ['required'],
            'dataToken': ['required'],
            'consumerAddress': ['bail', 'required'],
            'secondsToExpiration': ['required', 'integer'],
            'delegatePublicKey': ['bail', 'required'],
            'transferTxId': [
                'required',
                'access_token:documentId,consumerAddress,delegatePublicKey'
            ],
            'fileIndex': ['required'],
            'signature': [
                'required',
                'signature:consumerAddress,documentId,only_did'
            ],
        }


class DownloadRequest(CustomJsonRequest):
    def rules(self):
        return {
            'documentId': ['bail', 'required'],
            'serviceId': ['required'],
            'serviceType': ['required'],
            'dataToken': ['required'],
            'consumerAddress': ['bail', 'required'],
            'transferTxId': ['bail', 'required'],
            'fileIndex': ['required'],
            'signature': [
                'required',
                'download_signature:consumerAddress,documentId,transferTxId'
            ],
        }


class InitializeRequest(CustomJsonRequest):
    def rules(self):
        return {
            'documentId': ['required'],
            'serviceId': ['required'],
            'serviceType': ['required'],
            'dataToken': ['required'],
            'consumerAddress': ['required'],
        }
