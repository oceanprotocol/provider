import hashlib
import json
import logging
from typing import Any, Optional, Tuple
from uuid import uuid4

from enforce_typing import enforce_types
from flask import Response
from ocean_provider.file_types.definitions import FilesType
from ocean_provider.utils.basics import get_web3

logger = logging.getLogger(__name__)


class SmartContractCall(FilesType):
    @enforce_types
    def __init__(
        self,
        address: Optional[str] = None,
        abi: Optional[dict] = None,
        userdata=None,
    ) -> None:
        self.address = address
        self.type = "smartcontract"
        self.abi = abi
        self.userdata = None
        if userdata:
            self.userdata = (
                userdata if isinstance(userdata, dict) else json.loads(userdata)
            )

    def get_download_url(self):
        return ""

    @enforce_types
    def validate_dict(self) -> Tuple[bool, Any]:
        if not self.address:
            return False, "malformed smartcontract type, missing contract address"
        # validate abi
        inputs = self.abi.get("inputs")
        type = self.abi.get("type")
        if inputs is None or type != "function":
            return False, "invalid abi"
        mutability = self.abi.get("stateMutability", None)
        if mutability not in ["view", "pure"]:
            return False, "only view or pure functions are allowed"
        if not self.abi.get("name"):
            return False, "missing name"

        # check that all inputs have a match in userdata
        if len(inputs) > 0 and self.userdata is None:
            return False, "Missing parameters"
        for input in inputs:
            value = self.userdata.get(input.get("name"))
            if not value:
                return False, f"Missing userparam: {input.name}"
        return True, self

    @enforce_types
    def get_filename(self) -> str:
        return uuid4().hex

    def fetch_smartcontract_call(self):
        web3 = get_web3()
        contract = web3.eth.contract(
            address=web3.toChecksumAddress(self.address), abi=[self.abi]
        )
        function = contract.functions[self.abi.get("name")]
        args = dict()
        for input in self.abi.get("inputs"):
            args[input.get("name")] = self.userdata.get(input.get("name"))
            if input.get("type") == "address":
                args[input.get("name")] = web3.toChecksumAddress(
                    args[input.get("name")]
                )
        result = function(**args).call()
        if isinstance(result, object):
            return json.dumps(result), "application/json"
        return result, "application/text"

    def check_details(self, with_checksum=False):
        try:
            result, type = self.fetch_smartcontract_call()
            details = {"contentLength": len(result) or "", "contentType": type}
            if with_checksum:
                sha = hashlib.sha256()
                sha.update(result.encode("utf-8"))
                details["checksumType"] = "sha256"
                details["checksum"] = sha.hexdigest()
            return True, details
        except Exception:
            return False, {}

    def build_download_response(
        self,
        request,
        validate_url=True,
    ):
        try:
            result, type = self.fetch_smartcontract_call()
            return Response(
                result,
                200,
            )
        except Exception:
            raise ValueError("Failed to call contract")
