from eth_utils import event_abi_to_log_topic
from hexbytes import HexBytes
from web3.logs import DISCARD


class EventLogDecoder:
    def __init__(self, contract, receipt):
        self.contract = contract
        self.receipt = receipt
        self.event_abis = [abi for abi in self.contract.abi if abi["type"] == "event"]
        self._sign_abis = {event_abi_to_log_topic(abi): abi for abi in self.event_abis}

    def decode_logs(self):
        result = {}

        for log in self.receipt.logs:
            func_abi = self._get_event_abi_by_selector(log["topics"][0])
            event = getattr(self.contract.events, func_abi["name"])()
            processed = event.processReceipt(self.receipt, errors=DISCARD)
            result[func_abi["name"]] = processed

        return result

    def _get_event_abi_by_selector(self, selector: HexBytes):
        try:
            return self._sign_abis[selector]
        except KeyError:
            raise ValueError("Event is not presented in contract ABI.")
