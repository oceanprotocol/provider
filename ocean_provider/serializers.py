from eth_utils import add_0x_prefix
from ocean_provider.util import (
    get_asset_url_at_index,
    record_consume_request,
    validate_order,
    validate_transfer_not_used_for_other_service,
)
from ocean_provider.util_url import is_this_same_provider
from ocean_provider.utils.basics import get_asset_from_metadatastore, get_config
from ocean_utils.agreements.service_agreement import ServiceAgreement
from ocean_utils.agreements.service_types import ServiceTypes
from ocean_utils.did import did_to_id


def get_metadata_url():
    return get_config().aquarius_url


class StageAlgoSerializer:
    def __init__(self, consumer_address, provider_wallet, algo_data):
        """Initialize Serializer."""
        self.consumer_address = consumer_address
        self.provider_wallet = provider_wallet
        self.algo_data = algo_data

    def serialize(self):
        algorithm_meta = self.algo_data.get("algorithmMeta")
        algorithm_did = self.algo_data.get("algorithmDid")
        algorithm_token_address = self.algo_data.get("algorithmDataToken")
        algorithm_tx_id = self.algo_data.get("algorithmTransferTxId")

        dict_template = {"id": None, "rawcode": None, "container": None}

        if algorithm_did is None:
            return dict(
                {
                    "id": "",
                    "url": algorithm_meta.get("url"),
                    "rawcode": algorithm_meta.get("rawcode"),
                    "container": algorithm_meta.get("container"),
                }
            )

        msg = "algorithmDid requires both algorithmDataToken and algorithmTransferTxId."
        assert algorithm_token_address and algorithm_tx_id, msg

        algo_asset = get_asset_from_metadatastore(get_metadata_url(), algorithm_did)

        service = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, algo_asset)
        _tx, _order_log, _transfer_log = validate_order(
            self.consumer_address,
            algorithm_token_address,
            float(service.get_cost()),
            algorithm_tx_id,
            add_0x_prefix(did_to_id(algorithm_did))
            if algorithm_did.startswith("did:")
            else algorithm_did,
            service.index,
        )
        validate_transfer_not_used_for_other_service(
            algorithm_did,
            service.index,
            algorithm_tx_id,
            self.consumer_address,
            algorithm_token_address,
        )
        record_consume_request(
            algorithm_did,
            service.index,
            algorithm_tx_id,
            self.consumer_address,
            algorithm_token_address,
            service.get_cost(),
        )

        dict_template["id"] = algorithm_did
        dict_template["rawcode"] = ""

        if is_this_same_provider(service.service_endpoint):
            dict_template["url"] = get_asset_url_at_index(
                0, algo_asset, self.provider_wallet
            )
        else:
            dict_template["remote"] = {
                "serviceEndpoint": service.service_endpoint,
                "txId": algorithm_tx_id,
                "serviceIndex": service.index,
            }

        dict_template["container"] = algo_asset.metadata["main"]["algorithm"][
            "container"
        ]

        return dict(dict_template)
