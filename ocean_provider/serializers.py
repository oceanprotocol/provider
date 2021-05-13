#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json

from ocean_provider.utils.basics import get_asset_from_metadatastore
from ocean_provider.utils.util import get_asset_url_at_index, get_metadata_url


class StageAlgoSerializer:
    def __init__(self, consumer_address, provider_wallet, algo_data, algo_service):
        """Initialize Serializer."""
        self.consumer_address = consumer_address
        self.provider_wallet = provider_wallet
        self.algo_data = algo_data
        self.algo_service = algo_service

    def serialize(self):
        algorithm_meta = self.algo_data.get("algorithmMeta")
        algorithm_did = self.algo_data.get("algorithmDid")
        algorithm_tx_id = self.algo_data.get("algorithmTransferTxId")

        dict_template = {"id": None, "rawcode": None, "container": None}

        if algorithm_meta and isinstance(algorithm_meta, str):
            algorithm_meta = json.loads(algorithm_meta)

        if algorithm_did is None:
            return dict(
                {
                    "id": "",
                    "url": algorithm_meta.get("url"),
                    "rawcode": algorithm_meta.get("rawcode"),
                    "container": algorithm_meta.get("container"),
                }
            )

        algo_asset = get_asset_from_metadatastore(get_metadata_url(), algorithm_did)

        dict_template["id"] = algorithm_did
        dict_template["rawcode"] = ""

        asset_urls = get_asset_url_at_index(0, algo_asset, self.provider_wallet)
        if asset_urls:
            dict_template["url"] = asset_urls
        else:
            dict_template["remote"] = {
                "serviceEndpoint": self.algo_service.service_endpoint,
                "txId": algorithm_tx_id,
                "serviceIndex": self.algo_service.index,
            }

        dict_template["container"] = algo_asset.metadata["main"]["algorithm"][
            "container"
        ]

        return dict(dict_template)
