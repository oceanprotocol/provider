#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json

from ocean_provider.utils.basics import get_asset_from_metadatastore
from ocean_provider.utils.services import ServiceType
from ocean_provider.utils.url import append_userdata
from ocean_provider.utils.util import get_metadata_url, get_service_files_list


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

        dict_template = {
            "id": None,
            "rawcode": None,
            "container": None,
            "algouserdata": None,
        }

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
        sa = algo_asset.get_service_by_type(ServiceType.ACCESS)

        dict_template["id"] = algorithm_did
        dict_template["rawcode"] = ""
        dict_template["container"] = algo_asset.metadata["algorithm"]["container"]
        dict_template["remote"] = {
                "serviceEndpoint": self.algo_service.service_endpoint,
                "txId": algorithm_tx_id,
                "serviceId": self.algo_service.id,
            }
        # userdata = self.algo_data.get("algouserdata")
        # if userdata:
        #    dict_template["remote"]["algouserdata"] = userdata

        

        return dict(dict_template)
