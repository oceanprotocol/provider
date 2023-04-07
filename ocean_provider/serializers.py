#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
import json


class StageAlgoSerializer:
    def __init__(
        self,
        consumer_address,
        algo_data,
        algo_service,
        algo_asset=None,
    ):
        """Initialize Serializer."""
        self.consumer_address = consumer_address
        self.algo_data = algo_data
        self.algo_service = algo_service
        self.algo_asset = algo_asset

    def serialize(self):
        algorithm_meta = self.algo_data.get("meta")
        algorithm_did = self.algo_data.get("documentId")
        algorithm_tx_id = self.algo_data.get("transferTxId")

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

        dict_template["id"] = algorithm_did
        dict_template["rawcode"] = ""
        dict_template["container"] = self.algo_asset.metadata["algorithm"]["container"]
        dict_template["remote"] = {
            "serviceEndpoint": self.algo_service.service_endpoint,
            "txId": algorithm_tx_id,
            "serviceId": self.algo_service.id,
            "userData": self.algo_data.get("algouserdata", None),
        }
        dict_template["algocustomdata"] = self.algo_data.get("algocustomdata", None)
        return dict(dict_template)
