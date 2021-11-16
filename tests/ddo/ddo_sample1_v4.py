#
# Copyright 2021 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
json_dict = {
    "@context": ["https://w3id.org/did/v1"],
    "id": "did:op:0c184915b07b44c888d468be85a9b28253e80070e5294b1aaed81c2f0264e430",
    "version": "4.0.0",
    "chainId": 1337,
    "metadata": {
        "created": "2000-10-31T01:30:00.000-05:00",
        "updated": "2000-10-31T01:30:00.000-05:00",
        "name": "Ocean protocol white paper",
        "type": "dataset",
        "description": "Ocean protocol white paper -- description",
        "author": "Ocean Protocol Foundation Ltd.",
        "license": "CC-BY",
        "contentLanguage": "en-US",
        "tags": ["white-papers"],
        "additionalInformation": {"test-key": "test-value"},
        "links": [
            "http://data.ceda.ac.uk/badc/ukcp09/data/gridded-land-obs/gridded-land-obs-daily/",
            "http://data.ceda.ac.uk/badc/ukcp09/data/gridded-land-obs/gridded-land-obs-averages-25km/"
            "http://data.ceda.ac.uk/badc/ukcp09/",
        ],
    },
    "services": [
        {
            "id": "test",
            "type": "access",
            "datatokenAddress": "0xC7EC1970B09224B317c52d92f37F5e1E4fF6B687",
            "name": "Download service",
            "description": "Download service",
            "serviceEndpoint": "http://localhost:8030/",
            "timeout": 0,
            "files": "0x04f0dddf93c186c38bfea243e06889b490a491141585669cfbe7521a5c7acb3bfea5a5527f17eb75ae1f66501e1f70f73df757490c8df479a618b0dd23b2bf3c62d07c372f64c6ad94209947471a898c71f1b2f0ab2a965024fa8e454644661d538b6aa025e517197ac87a3767820f018358999afda760225053df20ff14f499fcf4e7e036beb843ad95587c138e1f972e370d4c68c99ab2602b988c837f6f76658a23e99da369f6898ce1426d49c199cf8ffa33b79002765325c12781a2202239381866c6a06b07754024ee9a6e4aabc8",
        }
    ],
}
