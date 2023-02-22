#
# Copyright 2023 Ocean Protocol Foundation
# SPDX-License-Identifier: Apache-2.0
#
ddo_dict = {
    "id": "did:op:e16a777d1f146dba369cf98d212f34c17d9de516fcda5c9546076cf043ba6e37",
    "version": "4.1.0",
    "chain_id": 8996,
    "metadata": {
        "created": "2021-12-29T13:34:27",
        "updated": "2021-12-29T13:34:27",
        "description": "Asset description",
        "copyrightHolder": "Asset copyright holder",
        "name": "Asset name",
        "author": "Asset Author",
        "license": "CC-0",
        "links": ["https://google.com"],
        "contentLanguage": "en-US",
        "categories": ["category 1"],
        "tags": ["tag 1"],
        "additionalInformation": {},
        "type": "dataset",
    },
    "services": [
        {
            "index": 0,
            "id": "compute_1",
            "type": "compute",
            "name": "compute_1",
            "description": "compute_1",
            "datatokenAddress": "0x0951D2558F897317e5a68d1b9e743156D1681168",
            "serviceEndpoint": "http://172.15.0.4:8030/api/services",
            "files": "0x0442b53536ebb3f1ee0301288efc7a14b9f807e9d104647ca052b0fb67954440bf18f9b5143c94ac5e7dedbefacccbf38783728de2f4c8af8468dca630e1e92e5c7c03cb82b4956fcfecb9fe6f19771df19e7e8dd06b4d6665bbe5b3d5bf5dbf5781b4f3ee97c7864a98d903df4acea2ad39176aed782b3faad82808ca4709382ccd8fa42561830069293d7cd6685696a54fc752f6d78fe7b3ed598636c5447fa593ffe4929280f3e6720f159251474035a29bdc11ae73150d3871600010dd97bd7de63cb64b338d4f5c1a9b70c082df801864a7d4f6c19e5568361e3cf6a3e795f5ae7c8972019405c113a33b5ae09a4dd5cdeff0",
            "timeout": 3600,
            "compute": {
                "namespace": "test",
                "allowRawAlgorithm": True,
                "allowNetworkAccess": False,
                "publisherTrustedAlgorithmPublishers": [],
                "publisherTrustedAlgorithms": [
                    {
                        "did": "did:op:706d7452b1a25b183051fe02f2ad902d54fc45a43fdcee26b20f21684b5dee72",
                        "filesChecksum": "b4908c868c78086097a10f986718a8f3fae1455f0d443c3dc59330207d47cc6d",
                        "containerSectionChecksum": "20d3f5667b2068e84db5465fb51aa405b06a0ff791635048d7976ec7f5abdc73",
                    }
                ],
            },
        },
        {
            "index": 1,
            "id": "access_1",
            "type": "access",
            "name": "name doesn't affect tests",
            "description": "decription doesn't affect tests",
            "datatokenAddress": "0x12d1d7BaF6fE43805391097A63301ACfcF5f5720",
            "serviceEndpoint": "http://172.15.0.4:8030",
            "files": "0x0487db5b45655d0ce74cf6e4707c2dd40509cb4d8f80af76758790b4ab715d7658a1f71ee1ee744e7af87275113bd0fde5f8362431934407c8e8bd6f20b1216de4f94cb3d03b975b5c61c5c9e6ac3373e50fc2d181c1b2808f9bca18a59180b77baad213c4dda70ddd866e6cbb0d6eae1036b6e0e8e8c2e17ca0e55180b2afb00acaa27bc343117457bb8d56d670d1e42ed6834b52c4a7f2eb035cb4bd98e24e5ba28935b67071d77d0edcd914572da492c72d0c049ed47d37a84b56a6be311b27fde9aea893afe408d2e96ce330e46443c2ee02ba5ee8757c5d3ef917de9863d13f843fb37794accad4d029c960fe4a56c3cc3d70",
            "timeout": 3600,
            "compute_dict": None,
        },
    ],
    "credentials": {"allow": [], "deny": []},
    "nft": {
        "address": "0x7358776DACe83a4b48E698645F32B043481daCBA",
        "name": "Data NFT 1",
        "symbol": "DNFT1",
        "state": 0,
        "owner": "0xBE5449a6A97aD46c8558A3356267Ee5D2731ab5e",
        "created": "2021-12-29T13:34:28",
    },
    "datatokens": [
        {
            "address": "0x0951D2558F897317e5a68d1b9e743156D1681168",
            "name": "Datatoken 1",
            "symbol": "DT1",
            "serviceId": "compute_1",
        }
    ],
    "event": {
        "tx": "0xa73c332ba8d9615c438e7773d8f8db6a258cc615e43e47130e5500a9da729cea",
        "block": 121,
        "from": "0xBE5449a6A97aD46c8558A3356267Ee5D2731ab5e",
        "contract": "0x7358776DACe83a4b48E698645F32B043481daCBA",
        "datetime": "2021-12-29T13:34:28",
    },
    "stats": {"consumes": -1, "isInPurgatory": "false"},
}

alg_ddo_dict = {
    "id": "did:op:706d7452b1a25b183051fe02f2ad902d54fc45a43fdcee26b20f21684b5dee72",
    "version": "4.1.0",
    "chain_id": 8996,
    "metadata": {
        "created": "2021-12-29T13:34:18",
        "updated": "2021-12-29T13:34:18",
        "description": "Asset description",
        "copyrightHolder": "Asset copyright holder",
        "name": "Asset name",
        "author": "Asset Author",
        "license": "CC-0",
        "links": ["https://google.com"],
        "contentLanguage": "en-US",
        "categories": ["category 1"],
        "tags": ["tag 1"],
        "additionalInformation": {},
        "type": "algorithm",
        "algorithm": {
            "language": "python",
            "version": "0.1.0",
            "container": {
                "entrypoint": "run.sh",
                "image": "oceanprotocol/algo_dockers",
                "tag": "python-branin",
                "checksum": "sha256:8221d20c1c16491d7d56b9657ea09082c0ee4a8ab1a6621fa720da58b09580e4",
            },
        },
    },
    "services": [
        {
            "index": 0,
            "id": "b4d208d6-0074-4002-9dd1-02d5d0ad352e",
            "type": "access",
            "name": "name doesn't affect tests",
            "description": "decription doesn't affect tests",
            "datatokenAddress": "0x12d1d7BaF6fE43805391097A63301ACfcF5f5720",
            "serviceEndpoint": "http://172.15.0.4:8030",
            "files": "0x0487db5b45655d0ce74cf6e4707c2dd40509cb4d8f80af76758790b4ab715d7658a1f71ee1ee744e7af87275113bd0fde5f8362431934407c8e8bd6f20b1216de4f94cb3d03b975b5c61c5c9e6ac3373e50fc2d181c1b2808f9bca18a59180b77baad213c4dda70ddd866e6cbb0d6eae1036b6e0e8e8c2e17ca0e55180b2afb00acaa27bc343117457bb8d56d670d1e42ed6834b52c4a7f2eb035cb4bd98e24e5ba28935b67071d77d0edcd914572da492c72d0c049ed47d37a84b56a6be311b27fde9aea893afe408d2e96ce330e46443c2ee02ba5ee8757c5d3ef917de9863d13f843fb37794accad4d029c960fe4a56c3cc3d70",
            "timeout": 3600,
            "compute_dict": None,
        },
        {
            "index": 1,
            "id": "compute_1",
            "type": "compute",
            "name": "compute_1",
            "description": "compute_1",
            "datatokenAddress": "0x0951D2558F897317e5a68d1b9e743156D1681168",
            "serviceEndpoint": "http://172.15.0.4:8030/api/services",
            "files": "0x0442b53536ebb3f1ee0301288efc7a14b9f807e9d104647ca052b0fb67954440bf18f9b5143c94ac5e7dedbefacccbf38783728de2f4c8af8468dca630e1e92e5c7c03cb82b4956fcfecb9fe6f19771df19e7e8dd06b4d6665bbe5b3d5bf5dbf5781b4f3ee97c7864a98d903df4acea2ad39176aed782b3faad82808ca4709382ccd8fa42561830069293d7cd6685696a54fc752f6d78fe7b3ed598636c5447fa593ffe4929280f3e6720f159251474035a29bdc11ae73150d3871600010dd97bd7de63cb64b338d4f5c1a9b70c082df801864a7d4f6c19e5568361e3cf6a3e795f5ae7c8972019405c113a33b5ae09a4dd5cdeff0",
            "timeout": 3600,
            "compute": {
                "namespace": "test",
                "allowRawAlgorithm": True,
                "allowNetworkAccess": False,
                "publisherTrustedAlgorithmPublishers": [],
                "publisherTrustedAlgorithms": [
                    {
                        "did": "did:op:706d7452b1a25b183051fe02f2ad902d54fc45a43fdcee26b20f21684b5dee72",
                        "filesChecksum": "b4908c868c78086097a10f986718a8f3fae1455f0d443c3dc59330207d47cc6d",
                        "containerSectionChecksum": "743e3591b4c035906be7dbc9eb592089d096be3b2d752f8d8d52917dd609f31f",
                    }
                ],
            },
        },
    ],
    "credentials": {"allow": [], "deny": []},
    "nft": {
        "address": "0xa072B0D477fae1aBE3537Ff66A8389B184E18F4d",
        "name": "Data NFT 1",
        "symbol": "DNFT1",
        "state": 0,
        "owner": "0xBE5449a6A97aD46c8558A3356267Ee5D2731ab5e",
        "created": "2021-12-29T13:34:20",
    },
    "datatokens": [
        {
            "address": "0x12d1d7BaF6fE43805391097A63301ACfcF5f5720",
            "name": "Datatoken 1",
            "symbol": "DT1",
            "serviceId": "b4d208d6-0074-4002-9dd1-02d5d0ad352e",
        }
    ],
    "event": {
        "tx": "0x09366c3bf4b24eabbe6de4a1ee63c07fca82c768fcff76e18e8dd461197f2aba",
        "block": 116,
        "from": "0xBE5449a6A97aD46c8558A3356267Ee5D2731ab5e",
        "contract": "0xa072B0D477fae1aBE3537Ff66A8389B184E18F4d",
        "datetime": "2021-12-29T13:34:20",
    },
    "stats": {"consumes": -1, "isInPurgatory": "false"},
}
