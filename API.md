<!--
Copyright 2021 Ocean Protocol Foundation
SPDX-License-Identifier: Apache-2.0
-->
# Ocean Provider Endpoints Specification

This document specifies the endpoints for Ocean Provider to be implemented by the core
developers. The final implementation and its documentation happens in Swagger
inline code comments and the latest implemented API documentation can be
accessed via:

- [Docs: Provider API Reference](https://docs.oceanprotocol.com/references/ocean_provider/)


## nonce endpoint
### GET /api/services/nonce
Parameters
```
    userAddress: String object containing a user's ethereum address
```

Returns:
Json object containing the nonce value.

Example:
```
POST /api/services/nonce?userAddress=0x990922334

```

Response:

```json
{
  "nonce": 23
}
```

## Encrypt endpoint

### GET /api/services/encrypt
Body: binary application/octet-stream

Returns:
Bytes string containing the encrypted document.


Example:
```
POST /api/services/encrypt
body: b'\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F\ ... \x00\x04YZ'
```

Response:

```

b'0x04b2bfab1f4e...7ed0573'

```

## Decrypt endpoint

### POST /api/services/decrypt
Parameters
```
    decrypterAddress: String object containing the address of the decrypter (required)
    chainId: the chain id of the network the document is on (required)
    transactionId: the transaction id of the encrypted document (optional)
    dataNftAddress: the address of the data nft (optional)
    encryptedDocument: the encrypted document (optional)
    flags: the flags of the encrypted document (optional)
    documentHash: the hash of the encrypted document (optional)
    nonce: the nonce of the encrypted document (required)
    signature: the signature of the encrypted document (required)
```

Returns:
Bytes string containing the decrypted document.


Example:
```
POST /api/services/decrypt
payload: {
    'decrypterAddress':'0xA78deb2Fa79463945C247991075E2a0e98Ba7A09'
    'chainId':8996
    'dataNftAddress':'0xBD558814eE914800EbfeF4a1cbE196F5161823d9'
    'encryptedDocument':'0xfd377a585a000004e6d6b4460200210116000000742fe5a3e0059f031f5d003d88840633b6d207ac3fdec5d1791d339f068c86c7c2399ad23dbf4d12b749db667b148e444be0bc0022f4b0c5c8795de3fbe6d00873b2c0dad8f18ecb76e3ed9cd5ba519ce9450d6c592c39adae1e1c0d78f8e8a93af488697fdf48d8cc12e91e2165321258aea37f71fd7c9119b498093260fcfb3ce12cd6c27ecfeebe53d51d2eea66802a5c12e647b06939b4ac020b2f77113b58d99f8c2d75c14426d7c1d6e7f711adf49429ef17a050c31ea9d24d9874394ee6fc9f9c08a8482b4e782d5ce2e6afb03d8977a16af310f7a93dd5c6b63078b71b682cb258f728b76811ba56b3affda6078cf516b91689524e3d17f55a26a2fe7df355cc76d4d6ed8f588347ca05b42e3e8d732d4abacc59e5087b049083af28ca7c4e4031d13bf74f4e7f2f484d0c266e4f1350532b8cac46860cff5d9c35dc7041902f4f1a00c2de40d8dfa8b4dfbbf2d4b5922751c80e2ef2af910831697976c868b214555538edac0019c1625d14a027dcccbbc5179b1063d5f9d8382c68a512beef5de0ddd55194a730fb9df480e1baa957f89e4f44c04b82bc391018204006f703b2faf14be0f50c852a66200289ab1899dbfa7ffa662fe08e0d570eac4dada4f212503aae73e74f6436dc08f41c4444e24d59dc32aaa679e6bcd6012c53b5b9cbf07afef7dc214...
    'flags': 1
    'documentHash':'0x0cb38a7bba49758a86f8556642aff655d00e41da28240d5ea0f596b74094d91f'
    'nonce':'1644315615.24195'
    'signature':'0xd6f27047853203824ab9e5acef87d0a501a64aee93f33a83b6f91cbe8fb4489824defceaccde91273f41290cb2a0c15572368e8bea0b456c7a653659cad7de311b'
}
```

Response:

```

b'{"@context": ["https://w3id.org/did/v1"], "id": "did:op:0c184915b07b44c888d468be85a9b28253e80070e5294b1aaed81c ...'

```



## Initial service request endpoint
### GET /api/services/initialize
Parameters
```
    documentId: String object containing document id (e.g. a DID)
    serviceId: String, ID of the service the datatoken is attached to
    consumerAddress: String object containing consumerAddress's ethereum address
    environment: String representing a compute environment offered by the provider
    validUntil: Integer, date of validity of the service (optional)
    fileIndex: Integer, the index of the file from the files list in the dataset. If set, provider will validate the file access. (optional)
```

Returns:
Json document with a quote for amount of tokens to transfer to the provider account.


Example:
```
GET /api/services/initialize
payload:
{
    "documentId":"0x1111",
    "serviceId": 0,
    "consumerAddress":"0x990922334",
}
```

Response:

```json
{
    "datatoken": "0x21fa3ea32892091...",
    "nonce": 23,
    "providerFee": 200,
    "computeAddress": "0x8123jdf8sdsa..."
}
```


## Download endpoint
### GET /api/services/download
Parameters
```
    documentId: String object containing document id (e.g. a DID)
    serviceId: String, representing the list of `file` objects that describe each file in the dataset
    transferTxId: Hex string -- the id of on-chain transaction for approval of datatokens transfer
    given to the provider's account
    fileIndex: integer, the index of the file from the files list in the dataset
    nonce: Nonce
    consumerAddress: String object containing consumerAddress's ethereum address
    signature: String object containg user signature (signed message)
```

Returns:
File stream


Example:
```
POST /api/services/download
payload:
{
    "documentId":"0x1111",
    "serviceId": 0,
    "fileIndex": 0,
    "datatoken": "",
    "consumerAddress":"0x990922334",
    "signature":"0x00110011",
    "transferTxId": "0xa09fc23421345532e34829"
```

Response:

```json
{
  "": ""
}
```

## File info endpoint
### POST /api/services/fileinfo

Retrieves Content-Type and Content-Length from the given URL or asset.

Parameters
```
    type: String, either "url" or "asset"
    did: String, DID of the dataset
    hash: String, hash of the file
    url: String, URL of the file
    serviceId: String, ID of the service the datatoken is attached to
```

Returns:
Json document file info object

Example:
```
POST /api/services/fileinfo
payload:
{
    "url": "https://s3.amazonaws.com/testfiles.oceanprotocol.com/info.0.json",
    "type": "url",
    "method": "GET",
}
```

Response:

```json
[
    {
        "contentLength":"1161"
        "contentType":"application/json"
        "index":0
        "valid": true
    },...
]
```

## Compute endpoints
All compute endpoints respond with an Array of status objects, each object
describing a compute job info.

Each status object will contain:
```
    owner:The owner of this compute job
    documentId: String object containing document id (e.g. a DID)
    jobId: String object containing workflowId
    dateCreated:Unix timestamp of job creation
    dateFinished:Unix timestamp when job finished
    status:  Int, see below for list
    statusText: String, see below
    algorithmLogUrl: URL to get the algo log (for user)
    resultsUrls: Array of URLs for algo outputs
    resultsDid: If published, the DID
```

Status description (`statusText`): (see Operator-Service for full status list)

| status   | Description               |
|----------|---------------------------|
|  1       | Job started               |
|  2       | Configuring volumes       |
|  3       | Running algorithm         |
|  4       | Filtering results         |
|  5       | Publishing results        |
|  6       | Job completed             |
|  7       | Job stopped               |
|  8       | Job deleted successfully  |


The `output` section required in creating a new compute job looks like this:
```json
{
    "nodeUri": "https://node.oceanprotocol.com",
    "providerUri": "https://provider-service..oceanprotocol.com",
    "providerAddress": "0x01011010101101010993433",
    "metadata": {"name": "Workflow output"},
    "metadataUri": "https://aquarius-service.oceanprotocol.com",
    "owner": "0x24f432aab0e22",
    "publishOutput": 1,
    "publishAlgorithmLog": 1
}
```


## Create new job or restart an existing stopped job

### POST /api/services/compute

Start a new job

Parameters
```
    signature: String object containg user signature (signed message) (required)
    consumerAddress: String object containing consumer's ethereum address (required)
    nonce: Integer, Nonce (required)
    dataset: Json object containing dataset information
        dataset.documentId: String, object containing document id (e.g. a DID) (required)
        dataset.serviceId: String, ID of the service the datatoken is attached to (required)
        dataset.transferTxId: Hex string, the id of on-chain transaction for approval of datatokens transfer
            given to the provider's account (required)
    algorithm: Json object, containing algorithm information
        algorithm.documentId: Hex string, the did of the algorithm to be executed (optional)
        algorithm.meta: Json object, defines the algorithm attributes and url or raw code (optional)

    One of `algorithm.documentId` or `algorithm.meta` is required, `algorithm.documentId` takes precedence
```

Returns:
Array of `status` objects as described above, in this case the array will have only one object


Example:
```
POST /api/compute?signature=0x00110011&documentId=did:op:1111&algorithmDid=0xa203e320008999099000&consumerAddress=0x990922334
```

Response:

```json
[
    {
      "jobId": "0x1111:001",
      "status": 1,
      "statusText": "Job started",
      ...
    }
]
```


## Status and Result


### GET /api/services/compute


Get all jobs and corresponding stats

Parameters
```
    signature: String object containg user signature (signed message)
    documentId: String object containing document did  (optional)
    jobId: String object containing workflowID (optional)
    consumerAddress: String object containing consumer's address (optional)

    At least one parameter from documentId, jobId and owner is required (can be any of them)
```

Returns

Array of `status` objects as described above


Example:
```
GET /api/services/compute?signature=0x00110011&documentId=did:op:1111&jobId=012023
```

Response:

```json
[
      {
        "owner":"0x1111",
        "documentId":"did:op:2222",
        "jobId":"3333",
        "dateCreated":"2020-10-01T01:00:00Z",
        "dateFinished":"2020-10-01T01:00:00Z",
        "status":5,
        "statusText":"Job finished",
        "algorithmLogUrl":"http://example.net/logs/algo.log",
        "resultsUrls":[
            "http://example.net/logs/output/0",
            "http://example.net/logs/output/1"
         ],
         "resultsDid":"did:op:87bdaabb33354d2eb014af5091c604fb4b0f67dc6cca4d18a96547bffdc27bcf"
       },
       {
        "owner":"0x1111",
        "documentId":"did:op:2222",
        "jobId":"3334",
        "dateCreated":"2020-10-01T01:00:00Z",
        "dateFinished":"2020-10-01T01:00:00Z",
        "status":5,
        "statusText":"Job finished",
        "algorithmLogUrl":"http://example.net/logs2/algo.log",
        "resultsUrls":[
            "http://example.net/logs2/output/0",
            "http://example.net/logs2/output/1"
         ],
         "resultsDid":""
       }
 ]
 ```

## Stop


### PUT /api/services/compute

Stop a running compute job.

Parameters
```
    signature: String object containg user signature (signed message)
    documentId: String object containing document did (optional)
    jobId: String object containing workflowID (optional)
    consumerAddress: String object containing consumer's address (optional)

    At least one parameter from documentId,jobId and owner is required (can be any of them)
```

Returns

Array of `status` objects as described above

Example:
```
PUT /api/services/compute?signature=0x00110011&documentId=did:op:1111&jobId=012023
```

Response:

```json
[
    {
      ...,
      "status": 7,
      "statusText": "Job stopped",
      ...
    }
]
```

## Delete

### DELETE /api/services/compute

Delete a compute job and all resources associated with the job. If job is running it will be stopped first.

Parameters
```
    signature: String object containg user signature (signed message)
    documentId: String object containing document did (optional)
    jobId: String object containing workflowId (optional)
    consumerAddress: String object containing consumer's address (optional)

    At least one parameter from documentId, jobId is required (can be any of them)
    in addition to consumerAddress and signature
```

Returns

Array of `status` objects as described above

Example:
```
DELETE /api/services/compute?signature=0x00110011&documentId=did:op:1111&jobId=012023
```

Response:
```json
[
    {
      ...,
      "status": 8,
      "statusText": "Job deleted successfully",
      ...
    }
]
```

### GET /api/services/computeResult

Allows download of asset data file.

Parameters
```
    jobId: String object containing workflowId (optional)
    index: Integer, index of the result to download (optional)
    consumerAddress: String object containing consumer's address (optional)
    nonce: Integer, Nonce (required)
    signature: String object containg user signature (signed message)
```

Returns:
Bytes string containing the compute result.


Example:
```
GET /api/services/computeResult?index=0&consumerAddress=0xA78deb2Fa79463945C247991075E2a0e98Ba7A09&jobId=4d32947065bb46c8b87c1f7adfb7ed8b&nonce=1644317370
```

Response:

```
b'{"result": "0x0000000000000000000000000000000000000000000000000000000000000001"}'
```

### GET /api/services/computeEnvironments

Allows download of asset data file.

Parameters
```
```

Returns:
List of compute environments.


Example:
```
GET /api/services/computeEnvironments
```

Response:

```json
[
    {
        "cpuType":"AMD Ryzen 7 5800X 8-Core Processor"
        "currentJobs":0
        "desc":"This is a mocked enviroment"
        "diskGB":2
        "gpuType":"AMD RX570"
        "id":"ocean-compute"
        "maxJobs":10
        "nCPU":2
        "nGPU":0
        "priceMin":2.3
        "ramGB":1
    },
    ...
]
```