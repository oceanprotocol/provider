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
### GET /api/v1/services/nonce
Parameters
```
    userAddress: String object containing a user's ethereum address
```

Returns:
Json object containing the nonce value.

Example:
```
POST /api/v1/services/nonce?userAddress=0x990922334

```

Response:

```json
{
  "nonce": 23
}
```

## Encrypt endpoint

### GET /api/v1/services/encrypt
Parameters
```
    documentId: String object containing document id (e.g. a DID)
    signature: String object containg user signature (signed message)
    publisherAddress: String object containing publisher's ethereum address
    document: String, representing the list of `file` objects that describe each file in the dataset
```

Returns:
Json object containing the encrypted document.


Example:
```
POST /api/v1/services/encrypt
payload:
{
    "signature":"0x00110011",
    "documentId":"0x1111",
    "publisherAddress":"0x990922334",
    "document":"[{index:0, url:""}, {index:1, url:""}]"
}
```

Response:

```json
{
  "encryptedDocument": ""
}
```



## Initial service request endpoint
### POST /api/v1/services/initialize
Parameters
```
    documentId: String object containing document id (e.g. a DID)
    serviceId: String, representing the list of `file` objects that describe each file in the dataset
    serviceType: String such as "access" or "compute"
    consumerAddress: String object containing publisher's ethereum address
```

Returns:
Json document with a quote for amount of tokens to transfer to the provider account.


Example:
```
POST /api/v1/services/initialize
payload:
{
    "documentId":"0x1111",
    "serviceId": 0,
    "serviceType": "access",
    "dataToken": "",
    "consumerAddress":"0x990922334",
```

Response:

```json
{
    "from": "0x...",
    "to": "0x...",
    "numTokens": 21,
    "dataToken": "0x21fa3ea32892091...",
    "nonce": 23
}
```


## Download endpoint
### GET /api/v1/services/download
Parameters
```
    documentId: String object containing document id (e.g. a DID)
    serviceId: String, representing the list of `file` objects that describe each file in the dataset
    serviceType: String such as "access" or "compute"
    fileIndex: integer, the index of the file from the files list in the dataset
    signature: String object containg user signature (signed message)
    consumerAddress: String object containing publisher's ethereum address
    transactionId: Hex string -- the id of on-chain transaction for approval of DataTokens transfer 
        given to the provider's account
```

Returns:
File stream


Example:
```
POST /api/v1/services/download
payload:
{
    "documentId":"0x1111",
    "serviceId": 0,
    "serviceType": "access",
    "fileIndex": 0,
    "dataToken": "",
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

## Compute endpoints
All compute endpoints respond with an Array of status objects, each object 
describing a compute job info. 

Each status object will contain:
```
    owner:The owner of this compute job
    documentId:
    jobId:
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

### POST /api/v1/services/compute

Start a new job

Parameters
```
    signature: String object containg user signature (signed message)
    documentId: String object containing the document did
    consumerAddress: String object containing consumer's ethereum address
    output: json object that define the output section, i.e. attributes of the compute results
    algorithmDid: hex str the did of the algorithm to be executed
    algorithmMeta: json object that define the algorithm attributes and url or raw code
    jobId: String object containing workflowID (optional)
    transferTxId: hex str the transaction id (hash) of the token transfer, must match the 
        amount of data tokens expressed in the `initialize` endpoint  
    serviceId: integer identifies a service in the list of services in the DDO document
    serviceType: type of service that serviceId refers to, must be `compute` in this case
    dataToken: hex str the ERC20 contract address of the DataToken attached to the documentId (did)

    One of `algorithmDid` or `algorithmMeta` is required, `algorithmDid` takes precedence
```

Returns:
Array of `status` objects as described above, in this case the array will have only one object


Example:
```
POST /api/v1/compute?signature=0x00110011&documentId=did:op:1111&algorithmDid=0xa203e320008999099000&consumerAddress=0x990922334
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
  
  
### GET /api/v1/services/compute
   
   
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
GET /api/v1/services/compute?signature=0x00110011&documentId=did:op:1111&jobId=012023
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
  
  
### PUT /api/v1/services/compute

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
PUT /api/v1/services/compute?signature=0x00110011&documentId=did:op:1111&jobId=012023
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

### DELETE /api/v1/services/compute

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
DELETE /api/v1/services/compute?signature=0x00110011&documentId=did:op:1111&jobId=012023
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
