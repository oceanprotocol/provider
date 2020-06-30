# Ocean Provider Endpoints Specification

This document specifies the endpoints for Ocean Provider to be implemented by the core 
developers. The final implementation and its documentation happens in Swagger 
inline code comments and the latest implemented API documentation can be 
accessed via:

- [Docs: Provider API Reference](https://docs.oceanprotocol.com/references/ocean_provider/)


## Encrypt endpoint

### GET /api/v1/service/encrypt
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
POST /api/v1/service/encrypt
payload:
{
    "signature":"0x00110011",
    "documentId":"0x1111",
    "publisherAddress":"0x990922334",
    "document":"[{index:0, url:""}, {index:1, url:""}]"
```

Response:

```json
{
  "encryptedDocument": ""
}
```



## Initial service request endpoint
### POST /api/v1/service/initialize
Parameters
```
    documentId: String object containing document id (e.g. a DID)
    serviceId: String, representing the list of `file` objects that describe each file in the dataset
    serviceType: String such as "access" or "compute"
    consumerAddress: String object containing publisher's ethereum address
```

Returns:
Json document with the token approveAndLock transaction parameters


Example:
```
POST /api/v1/service/initialize
payload:
{
    "documentId":"0x1111",
    "serviceId": 0,
    "serviceType": "access",
    "tokenAddress": "",
    "consumerAddress":"0x990922334",
```

Response:

```json
{
    "from": "0x...",
    "to": "0x...",
    "numTokens": 21,
    "dataTokenAddress": "0x21fa3ea32892091...",
}
```


## Download endpoint
### GET /api/v1/service/download
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
POST /api/v1/service/download
payload:
{
    "documentId":"0x1111",
    "serviceId": 0,
    "serviceType": "access",
    "fileIndex": 0,
    "tokenAddress": "",
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
