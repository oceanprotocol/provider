<!--
Copyright 2021 Ocean Protocol Foundation
SPDX-License-Identifier: Apache-2.0
-->

# Possible errors returned by Provider

This document reflects couple of the possible errors returned by Provider.
## Compute routes

### initializeCompute

In order to consume a data service the user is required to send
one datatoken to the provider, as well as provider fees for the compute job.

#### 1. 400 - Bad Request

It occurs when the validation part fails.
The following errors are displayed in JSON format:

##### 1.1 For algorithm validation
```python
{
    "additional_input": "invalid"
}
```
**Reason** The `additional_inputs` key is not a list.

```python
{
    "algorithm": "missing_meta_documentId"
}
```
**Reason** Either algorithm metadata, either algorithm DID is missing.

```python
{
    "algorithm": "file_unavailable"
}
```
**Reason** One possibility is that the asset could not be retrieved from Aquarius's database.
Otherwise, there are issues related to `services`, such as:
- particular `service` is not found


- `Key <key> not found in files.` - `datatokenAddress` or `nftAddress` or `files` is missing
the decrypted files object


- `Mismatch of datatoken.` - mismatch between service datatoken & decrypted files datatoken;


- `Mismatch of dataNft.` - mismatch between asset data NFT address & the one from the decrypted files;


- `Expected a files list` - `files` is not a list;


- `Error decrypting service files` - other errors for decrypting the file.

```python
{
    "algorithm": "not_algo"
}
```
**Reason** The `type` from the algorithm's metadata is not specified as `algorithm`.


```python
{
    "algorithm.serviceId": "missing"
}
```
or

```python
{
    "algorithm.serviceId": "not_found"
}
```

**Reason** The `serviceId` key is missing from the algorithm's DDO.

```python
{
    "algorithm.documentId": "did_not_found"
}
```

**Reason** The asset `DID` could not be retrieved from the metadata store.

```python
{
    "error": "Asset malformed"
}
```
**Reason** Data NFT address is not present in the asset object.

```python
{
    "error": "Asset is not consumable."
}
```

**Reason** Metadata status is not in the range of valid status codes for
assets.

```python
{
    "error": "Error: Access to asset <DID> was denied with code: <code>."
}
```
**Reason** Asset cannot be accessed due to error status code.

```python
{
    "algorithm.serviceId": "service_not_access_compute"
}
```

**Reason** Service type is neither `access`, nor `compute`.

```python
{
    "algorithm.serviceId": "main_service_compute"
}
```

**Reason** If the main service is not `compute` for this asset when calling `initialize`
endpoint.

```python
{
    "algorithm.serviceId": "compute_services_not_in_same_provider"
}
```

**Reason** Files attached to the compute service are not decrypted by the correct provider.

```python
{
    "error": "The validUntil value is not correct."
}
```
**Reason** `validUntil` value is most probably expired.

```python
{
    "error": "Compute environment does not exist."
}
```
**Reason** If you are trying to initialize a compute service, the compute values need to be provided.
```python
{
    "error": "DID is not a valid algorithm."
}
```
**Reason** Either the DID is incorrect typed, either the algorithm timeout expired.

#### 2. 503 - Service Unavailable

It shows up when Provider server is not responding.




