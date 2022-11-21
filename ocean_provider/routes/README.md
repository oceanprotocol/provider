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
- particular `service` is not found;
- `datatokenAddress`, `nftAddress`, `files` information are missing from the
decrypted files object.

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
**Reason** The `serviceId` key is missing from the algorithm's DDO.






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




