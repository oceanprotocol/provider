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
**Reason** The `type` from the algorithm's metadata from the algorithm DDO is not specified as `algorithm`.

```python
{
    "algorithm.documentId": "missing"
}
```
**Reason** The `documentId` key is missing from the algorithm's DDO.

```python
{
    "algorithm.transferTxId": "missing"
}
```
**Reason** The `transferTxId` key is missing from the algorithm's DDO.

```python
{
    "algorithm.serviceId": "missing"
}
```
**Reason** The `serviceId` key is missing from the algorithm's DDO.

```python
{
    "algorithm.serviceId": "not_found"
}
```

**Reason** The provided `serviceId` does not exist.

```python
{
    "algorithm.documentId": "did_not_found"
}
```

**Reason** The algorithm's `DID` could not be retrieved from the metadata store,
because the algorithm asset does not exist.

```python
{
    "error": "Asset malformed"
}
```
**Reason** The asset published on chain is malformed, missing some required keys or not compliant with our schemas.

```python
{
    "error": "Asset is not consumable."
}
```

**Reason** Asset's metadata status is not in the range of valid status codes for
assets. The recognized states for the metadata are
defined on our [docs](https://docs.oceanprotocol.com/core-concepts/did-ddo#state).


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
This occurs when both `asset` and `algorithm` are requested by their compute service
which cannot be decrypted by a single provider as how it is supposed to be.

```python
{
    "error": "not_trusted_algo_publisher"
}
```
**Reason** The owner of the algorithm's DDO is not a trusted algorithms publishers list.

```python
{
    "error": "not_trusted_algo"
}
```
**Reason** The algorithm's DID is not a trusted algorithms' dictionary.

```python
{
    "error": "no_publisherTrustedAlgorithms"
}
```
**Reason** The algorithm's key `publisherTrustedAlgorithms` does not exist in the algorithm's DDO.

```python
{
    "error": "algorithm_file_checksum_mismatch"
}
```
**Reason** The `filesChecksum` from the algorithm's DDO is invalid.

```python
{
    "error": "algorithm_container_checksum_mismatch"
}
```
**Reason** The `containerChecksum` from the algorithm's DDO is invalid.

```python
{
    "error": "no_raw_algo_allowed"
}
```
**Reason** Privacy option regarding raw algorithms is disabled.

```python
{
    "algorithm": "in_use_or_not_on_chain"
}
```
**Reason** Validation order for the algorithm failed due to the fact that the algorithm
has already an order in use, or it does not exist on the chain.

```python
{
    "algorithm.": "did_not_found"
}
```
**Reason** Algorithm's DID does not exist in the Metadata store. Also, `url` or `remote`
are missing from algorithm's DDO.

```python
{
    "algorithm.": "meta_oneof_url_rawcode_remote"
}
```
**Reason** Algorithm's DDO does not contain the following keys:

- `url`
- `rawcode`
- `remote`

```python
{
    "algorithm.container": "missing_entrypoint_image_checksum"
}
```
**Reason** Either `entrypoint`, either `image`, or either `checksum` are missing from the container dictionary from the algorithm's
DDO.

```python
{
    "algorithm.container": "checksum_prefix"
}
```
**Reason** Container checksum does not start with the prefix `sha256:`.

```python
{
    "output": "invalid"
}
```
**Reason** The algorithm's validation after the build stage has not been
decoded properly as a dictionary.

##### 1.2 For order fees validation

```python
{
    "order": "fees_not_paid"
}
```
**Reason** Provider fees are not paid.

##### 1.3 For other validation errors

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
**Reason** The compute environment provided by the user does not exist, it is not served by our compute-to-data feature.
The user can use `get_c2d_environments` to check the list of available compute environments.
```python
{
    "error": "DID is not a valid algorithm."
}
```
**Reason** Either the algorithm asset's DID is incorrectly typed, either the algorithm timeout expired.

#### 2. 503 - Service Unavailable

It shows up when Provider server is not responding.


### startCompute

Starts the execution of the workflow and runs the provided algorithm.

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
**Reason** The `type` from the algorithm's metadata from the algorithm DDO is not specified as `algorithm`.

```python
{
    "algorithm.documentId": "missing"
}
```
**Reason** The `documentId` key is missing from the aalgorithm's DDO.

```python
{
    "algorithm.transferTxId": "missing"
}
```
**Reason** The `transferTxId` key is missing from the algorithm's DDO.

```python
{
    "algorithm.serviceId": "missing"
}
```
**Reason** The `serviceId` key is missing from the algorithm's DDO.


```python
{
    "algorithm.documentId": "did_not_found"
}
```

**Reason** The algorithm's `DID` could not be retrieved from the metadata store,
because the algorithm asset does not exist.

```python
{
    "algorithm.serviceId": "not_found"
}
```

**Reason** The provided `serviceId` does not exist.

```python
{
    "error": "Asset malformed"
}
```
**Reason** The asset published on chain is malformed, missing some required keys or not compliant with our schemas.

```python
{
    "error": "Asset is not consumable."
}
```

**Reason** Asset's metadata status is not in the range of valid status codes for
assets. The recognized states for the metadata are
defined on our [docs](https://docs.oceanprotocol.com/core-concepts/did-ddo#state).


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
This occurs when both `asset` and `algorithm` are requested by their compute service
which cannot be decrypted by a single provider as how it is supposed to be.


```python
{
    "error": "not_trusted_algo_publisher"
}
```
**Reason** The owner of the algorithm's DDO is not a trusted algorithms publishers list.

```python
{
    "error": "not_trusted_algo"
}
```
**Reason** The algorithm's DID is not a trusted algorithms' dictionary.

```python
{
    "error": "no_publisherTrustedAlgorithms"
}
```
**Reason** The algorithm's key `publisherTrustedAlgorithms` does not exist in the algorithm's DDO.

```python
{
    "error": "algorithm_file_checksum_mismatch"
}
```
**Reason** The `filesChecksum` from the algorithm's DDO is invalid.

```python
{
    "error": "algorithm_container_checksum_mismatch"
}
```
**Reason** The `containerChecksum` from the algorithm's DDO is invalid.

```python
{
    "error": "no_raw_algo_allowed"
}
```
**Reason** Privacy option regarding raw algorithms is disabled.

```python
{
    "algorithm": "in_use_or_not_on_chain"
}
```
**Reason** Validation order for the algorithm failed due to the fact that the algorithm
has already an order in use, or it does not exist on the chain.

```python
{
    "algorithm.": "did_not_found"
}
```
**Reason** Algorithm's DID does not exist in the Metadata store. Also, `url` or `remote`
are missing from algorithm's DDO.

```python
{
    "algorithm.": "meta_oneof_url_rawcode_remote"
}
```
**Reason** Algorithm's DDO does not contain the following keys:

- `url`
- `rawcode`
- `remote`

```python
{
    "algorithm.container": "missing_entrypoint_image_checksum"
}
```
**Reason** Either `entrypoint`, either `image`, or either `checksum` are missing from the container dictionary from the algorithm's
DDO.

```python
{
    "algorithm.container": "checksum_prefix"
}
```
**Reason** Container checksum does not start with the prefix `sha256:`.

```python
{
    "output": "invalid"
}
```
**Reason** The algorithm's validation after the build stage has not been
decoded properly as a dictionary.

##### 1.2 For order fees validation

```python
{
    "order": "fees_not_paid"
}
```
**Reason** Provider fees are not paid.

#### 2. 401 - Consumer signature is invalid

Consumer signature is invalid or failed verification when the job was submitted to
operator-service.

#### 3. 503 - Service Unavailable

It shows up when Provider server is not responding.