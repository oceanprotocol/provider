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

#### 400 - Bad Request

It occurs when the payload is incorrect, either at least one parameter is missing.
The following errors are displayed in JSON format:

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

#### 503 - Service Unavailable

It shows up when Provider server is not responding.




