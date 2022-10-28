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
The following messages attached to this status code are:

- **The validUntil value is not correct.**
- **Compute environment does not exist.**
- **DID is not a valid algorithm.**

#### 503 - Service Unavailable

It shows up when Provider server is not responding.




