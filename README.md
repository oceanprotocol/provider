<!--
Copyright 2022 Ocean Protocol Foundation
SPDX-License-Identifier: Apache-2.0
-->
[![banner](https://raw.githubusercontent.com/oceanprotocol/art/master/github/repo-banner%402x.png)](https://oceanprotocol.com)

[![Maintainability](https://api.codeclimate.com/v1/badges/6f5987cfdd2fd265047b/maintainability)](https://codeclimate.com/github/oceanprotocol/provider/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/6f5987cfdd2fd265047b/test_coverage)](https://codeclimate.com/github/oceanprotocol/provider/test_coverage)
[![GitHub contributors](https://img.shields.io/github/contributors/oceanprotocol/provider.svg)](https://github.com/oceanprotocol/provider/graphs/contributors)

# Provider
REST API for provider of data services

This is part of the Ocean Protocol V3 tools.

This is feature complete and is a BETA version.

## What Provider does:

- The only component that can access your data
- Performs checks on chain for buyer permissions and payments
- Encrypts the URL and metadata during publish
- Decrypts the URL when the dataset is downloaded or a compute job is started
- Provides access to data assets by streaming data (and never the URL)
- Provides compute services (connects to C2D environment)
- Typically run by the Data Provider

### Technology used:

Python Flask HTTP server

## Starting the server locally

### Quick start
Uses the rinkeby network with a remote metadatastore instance running at https://aquarius.marketplace.dev-ocean.com

```bash
git clone git@github.com:oceanprotocol/provider.git
cd provider/

python3 -m venv venv
source venv/bin/activate

pip install -r requirements_dev.txt
cp .env.example .env

flask run --port=8030

```

### Detailed steps

#### 1. Clone the repo
```bash
git clone git@github.com:oceanprotocol/provider.git
cd provider/
```

#### 2. Virtual env (optional)
Before running it locally we recommend to set up virtual environment:

```bash
virtualenv venv -p python3.8
# OR: python -m venv venv
source venv/bin/activate
```

#### 3. Requirements

Install all the requirements:

```
pip install -r requirements_dev.txt
```

#### 4. Dependencies

*Metadata store (Aquarius).* Do one of the following:
* Run Aquarius locally, see https://github.com/oceanprotocol/aquarius
* Point to a remote instance such as `https://aquarius.marketplace.dev-ocean.com`.
In this case replace the `aquarius.url` option in the `config.ini` file with the appropriate URL.


*Ethereum network.* Do one of the following:
* Run ganache-cli
* Point to rinkeby testnet or any other ethereum network

Make sure that ocean contracts (https://github.com/oceanprotocol/contracts) are deployed to the your network of choice.
Update the `network` option in the `config.ini` file with the proper network URL. For now it must be a URL, a simple network name (e.g. mainnet) will be supported in the future.

#### 5. Start the provider server
Add the corresponding environment variables in your `.env` file. Here is an example:

```
FLASK_APP=ocean_provider/run.py
PROVIDER_CONFIG_FILE=config.ini
PROVIDER_ADDRESS=your ethereum address goes here
PROVIDER_PRIVATE_KEY=the private key
PROVIDER_FEE_TOKEN = address of ERC20 token used to get fees
```

You might also want to set `FLASK_ENV=development`. Then run ```flask run --port=8030```

Refer to the [API.md](API.md) file for endpoints and payloads.

##### Environment variables
* `REQUEST_RETRIES` defines the number of times file downloads are tried, accounting got network glitches and connectivity issues. Defaults to 1 (one trial, meaning no retries).
* `RBAC_SERVER_URL` defines the URL to the RBAC permissions server. Defaults to None (no special permissions).
* `PRIVATE_PROVIDER` if set, adds a "providerAccess": "private" key-value pair to RBAC requests
* `REDIS_CONNECTION` defines a connection URL to Redis. Defaults to None (no Redis connection, SQLite database is used instead)
* `TEST_PRIVATE_KEY1` and `TEST_PRIVATE_KEY2` are private wallet keys for publisher and consumer tests.
* `OPERATOR_SERVICE_URL` defines connection to C2D
* `LOG_CFG` and `LOG_LEVEL` define the location of the log file and logging leve, respectively
* `IPFS_GATEWAY` defines ipfs gateway for resolving urls
* `AUTHORIZED_DECRYPTERS` list of authorized addresses that are allowed to decrypt chain data. Use it to restrict access only to certain callers (e.g. custom Aquarius instance). Empty by default, meaning all decrypters are authorized.
* `USE_CHAIN_PROOF` or `USE_HTTP_PROOF` set a mechanism for saving proof-of-download information. For any present true-ish value of `USE_CHAIN_PROOF`, the proof is sent on-chain. When defining `USE_HTTP_PROOF` the env var must configure a HTTP endpoint that accepts a POST request.
* `IS_POA_NETWORK` define that the network used is POA style, requiring special middlewares


#### Before you commit
If you are a contributor, make sure you install the pre-commit hooks using the command `pre-commit install`. This will make sure your imports are sorted and your code is properly formatted before committing. We use `black`, `isort` and `flake8` to keep code clean.

Licensing your commits is also available: use the command `licenseheaders -t .copyright.tmpl -x venv` (or replace "venv" with your local virtual environment path). This option is not available as a precommit since it takes longer.

#### Versioning and releases
To release a new version of Provider, please follow the steps decribed in [the release process](release-process.md)
