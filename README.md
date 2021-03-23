<!--
Copyright 2021 Ocean Protocol Foundation
SPDX-License-Identifier: Apache-2.0
-->
[![banner](https://raw.githubusercontent.com/oceanprotocol/art/master/github/repo-banner%402x.png)](https://oceanprotocol.com)

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/286c8284fd0140d294d0933f6578b3ad)](https://www.codacy.com/gh/oceanprotocol/provider/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=oceanprotocol/provider&amp;utm_campaign=Badge_Grade) [![Codacy Badge](https://app.codacy.com/project/badge/Coverage/286c8284fd0140d294d0933f6578b3ad)](https://www.codacy.com/gh/oceanprotocol/provider/dashboard?utm_source=github.com&utm_medium=referral&utm_content=oceanprotocol/provider&utm_campaign=Badge_Coverage)  [![GitHub contributors](https://img.shields.io/github/contributors/oceanprotocol/provider.svg)](https://github.com/oceanprotocol/provider/graphs/contributors)

# provider
REST API for provider of data services

This is part of the Ocean Protocol V3 tools.

This is feature complete and is a BETA version.

## Starting the server locally

### Quick start
Uses the rinkeby network with a remote metadatastore instance running at https://aquarius.marketplace.dev-ocean.com

```bash
git clone git@github.com:oceanprotocol/provider.git
cd provider/

virtualenv venv -p python3.8
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
CONFIG_FILE=config.ini
PROVIDER_ADDRESS=your ethereum address goes here
# Set one of the following
PROVIDER_KEY=the private key
PROVIDER_ENCRYPTED_KEY=The encrypted key json from the keyfile
PROVIDER_KEYFILE=path to the keyfile which has the encrypted key
# and set the password if using either PROVIDER_KEYFILE or PROVIDER_ENCRYPTED_KEY
PROVIDER_PASSWORD=password to allow decrypting the encrypted key
```

You might also want to set `FLASK_ENV=development`. Then run ```flask run --port=8030```

Refer to the [API.md](API.md) file for endpoints and payloads.

#### Before you commit
If you are a contributor, make sure you install the pre-commit hooks using the command `pre-commit install`. This will make sure your imports are sorted and your code is properly formatted before committing. We use `black`, `isort` and `flake8` to keep code clean.

Licensing your commits is also available: use the command `licenseheaders -t .copyright.tmpl -x venv` (or replace "venv" with your local virtual environment path). This option is not available as a precommit since it takes longer.
