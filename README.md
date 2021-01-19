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

virtualenv venv -p python3.6
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
virtualenv venv -p python3.6
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

#### Installing the git pre-commit hook (recommended)
`flake8 --install-hook git`
`git config --bool flake8.strict true`

You can also run isort to order imports `isort {file_path}`
