# provider-py
REST API for provider of data services

This is part of the Ocean Protocol V3 tools.

This is feature complete and is a BETA version.  

## Starting the server locally

### Quick start
Uses the rinkeby network with a remote metadatastore instance running at https://aquarius.marketplace.dev-ocean.com 

```bash
git clone git@github.com:oceanprotocol/provider-py.git
cd provider-py/

virtualenv venv -p python3.6
source venv/bin/activate 

pip install -r requirements_dev.txt
export FLASK_APP=ocean_provider/run.py
export CONFIG_FILE=config.ini
export PROVIDER_ADDRESS="068ed00cf0441e4829d9784fcbe7b9e26d4bd8d0"
export PROVIDER_PASSWORD="secret"
export PROVIDER_KEYFILE="tests/resources/provider_key_file.json"
export AQUARIUS_URL="https://aquarius.marketplace.dev-ocean.com"

export PARITY_ADDRESS1="0x00bd138abd70e2f00903268f3db08f2d25677c9e"
export PARITY_PASSWORD1="node0"
export PARITY_KEYFILE1="tests/resources/consumer_key_file.json"

flask run --port=8030

```

### Detailed steps

#### 1. Clone the repo
```bash
git clone git@github.com:oceanprotocol/provider-py.git
cd provider-py/
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
```bash
export FLASK_APP=ocean_provider/run.py
export CONFIG_FILE=config.ini
export PROVIDER_ADDRESS="your ethereum address goes here"
# Set one of the following
export PROVIDER_KEY="the private key"
export PROVIDER_ENCRYPTED_KEY="The encrypted key json from the keyfile"
export PROVIDER_KEYFILE="path to the keyfile which has the encrypted key"
# and set the password if using either PROVIDER_KEYFILE or PROVIDER_ENCRYPTED_KEY
export PROVIDER_PASSWORD="password to allow decrypting the encrypted key"

flask run --port=8030
```

Refer to the [API.md](API.md) file for endpoints and payloads.
