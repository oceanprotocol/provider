export PROVIDER_CONFIG_FILE=config.ini
export PROVIDER_ADDRESS=<etheruem address>
export PROVIDER_PRIVATE_KEY=<private key>
export TEST_PRIVATE_KEY1=<private key>
export TEST_PRIVATE_KEY2=<private key>
export OPERATOR_SERVICE_URL=http://<operator service api>
export ADDRESS_FILE=~/contracts/addresses/address.json
export IPFS_GATEWAY=http://127.0.0.1:8080
export AUTHORIZED_DECRYPTERS=[]
export LOG_LEVEL=DEBUG

# Start Flask server
export FLASK_ENV=development
export FLASK_APP=ocean_provider/run.py
flask run --host=0.0.0.0 --port=8030
