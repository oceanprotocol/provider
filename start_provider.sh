export PROVIDER_CONFIG_FILE=config.ini
export PROVIDER_ADDRESS=0x1BDD96Fa11b44b392B6A760640A34504585c3b29
#export OPERATOR_SERVICE_URL=http://127.0.0.1:8050
export OPERATOR_SERVICE_URL=http://af31ae3550deb4f1bbc7118d4f744469-2129339766.us-east-1.elb.amazonaws.com:9000
export ADDRESS_FILE=address.json
export IPFS_GATEWAY=http://3.95.217.98:8080
export AUTHORIZED_DECRYPTERS=[]
export LOG_LEVEL=DEBUG

# Start Flask server
export FLASK_ENV=development
export FLASK_APP=ocean_provider/run.py
flask run --host=0.0.0.0 --port=8030
