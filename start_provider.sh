# Export env vars
export PROVIDER_CONFIG_FILE=config.ini
export AUTH_TOKEN_EXPIRATION=3153600000
export PROVIDER_PRIVATE_KEY=0xfd5c1ccea015b6d663618850824154a3b3fb2882c46cefb05b9a93fea8c3d215
export TEST_PRIVATE_KEY1=0xef4b441145c1d0f3b4bc6d61d29f5c6e502359481152f869247c7a4244d45209
export TEST_PRIVATE_KEY2=0x5d75837394b078ce97bc289fa8d75e21000573520bfa7784a9d28ccaae602bf8
export OPERATOR_SERVICE_URL=https://c2d-dev.operator.oceanprotocol.com/
export ADDRESS_FILE=~/.ocean/ocean-contracts/artifacts/address.json
export IPFS_GATEWAY=http://172.15.0.16:8080
export PROVIDER_IPFS_GATEWAY=http://172.15.0.16:8080
export AUTHORIZED_DECRYPTERS=[]

# Start Flask server
export FLASK_ENV=development
export FLASK_APP=ocean_provider/run.py
flask run --port=8030