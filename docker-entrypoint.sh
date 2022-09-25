#!/bin/sh
##
## Copyright 2021 Ocean Protocol Foundation
## SPDX-License-Identifier: Apache-2.0
##

export PROVIDER_CONFIG_FILE=/ocean-provider/config.ini
export PROVIDER_ADDRESS=0x1BDD96Fa11b44b392B6A760640A34504585c3b29
export PROVIDER_PRIVATE_KEY=d1006524a22f4b6dce69dc8e8a05e016b811600ed6eec40fed069255119ac1ed
export OPERATOR_SERVICE_URL=http://af31ae3550deb4f1bbc7118d4f744469-2129339766.us-east-1.elb.amazonaws.com:9000
export ADDRESS_FILE=address.json
export IPFS_GATEWAY=http://44.193.74.142:8080
export AUTHORIZED_DECRYPTERS=[]
export LOG_LEVEL=DEBUG

if [ "${DEPLOY_CONTRACTS}" = "true" ]; then
  while [ ! -f "/ocean-contracts/artifacts/ready" ]; do
    sleep 2
  done
fi

/bin/cp -up /ocean-provider/artifacts/* /usr/local/artifacts/ 2>/dev/null || true

gunicorn -b 0.0.0.0:8030 -w 1 -t 9000 ocean_provider.run:app
tail -f /dev/null
