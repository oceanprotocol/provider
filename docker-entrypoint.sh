#!/bin/sh
##
## Copyright 2021 Ocean Protocol Foundation
## SPDX-License-Identifier: Apache-2.0
##

export CONFIG_FILE=/ocean-provider/config.ini
envsubst < /ocean-provider/config.ini.template > /ocean-provider/config.ini

if [ "${DEPLOY_CONTRACTS}" = "true" ]; then
  while [ ! -f "/ocean-contracts/artifacts/ready" ]; do
    sleep 2
  done
fi

/bin/cp -up /ocean-provider/artifacts/* /usr/local/artifacts/ 2>/dev/null || true

gunicorn -b ${OCEAN_PROVIDER_URL#*://} -w ${OCEAN_PROVIDER_WORKERS} -t ${OCEAN_PROVIDER_TIMEOUT} ocean_provider.run:app
tail -f /dev/null
