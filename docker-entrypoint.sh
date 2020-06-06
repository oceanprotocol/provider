#!/bin/sh

export CONFIG_FILE=/provider/config.ini
envsubst < /provider/config.ini.template > /provider/config.ini
if [ "${LOCAL_CONTRACTS}" = "true" ]; then
  echo "Waiting for contracts to be generated..."
  while [ ! -f "/usr/local/keeper-contracts/ready" ]; do
    sleep 2
  done
fi

/bin/cp -up /usr/local/keeper-contracts/* /usr/local/artifacts/ 2>/dev/null || true

gunicorn -b ${OCEAN_PROVIDER_URL#*://} -w ${OCEAN_PROVIDER_WORKERS} -t ${OCEAN_PROVIDER_TIMEOUT} ocean_provider.run:app
tail -f /dev/null
