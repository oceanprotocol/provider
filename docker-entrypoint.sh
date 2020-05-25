#!/bin/sh

export CONFIG_FILE=/brizo/config.ini
envsubst < /brizo/config.ini.template > /brizo/config.ini
if [ "${LOCAL_CONTRACTS}" = "true" ]; then
  echo "Waiting for contracts to be generated..."
  while [ ! -f "/usr/local/keeper-contracts/ready" ]; do
    sleep 2
  done
fi

/bin/cp -up /usr/local/keeper-contracts/* /usr/local/artifacts/ 2>/dev/null || true

gunicorn -b ${BRIZO_URL#*://} -w ${BRIZO_WORKERS} -t ${BRIZO_TIMEOUT} brizo.run:app
tail -f /dev/null
