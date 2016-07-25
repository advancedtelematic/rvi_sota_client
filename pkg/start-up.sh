#!/bin/bash

set -eo pipefail

# FIXME(PRO-820): allow authentcation again via an environment variable

export OTA_CONSOLE=${OTA_CONSOLE-false}
export OTA_HTTP=${OTA_HTTP-false}
export OTA_WEBSOCKET=${OTA_WEBSOCKET-true}

export OTA_CORE_URL=${OTA_CORE_URL-http://localhost:8080}
export OTA_REGISTRY_URL=${OTA_REGISTRY_URL-http://localhost:8083}
export OTA_WEB_URL=${OTA_WEB_URL-http://localhost:9000}

export PACKAGE_MANAGER=${PACKAGE_MANAGER-'dpkg'}

DEVICES_PATH="/api/v1/devices"

# generate device ids
RANDOM_VIN="TEST$(< /dev/urandom tr -dc A-HJ-NPR-Z0-9 | head -c 13; echo;)"
export OTA_CLIENT_VIN=${OTA_CLIENT_VIN-$RANDOM_VIN}

if [[ -n $DONT_ADD_DEVICE ]]; then
    if [ -z ${OTA_DEVICE_UUID} ]; then

        URL="${OTA_CONSUL_URL}/v1/kv/uuid$OTA_CLIENT_NUM"

        echo "waiting for uuid on $URL"
        until RESP=$(curl -s --output /dev/null --write-out %{http_code} $URL); [ $RESP -eq 200 ]; do
            printf '.'
            sleep 1
        done

        OTA_DEVICE_UUID=$(curl -Ssf $URL | jq -r ".[].Value" | base64 --decode)
    fi
else
    # Add device to ota-plus web
    OTA_DEVICE_UUID=$(http --check-status --ignore-stdin \
                           ${OTA_REGISTRY_URL}${DEVICES_PATH} \
                           deviceName=${OTA_CLIENT_VIN} \
                           deviceId=${OTA_CLIENT_VIN} \
                           deviceType=Vehicle | cut -c2-37)
    echo "created device $OTA_DEVICE_UUID"
fi

export OTA_DEVICE_UUID

if [[ -n $PROVISION ]]; then
  export OTA_CREDENTIALS_FILE=${OTA_CREDENTIALS_FILE-credentials.toml}
else
  export OTA_CREDENTIALS_FILE=${OTA_CREDENTIALS_FILE-/opt/ats/credentials.toml}
fi

TEMPLATE_PATH=${TEMPLATE_PATH-'/etc/sota.toml.template'}
OUTPUT_PATH=${OUTPUT_PATH-/etc/sota.toml}

if [[ -n "${OTA_NO_AUTH}" ]]; then
  sed -i '1,/\[device\]/{/\[device\]/p;d}' "${TEMPLATE_PATH}"
fi

if [[ -n $PROVISION ]]; then
  SOTA_TOML=$(cat $TEMPLATE_PATH | envsubst )
  echo "$SOTA_TOML"
else
  SOTA_TOML=$(cat $TEMPLATE_PATH | envsubst > $OUTPUT_PATH)
  cat $OUTPUT_PATH
  RUST_LOG=${RUST_LOG-debug} sota_client --config=/etc/sota.toml
fi
