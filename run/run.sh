#!/bin/bash

set -eo pipefail

# set default environment variables
AUTH_SECTION="${AUTH_SECTION:-false}"
AUTH_SERVER="${AUTH_SERVER:-http://localhost:9001}"
CORE_SERVER="${CORE_SERVER:-http://localhost:8080}"
OUTPUT_PATH="${OUTPUT_PATH:-/etc/sota.toml}"
REGISTRY_SERVER="${REGISTRY_SERVER:-http://localhost:8083}"
TEMPLATE_PATH="${TEMPLATE_PATH:-/etc/sota.toml.template}"

# generate or use existing device vin
RAND=$(< /dev/urandom tr -dc A-HJ-NPR-Z0-9 | head -c 13 || [[ $? -eq 141 ]])
export DEVICE_VIN=${DEVICE_VIN:-"TEST${RAND}"}

# create or use existing device uuid
if [[ -z "${DEVICE_UUID}" ]]; then
    DEVICE_UUID=$(http post "${REGISTRY_SERVER}/api/v1/devices" \
                       deviceName="${DEVICE_VIN}" \
                       deviceId="${DEVICE_VIN}" \
                       deviceType=Vehicle \
                       --check-status --print=b \
                      | tr -d '"')
fi
export DEVICE_UUID

[[ "${AUTH_SECTION}" = true ]] && {
    # create or use existing device credentials
    if [[ -z "${AUTH_CLIENT_ID}" ]]; then
        CREDENTIALS=$(http post "${AUTH_SERVER}/clients" \
                           client_name="${DEVICE_VIN}" \
                           grant_types:='["client_credentials"]' \
                           scope="ota-core.$DEVICE_UUID.write ota-core.$DEVICE_UUID.read" \
                           --check-status --print=b)
        AUTH_CLIENT_ID=$(echo "${CREDENTIALS}" | jq -r .client_id)
        AUTH_CLIENT_SECRET=$(echo "${CREDENTIALS}" | jq -r .client_secret)
    fi
    export AUTH_CLIENT_ID
    export AUTH_CLIENT_SECRET
} || {
    # remove [auth] section
    sed -i '/\[core\]/,$!d' "${TEMPLATE_PATH}"
}

# generate sota.toml config
echo "---START CONFIG---"
envsubst < "${TEMPLATE_PATH}" | tee "${OUTPUT_PATH}"
echo "---END CONFIG---"
[[ "${CONFIG_ONLY}" = true ]] && exit 0

# set up dbus
eval "$(dbus-launch)"
export DBUS_SESSION_BUS_ADDRESS
export DBUS_SESSION_BUS_PID

# start client
RUST_LOG="${RUST_LOG:-debug}" sota_client --config="${OUTPUT_PATH}"
