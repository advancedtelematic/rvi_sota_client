#!/bin/bash

set -eo pipefail


CONFIG_PATH="${CONFIG_PATH:-/tmp/sota.toml}"
AUTH_SERVER="${AUTH_SERVER:-http://localhost:9001}"
CORE_SERVER="${CORE_SERVER:-http://localhost:8001}"
REGISTRY_SERVER="${REGISTRY_SERVER:-http://localhost:8083}"
PACKAGE_MANAGER="${PACKAGE_MANAGER:-deb}"


function start_client() {
  export RUST_LOG="${RUST_LOG:-debug}"
  export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

  sota_client --print --config="${CONFIG_PATH}"
  exec sota_client --config="${CONFIG_PATH}"
}

function start_dbus() {
    eval "$(dbus-launch)"
    export DBUS_SESSION_BUS_ADDRESS
    export DBUS_SESSION_BUS_PID
}

function generate_config() {
  vin=${DEVICE_VIN:-TEST$(< /dev/urandom tr -dc A-HJ-NPR-Z0-9 | head -c 13 || [[ $? -eq 141 ]])}
  uuid=${DEVICE_UUID:-$(curl -f -XPOST -H "Content-Type: application/json" "${REGISTRY_SERVER}/api/v1/devices" \
    -d "{ \"deviceName\": \"${vin}\", \"deviceId\": \"${vin}\", \"deviceType\": \"Vehicle\" }" | tr -d '"')}

  cat << EOF > "${CONFIG_PATH}"
[core]
server = "${CORE_SERVER}"

[device]
uuid = "${uuid}"
package_manager = "${PACKAGE_MANAGER}"
EOF

  # optionally add an auth section
  [[ -z "${AUTH_CLIENT_ID}" ]] || {
      cat << EOF >> "${CONFIG_PATH}"
[auth]
server = "${AUTH_SERVER}"
client_id = "${AUTH_CLIENT_ID}"
client_secret = "${AUTH_CLIENT_SECRET}"
EOF
  }
}


[[ -e "${CONFIG_PATH}" ]] || generate_config
[[ -n "${DBUS_SESSION_BUS_ADDRESS}" ]] || start_dbus
start_client
