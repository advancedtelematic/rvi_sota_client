#!/bin/bash

set -xeo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <package> [<destination>]"
  echo "packages: deb rpm"
  exit 1
fi

: "${PACKAGE_VERSION:?'Environment variable PACKAGE_VERSION must be set.'}"

PACKAGE_NAME="${PACKAGE_NAME-sota_client}"
PACKAGE_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFIX=/opt/ats

export OTA_AUTH_URL="${OTA_AUTH_URL-http://localhost:9001}"
export OTA_CORE_URL="${OTA_CORE_URL-http://localhost:8080}"
export OTA_CREDENTIALS_FILE="${OTA_CREDENTIALS_FILE-${PREFIX}/credentials.toml}"
export OTA_CONSOLE="${OTA_CONSOLE-false}"
export OTA_HTTP="${OTA_HTTP-false}"
export OTA_WEBSOCKET="${OTA_WEBSOCKET-true}"

case $1 in
  "deb" )
    export PACKAGE_MANAGER="deb"
    PKG_BUILD_OPTS="--deb-systemd ${PACKAGE_DIR}/sota_client.service"
    ;;
  "rpm" )
    export PACKAGE_MANAGER="rpm"
    PKG_BUILD_OPTS="--rpm-service ${PACKAGE_DIR}/sota_client.service"
    ;;
  *)
    echo "unknown package format $1"
    exit 2
esac
shift

function make_pkg {
  destination=$1
  template=$(mktemp)

  envsubst < "${PACKAGE_DIR}/sota.toml.template" > "${template}"
  if [[ -n "${OTA_NO_AUTH}" ]]; then
    sed -i '1,/\[device\]/{/\[device\]/p;d}' "${template}"
  fi
  chmod 600 "$template"

  fpm \
    -s dir \
    -t "${PACKAGE_MANAGER}" \
    --architecture native \
    --name "${PACKAGE_NAME}" \
    --version "${PACKAGE_VERSION}" \
    --package NAME-VERSION.TYPE \
    --prefix "${PREFIX}" \
    ${PKG_BUILD_OPTS} \
    "${PACKAGE_DIR}/sota_client=sota_client" \
    "${template}=sota.toml"

  if [ -n "$destination" ]; then
    mv -f "sota_client*.${PACKAGE_MANAGER}" "${destination}"
  fi
  rm -f "${template}"
}

make_pkg $*
