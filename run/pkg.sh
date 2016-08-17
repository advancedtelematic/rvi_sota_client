#!/bin/bash

set -eo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <package> [<destination>]"
  echo "packages: deb rpm"
  exit 1
fi

# check package version is set
: "${PACKAGE_VERSION:?}"

PACKAGE_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFIX=/opt/sota

export OTA_AUTH_URL="${OTA_AUTH_URL-http://localhost:9001}"
export OTA_CORE_URL="${OTA_CORE_URL-http://localhost:8080}"
export OTA_CREDENTIALS_FILE="${OTA_CREDENTIALS_FILE-${PREFIX}/credentials.toml}"

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
  [[ "${AUTH_SECTION}" = false ]] && sed -i '1,/\[core\]/{/\[core\]/p;d}' "${template}"
  chmod 600 "$template"

  fpm \
    -s dir \
    -t "${PACKAGE_MANAGER}" \
    --architecture native \
    --name "${PACKAGE_NAME:-sota-client}" \
    --version "${PACKAGE_VERSION}" \
    --package NAME-VERSION.TYPE \
    ${PKG_BUILD_OPTS} \
    "${PACKAGE_DIR}/sota_client=/usr/bin/sota_client" \
    "${PACKAGE_DIR}/sota_certificates=/etc/sota_certificates" \
    "${template}=/etc/sota.toml"

  if [ -n "$destination" ]; then
    mv -f "sota-client*.${PACKAGE_MANAGER}" "${destination}"
  fi
  rm -f "${template}"
}

make_pkg $*
