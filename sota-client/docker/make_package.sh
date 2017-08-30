#!/bin/bash

set -xeo pipefail


if [ $# -lt 1 ]; then
  echo "Usage: $0 <package> [<dest>]"
  echo "packages: deb rpm"
  exit 1
fi

cwd="$(cd "$(dirname "$0")" && pwd)"
: "${PACKAGE_VERSION:?}" # check package version is set
export BIN_DIR="${BIN_DIR:-/usr/local/bin}"
export CONFIG_DIR="${CONFIG_DIR:-/usr/local/etc}"
envsubst < ${cwd}/sota-client.service.tpl > ${cwd}/sota-client.service

case $1 in
  "deb" )
    pac_man="deb"
    pac_flags="--deb-systemd ${cwd}/sota-client.service"
    ;;
  "rpm" )
    pac_man="rpm"
    pac_flags="--rpm-service ${cwd}/sota-client.service"
    ;;
  *)
    echo "unknown package format $1"
    exit 2
esac
shift


function make_pkg {
  dest="$1"
  config_path="${CONFIG_PATH:-${cwd}/../tests/config/default.toml}"
  toml_file=$(mktemp)

  cp "${config_path}" "${toml_file}"
  chmod 600 "${toml_file}"

  # FIXME: better substitutions with rq
  sed -i "s|http://127.0.0.1:9001|${AUTH_SERVER:-http://127.0.0.1:9001}|" "${toml_file}"
  sed -i "s|http://127.0.0.1:8080|${CORE_SERVER:-http://127.0.0.1:8080}|" "${toml_file}"
  [[ "${AUTH_SECTION}" = false ]] && sed -i '1,/\[core\]/{/\[core\]/p;d}' "${toml_file}"

  fpm \
    -s dir \
    -t "${pac_man}" \
    --architecture native \
    --name "${PACKAGE_NAME:-sota-client}" \
    --version "${PACKAGE_VERSION}" \
    --package NAME-VERSION.TYPE \
    ${pac_flags} \
    "${cwd}/sota_client=${BIN_DIR}/sota_client" \
    "${cwd}/sota_sysinfo.sh=${BIN_DIR}/sota_sysinfo.sh" \
    "${cwd}/sota_certificates=${CONFIG_DIR}/sota_certificates" \
    "${toml_file}=${CONFIG_DIR}/sota.toml"

  [[ -n "${dest}" ]] && mv -f sota-client*.${pac_man} "${dest}"
  rm -f "${toml_file}"
}

make_pkg $*
