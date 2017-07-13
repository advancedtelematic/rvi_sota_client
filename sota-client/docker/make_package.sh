#!/bin/bash

set -xeo pipefail


if [ $# -lt 1 ]; then
  echo "Usage: $0 <package> [<dest>]"
  echo "packages: deb rpm"
  exit 1
fi

cwd="$(cd "$(dirname "$0")" && pwd)"
: "${PACKAGE_VERSION:?}" # check package version is set

case $1 in
  "deb" )
    pac_man="deb"
    pac_flags="--deb-systemd ${cwd}/sota_client_default.service"
    ;;
  "rpm" )
    pac_man="rpm"
    pac_flags="--rpm-service ${cwd}/sota_client_default.service"
    ;;
  *)
    echo "unknown package format $1"
    exit 2
esac
shift


function make_pkg {
  dest="$1"
  bin_dir="${BIN_DIR:-/usr/local/bin}"
  config_dir="${CONFIG_DIR:-/usr/etc}"
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
    "${cwd}/sota_client=${bin_dir}/sota_client" \
    "${cwd}/sota_sysinfo.sh=${bin_dir}/sota_sysinfo.sh" \
    "${cwd}/sota_certificates=${config_dir}/sota_certificates" \
    "${toml_file}=${config_dir}/sota.toml"

  [[ -n "${dest}" ]] && mv -f sota-client*.${pac_man} "${dest}"
  rm -f "${toml_file}"
}

make_pkg $*
