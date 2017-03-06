#!/bin/bash

set -xeo pipefail

: "${SOTA_GATEWAY_URI:?}"
certdir=${SOTA_CERT_DIR-/usr/local/etc/sota/}
mkdir -p $certdir && cd $certdir

regpkcs="${1-credentials.p12}"
devpkcs="${2-device.p12}"
srvcrt="${3-srv.crt}"
ecukey=${4-ecuprimary}

function mk_device_id() {
  ifconfig -a | grep 'HWaddr ..:' | head -n 1 | sed -e 's/^.*HWaddr //' | sed -e 's/\s*$//'
}
SOTA_DEVICE_ID="${SOTA_DEVICE_ID-$(mk_device_id)}"


function device_registration() {
  if [ ! -f $regpkcs ]; then
    echo "Missing '$regpkcs' in $PWD"
    exit 1
  elif [ -f $devpkcs ]; then
    echo "Already provisioned '$devpkcs' in $PWD"
    exit 0
  fi

  openssl pkcs12 -in $regpkcs -out $regpkcs.pem -nodes -passin pass:""
  openssl pkcs12 -in $regpkcs -cacerts -nokeys -passin pass:"" 2>/dev/null \
    | sed --quiet '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > $srvcrt

  curl --cacert $srvcrt --cert $regpkcs.pem \
    -X POST $SOTA_GATEWAY_URI/devices \
    -H 'Content-Type: application/json' \
    -d '{"deviceId":"'$SOTA_DEVICE_ID'","ttl":36000}' \
    -o $devpkcs

  openssl pkcs12 -in $devpkcs -out $devpkcs.pem -nodes -passin pass:""
  openssl pkcs12 -in $devpkcs -cacerts -nokeys -passin pass:"" 2>/dev/null \
    | sed --quiet '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > $srvcrt
}

function ecu_registration() {
  openssl genpkey -algorithm RSA -out $ecukey.pem -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout -in $ecukey.pem -out $ecukey.pub
  keypub=$(sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' < $ecukey.pub)

  curl --cacert $srvcrt --cert $devpkcs.pem \
    -X POST $SOTA_GATEWAY_URI/director/ecus \
    -H 'Content-Type: application/json' \
    -d '{"primary_ecu_serial":"'$SOTA_DEVICE_ID'", "ecus":[{"ecu_serial":"'$SOTA_DEVICE_ID'", "clientKey": {"keytype": "RSA", "keyval": {"public": "'"$keypub"'"}}}]}'
}

function director_metadata() {
  mkdir -p director/metadata
  curl --cacert $srvcrt --cert $devpkcs.pem \
    $SOTA_GATEWAY_URI/director/root.json \
    -o director/metadata/root.json
}

function repo_metadata() {
  mkdir -p repo/metadata
  curl --cacert $srvcrt --cert $devpkcs.pem \
    $SOTA_GATEWAY_URI/repo/root.json \
    -o repo/metadata/root.json
}

device_registration
ecu_registration
director_metadata
repo_metadata

cat > /sysroot/boot/sota.toml <<EOF
[tls]
cn = $SOTA_DEVICE_ID
cacert = $SOTA_CERT_DIR/$srvcrt
p12_path = $SOTA_CERT_DIR/$devpkcs
p12_password = ""

[uptane]
director_server = "$SOTA_GATEWAY_URI/director"
images_server = "$SOTA_GATEWAY_URI/repo"
metadata_path = "$SOTA_CERT_DIR/director/metadata"
ecu_serial = "$SOTA_DEVICE_ID"
private_key_path = $SOTA_CERT_DIR/$ecukey.pem
public_key_path = $SOTA_CERT_DIR/$ecukey.pub

[device]
packages_dir = "/tmp/"
package_manager = "off"
system_info = "sota_sysinfo.sh"
EOF
