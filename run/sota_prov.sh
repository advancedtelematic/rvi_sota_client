#!/bin/bash

set -xeo pipefail

: "${SOTA_GATEWAY_URI:?}"
certdir=${SOTA_CERT_DIR-/usr/local/etc/sota}
mkdir -p "$certdir" && cd "$certdir"

in_reg="${1-credentials}" # input registration credentials file prefix
out_dev="${2-device}"     # output device credentials file prefix
out_ca="${3-ca}"          # output ca certificates file prefix
out_ecu="${4-ecuprimary}" # output primary ecu file prefix


function mk_device_id() {
  ifconfig -a | grep 'HWaddr ..:' | head -n 1 | sed -e 's/^.*HWaddr //' | sed -e 's/\s*$//'
}
device_id="${SOTA_DEVICE_ID-$(mk_device_id)}"

function device_registration() {
  if [ ! -f "$in_reg.p12" ]; then
    echo "Missing '$in_reg.p12' in $PWD"
    exit 1
  elif [ -f "$out_dev.p12" ]; then
    echo "Already provisioned '$out_dev.p12' in $PWD"
    exit 0
  fi

  openssl pkcs12 -in "$in_reg.p12" -out "$in_reg.pem" -nodes -passin pass:""
  openssl pkcs12 -in "$in_reg.p12" -cacerts -nokeys -passin pass:"" 2>/dev/null \
    | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "$out_ca.crt"

  curl -vv -f --cacert "$out_ca.crt" --cert "$in_reg.pem" \
    -X POST "$SOTA_GATEWAY_URI/devices" \
    -H 'Content-Type: application/json' \
    -d '{"deviceId":"'"$device_id"'","ttl":36000}' \
    -o "$out_dev.p12"

  openssl pkcs12 -in "$out_dev.p12" -out "$out_dev.pem" -nodes -passin pass:""
  openssl pkcs12 -in "$out_dev.p12" -cacerts -nokeys -passin pass:"" 2>/dev/null \
    | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "$out_ca.crt"
  openssl pkcs12 -in "$out_dev.p12" -clcerts -nokeys -passin pass:"" 2>/dev/null \
    | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "$out_dev.crt"
}

function ecu_registration() {
  openssl genpkey -algorithm RSA -out "$out_ecu.pem" -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout -in "$out_ecu.pem" -out "$out_ecu.pub"
  keypub=$(sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' < "$out_ecu.pub")

  curl -vv -f --cacert "$out_ca.crt" --cert "$out_dev.pem" \
    -X POST "$SOTA_GATEWAY_URI/director/ecus" \
    -H 'Content-Type: application/json' \
    -d '{"primary_ecu_serial":"'"$device_id"'", "ecus":[{"ecu_serial":"'"$device_id"'", "clientKey": {"keytype": "RSA", "keyval": {"public": "'"$keypub"'"}}}]}'
}

function director_metadata() {
  mkdir -p metadata/director
  curl --cacert "$out_ca.crt" --cert "$out_dev.pem" \
    "$SOTA_GATEWAY_URI/director/root.json" \
    -o metadata/director/root.json
}

function repo_metadata() {
  mkdir -p metadata/repo
  curl -vv -f --cacert "$out_ca.crt" --cert "$out_dev.pem" \
    "$SOTA_GATEWAY_URI/repo/root.json" \
    -o metadata/repo/root.json
}


device_registration
ecu_registration
director_metadata
repo_metadata

cat > sota.toml <<EOF
[device]
package_manager = "off"

[tls]
server = "$SOTA_GATEWAY_URI"
ca_file = "$certdir/$out_ca.crt"
cert_file = "$certdir/$out_dev.crt"
pkey_file = "$certdir/$out_dev.pem"

[uptane]
director_server = "$SOTA_GATEWAY_URI/director"
repo_server = "$SOTA_GATEWAY_URI/repo"
primary_ecu_serial = "$device_id"
metadata_path = "$certdir/metadata"
private_key_path = "$certdir/$out_ecu.pem"
public_key_path = "$certdir/$out_ecu.pub"
EOF
