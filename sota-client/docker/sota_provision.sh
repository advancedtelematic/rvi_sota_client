#!/bin/bash

set -xeuo pipefail

random_serial() {
  echo $(tr -dc '[:alnum:]' < /dev/urandom | dd bs=1 count=10 2>/dev/null)
}

device_id="${SOTA_DEVICE_ID:-$(petname || ifconfig -a | grep -oE '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' | head -n1)}"
hardware_id="${SOTA_HARDWARE_ID:-$(cat /etc/hostname)}"
primary_serial="${SOTA_PRIMARY_SERIAL:-$(random_serial)}"
cert_dir="${SOTA_CERT_DIR:-/usr/local/etc/sota}"

mkdir -p "$cert_dir" && cd "$cert_dir"

in_reg="${1-credentials}" # input registration credentials file prefix
out_dev="${2-device}"     # output device credentials file prefix
out_ca="${3-ca}"          # output ca certificates file prefix
out_pri="${4-primary}"    # output primary ecu file prefix
in_ecus="${5-ecus}"       # input secondary ecus file
in_hardware="${6-secondary_hardware}" # input secondary hardware file


main() {
  prepare_ecus
  prepare_keys
  register_device || { wait_for_ntp && register_device; }
  register_ecus

  fetch_metadata root director
  fetch_metadata root repo

  generate_toml
  generate_manifests
  generate_installers
}

wait_for_ntp() {
  while [[ "$(timedatectl status | grep NTP)" != "NTP synchronized: yes" ]]; do
    sleep 5
    echo "Waiting for NTP sync..."
  done
}

prepare_ecus() {
  if [ ! -f "$in_ecus" ]; then
    touch "$in_ecus"
    if [ -f "$in_hardware" ]; then
      while read -r hw_id; do
        echo "$(random_serial) $hw_id" >> $in_ecus
      done < "$in_hardware"
    fi
  fi
}

prepare_keys() {
  echo "Preparing keys ..."

  [ ! -f "$in_reg.p12"  ] && { echo "Missing '$in_reg.p12' in $PWD"; exit 1; }
  [   -f "$out_dev.p12" ] && { echo "Already provisioned '$out_dev.p12' in $PWD"; exit 0; }

  openssl pkcs12 -in "$in_reg.p12" -out "$in_reg.pem" -nodes -passin pass:""
  openssl pkcs12 -in "$in_reg.p12" -cacerts -nokeys -passin pass:"" 2>/dev/null \
    | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "$out_ca.crt"

  openssl genpkey -algorithm RSA -out "$out_pri.der" -outform DER -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout -in "$out_pri.der" -inform DER -out "$out_pri.pub"

  while read -r serial hw_id; do
    openssl genpkey -algorithm RSA -out "$serial.der" -outform DER -pkeyopt rsa_keygen_bits:2048
    openssl rsa -pubout -in "$serial.der" -inform DER -out "$serial.pub"
  done < "$in_ecus"
}

register_device() {
  echo "Registering device: $device_id"

  curl -vvf --cacert "$out_ca.crt" --cert "$in_reg.pem" "$SOTA_GATEWAY_URI/devices" \
    -H 'Content-Type: application/json' \
    -d '{"deviceId":"'"$device_id"'","ttl":365}' \
    -o "$out_dev.p12" \
    || return 1
  echo "Wrote device bundle to $cert_dir/$out_dev.p12"

  openssl pkcs12 -in "$out_dev.p12" -out "$out_dev.pem" -nodes -passin pass:""
  echo "Wrote device certificate to $cert_dir/$out_dev.pem"
  openssl pkcs12 -in "$out_dev.p12" -cacerts -nokeys -passin pass:"" 2>/dev/null \
    | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "$out_ca.crt"
  echo "Wrote certificate authority file to $cert_dir/$out_ca.crt"
  openssl pkcs12 -in "$out_dev.p12" -clcerts -nokeys -passin pass:"" 2>/dev/null \
    | sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "$out_dev.crt"
  echo "Wrote client certificate to $cert_dir/$out_dev.crt"
}

register_ecus() {
  echo "Registering ECUs with Director..."

  # join the next line and jump back to the start before escaping all newlines
  pubkey=$(sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' < "$out_pri.pub")
  ecus='{"ecu_serial":"'"$primary_serial"'","hardware_identifier":"'"$hardware_id"'","clientKey":{"keytype":"RSA","keyval":{"public":"'"$pubkey"'"}}}'

  while read -r serial hw_id; do
    pubkey=$(sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' < "$serial.pub")
    ecus+=',{"ecu_serial":"'"$serial"'","hardware_identifier":"'"$hw_id"'","clientKey":{"keytype":"RSA","keyval":{"public":"'"$pubkey"'"}}}'
  done < "$in_ecus"

  curl -vvf --cacert "$out_ca.crt" --cert "$out_dev.pem" \
    "$SOTA_GATEWAY_URI/director/ecus" \
    -H 'Content-Type: application/json' \
    -d '{"primary_ecu_serial":"'"$primary_serial"'","ecus":['"$ecus"']}'
}

fetch_metadata() {
  local metadata=$1
  local service=$2
  mkdir -p "metadata/$service"

  echo "Fetching $metadata.json from $service"
  curl -vvf --cacert "$out_ca.crt" --cert "$out_dev.pem" \
    "$SOTA_GATEWAY_URI/$service/$metadata.json" \
    -o "metadata/$service/$metadata.json"
}

generate_toml() {
  echo "Writing SOTA config to $cert_dir/sota.toml"
  cat > sota.toml <<EOF
[device]
package_manager = "off"
system_info = "sota_sysinfo.sh"

[tls]
server = "$SOTA_GATEWAY_URI"
ca_file = "$cert_dir/$out_ca.crt"
cert_file = "$cert_dir/$out_dev.crt"
pkey_file = "$cert_dir/$out_dev.pem"

[uptane]
director_server = "$SOTA_GATEWAY_URI/director"
repo_server = "$SOTA_GATEWAY_URI/repo"
primary_ecu_serial = "$primary_serial"
primary_ecu_hardware_identifier = "$hardware_id"
metadata_path = "$cert_dir/metadata"
private_key_path = "$cert_dir/$out_pri.der"
public_key_path = "$cert_dir/$out_pri.pub"

[[ecus]]
ecu_serial = "$primary_serial"
public_key_path = "$cert_dir/$out_pri.pub"
manifest_path = "$cert_dir/$out_pri.manifest"
EOF

  while read -r serial hw_id; do
    cat >> sota.toml <<EOF

[[ecus]]
ecu_serial = "$serial"
public_key_path = "$cert_dir/$serial.pub"
manifest_path = "$cert_dir/$serial.manifest"
EOF
  done < "$in_ecus"
}

generate_manifests() {
  sota-launcher manifests --level debug --priv-keys "$cert_dir"
}

generate_installers() {
  while read -r serial hw_id; do
    cat > "$serial.toml" <<EOF
serial = "$serial"
private_key_path = "$cert_dir/$serial.der"
signature_type = "rsassa-pss"
EOF
  done < "$in_ecus"
}


main
