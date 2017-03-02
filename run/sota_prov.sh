#!/bin/bash -x

: "${SOTA_GATEWAY_URI:?}"

function device_registration() {
  device_id="${1}"
  regpkcs="${2-credentials.p12}"
  devpkcs="${3-device.p12}"
  srvcrt="${4-srv.crt}"

  openssl pkcs12 -in $regpkcs -out $regpkcs.pem -nodes -passin pass:""
  openssl pkcs12 -in $regpkcs -cacerts -nokeys -passin pass:"" 2>/dev/null | openssl x509 -outform PEM > $srvcrt

  curl --cacert $srvcrt --cert $regpkcs.pem \
    -X POST $SOTA_GATEWAY_URI/devices \
    -H 'Content-Type: application/json' \
    -d '{"deviceId":"'$device_id'","ttl":36000}' -o $devpkcs

  rm -f $regpkcs $regpkcs.pem
}

function mk_device_id() {
  ifconfig -a | grep 'HWaddr ..:' | head -1 | sed -e 's/^.*HWaddr //'
}

cd ${SOTA_CERT_DIR-/etc/sota/certs/}
regpkcs=credentials.p12
if [ ! -f $regpkcs ]; then
  echo "Missing '$regpkcs' in $PWD"
  exit 1
fi
device_registration $(mk_device_id) $regpkcs
