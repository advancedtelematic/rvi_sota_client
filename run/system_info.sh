#!/bin/bash

INFO=$(lshw -json)

MANIFEST_PATH=/etc/manifest.xml
if [ -f $MANIFEST_PATH ]; then
  MANIFEST={\"manifest_file\":\"$( cat $MANIFEST_PATH | sed 's/"/\\"/'g | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/ /g' )\"}
  INFO=$(echo $MANIFEST $INFO | jq -s add | jq -r .)
fi

SERVICE_HOSTNAME_PATH=/var/lib/tor/hidden_service/hostname
if [ -f $SERVICE_HOSTNAME_PATH ]; then
  SERVICE_HOSTNAME={\"service_hostname\":\"$( cat $SERVICE_HOSTNAME_PATH )\"}
  INFO=$(echo $SERVICE_HOSTNAME $INFO | jq -s add | jq -r .)
fi

echo $INFO | jq -c -r .
