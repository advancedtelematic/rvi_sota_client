#!/bin/bash
# bash "strict mode", see
# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail
IFS=$'\n\t'

eval $(dbus-launch)
export DBUS_SESSION_BUS_ADDRESS
export DBUS_SESSION_BUS_PID

LOGLEVEL=${LOGLEVEL:-"info"}
SOTA_CLIENT="${SOTA_CLIENT_ADDR:-0.0.0.0}:${SOTA_CLIENT_PORT:-9080}"
RVI="${RVI:-http://rvi-client:8901}"

export RUST_LOG=${RUST_LOG:-"sota_client=$LOGLEVEL"}
/usr/bin/sota_client -c /var/sota/client.toml -r "$RVI" -e "$SOTA_CLIENT"
