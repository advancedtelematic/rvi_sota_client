#!/bin/bash

set -eo pipefail

function print_usage {
    echo "Usage: $(basename $0)"
    echo ""
    echo "Envirionment variables:"
    echo "PULL_URI: The remote to pull from"
    echo "COMMIT: The commit-hash"
    echo "AUTHPLUS_ACCESS_TOKEN: The auth-plus access token"
}

if [ -z "$PULL_URI" ]; then
    echo "The pull uri is not specified, set PULL_URI env" >&2
    print_usage
    exit 1
fi

if [ -z "$COMMIT" ]; then
    echo "The commit is not specified, set COMMIT env" >&2
    print_usage
    exit 1
fi

if [ -z "$AUTHPLUS_ACCESS_TOKEN" ]; then
    echo "The auth-plus access token is not specified, set AUTHPLUS_ACCESS_TOKEN env" >&2
    print_usage
    exit 1
fi

HDR="Authorization=Bearer $AUTHPLUS_ACCESS_TOKEN"

mkdir -p /var/sota_ostree/

if [ -f /var/sota_ostree/staging ]; then
    CUR_COMMIT=$(cat /var/sota_ostree/staging)
fi

if [ "$COMMIT" == "$CUR_COMMIT" ]; then
    echo "already installed"
    exit 0
fi

rm -f /etc/ostree/remotes.d/agl-remote.conf
ostree remote add --no-gpg-verify agl-remote "$PULL_URI"
ostree pull agl-remote --http-header="$HDR" "$COMMIT"
ostree admin deploy "$COMMIT" && echo -n "$COMMIT" > /var/sota_ostree/staging

sync
