#!/bin/bash

set -eo pipefail

PKG_NAME="sota_client_latest"
WORKING_DIR="/tmp/sota_client_extract_$$"

cd $(dirname $0)
PKG_SRC_DIR=$(pwd)

function convert_to_rpm {
    mv $dest $dest.deb
    alien -c -k -r --fixperms $dest.deb
    mv sota*.rpm $dest
}

function tailor_deb {
    rm -fr $WORKING_DIR
    mkdir -p $WORKING_DIR/DEBIAN
    echo "Extracting Debian package $PKGS_DIR/$PKG_NAME.deb to $WORKING_DIR"
    dpkg-deb -x $PKGS_DIR/$PKG_NAME.deb $WORKING_DIR/
    dpkg-deb -e $PKGS_DIR/$PKG_NAME.deb $WORKING_DIR/DEBIAN

    if [[ $package == "deb" ]]; then
        pkgmanager="dpkg"
    else
        pkgmanager="rpm"
    fi

    SOTA_TOML="$WORKING_DIR/opt/ats/sota.toml"
    sed -i "s/^client_id = .*$/client_id = \"$OTA_AUTH_CLIENT_ID\"/" "$SOTA_TOML"
    sed -i "s/^secret = .*$/secret = \"$OTA_AUTH_SECRET\"/" "$SOTA_TOML"
    sed -i "s/^uuid = .*$/uuid = \"$OTA_DEVICE_UUID\"/" "$SOTA_TOML"
    sed -i "s/^vin = .*$/vin = \"$OTA_CLIENT_VIN\"/" "$SOTA_TOML"
    sed -i "s/^package_manager = .*$/package_manager = \"$pkgmanager\"/" "$SOTA_TOML"

    mkdir -p $(dirname $dest)
    echo "Re-packaging contents of $WORKING_DIR/ to $dest"
    dpkg-deb -b $WORKING_DIR/ $dest
    rm -fr $WORKING_DIR
}


if [ $# -lt 2 ]; then
    echo "Usage: $0 <package> <destination>"
    echo "packages: deb rpm"
    exit 1
fi

package="${1}"
dest="${2}"

echo "Tailoring $package package and outputting as '$dest'"
case $package in
    "deb" )
        tailor_deb
        ;;
    "rpm" )
        tailor_deb
        convert_to_rpm
        ;;
    *)
        echo "unknown package $package"
        exit 2
esac
