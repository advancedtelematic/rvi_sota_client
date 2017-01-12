/bin/sh

RUST_LOG=debug /usr/bin/sota_client --config /sysroot/boot/sota.toml --device-certificates-path /usr/etc/sota_certificates --device-package-manager ostree

