/bin/sh

RUST_LOG=debug /usr/bin/sota_client --config /sysroot/boot/sota.toml --core-ca-file /usr/etc/sota_certificates --device-package-manager ostree

