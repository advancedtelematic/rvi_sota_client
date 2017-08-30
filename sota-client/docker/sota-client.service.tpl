[Unit]
Description=SOTA Client
Wants=network-online.target
After=network.target network-online.target
Requires=network-online.target

[Service]
RestartSec=5
Restart=on-failure
Environment="RUST_LOG=debug"
DefaultTimeoutStopSec=5
ExecStart=${BIN_DIR}/sota_client --config ${CONFIG_DIR}/sota.toml

[Install]
WantedBy=multi-user.target
