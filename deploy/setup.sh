#!/bin/bash
set -euo pipefail

# Pulumi backend setup script — runs on the VM as root.

BINARY_PATH="/usr/local/bin/pulumi-backend"
DATA_DIR="/var/lib/pulumi-backend"
SERVICE_USER="pulumi-backend"

# Create dedicated system user.
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# Create data directory.
mkdir -p "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 700 "$DATA_DIR"

# Move binary into place.
if [ -f /tmp/pulumi-backend-linux-amd64 ]; then
    mv /tmp/pulumi-backend-linux-amd64 "$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
fi

# Allow binding to ports 80/443 without root.
setcap 'cap_net_bind_service=+ep' "$BINARY_PATH"

# Install systemd unit.
cat > /etc/systemd/system/pulumi-backend.service << 'UNIT'
[Unit]
Description=Pulumi Backend
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pulumi-backend
Group=pulumi-backend
ExecStart=/usr/local/bin/pulumi-backend
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security hardening.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/pulumi-backend

# Environment from file.
EnvironmentFile=/var/lib/pulumi-backend/env

[Install]
WantedBy=multi-user.target
UNIT

echo "Setup complete. Create /var/lib/pulumi-backend/env then: systemctl daemon-reload && systemctl enable --now pulumi-backend"
