#!/usr/bin/env bash
# Install the Twisted engine as a WSL systemd user service.
#
# Run from the WSL side (one-time):
#   ./scripts/install-engine-systemd.sh

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found — WSL2 systemd is probably disabled."
    echo "Enable it by adding the following to /etc/wsl.conf:"
    echo "    [boot]"
    echo "    systemd=true"
    echo "Then run 'wsl --shutdown' from PowerShell and re-launch Ubuntu."
    exit 1
fi

# Generate the unit
.venv/bin/twisted serve --install-systemd

systemctl --user daemon-reload
systemctl --user enable --now twisted-engine.service

echo
echo "Engine status:"
systemctl --user status --no-pager twisted-engine.service || true

echo
echo "Bearer token:"
.venv/bin/twisted token show
echo
echo "Token file:"
.venv/bin/twisted token path
