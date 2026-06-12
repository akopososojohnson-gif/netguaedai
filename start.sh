#!/bin/bash
#
# NetGuard AI - Start Script
# Starts all NetGuard AI services using systemd
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETGUARD_DIR="${SCRIPT_DIR}/netguaedai/netguard/netguard"

echo "=================================="
echo "  NetGuard AI - System Starter    "
echo "=================================="
echo ""

# Check if installed
if [[ ! -d "/opt/netguard" ]] || [[ ! -f "/etc/netguard/netguard.conf" ]]; then
    echo "NetGuard AI is not installed yet."
    echo "Running installer..."
    echo ""
    cd "${NETGUARD_DIR}"
    sudo ./netguard.sh install
    exit 0
fi

# Stop any existing services first
echo "[1/3] Stopping any existing services..."
sudo systemctl stop netguard-web netguard-processor netguard-capture 2>/dev/null || true

# Ensure gunicorn is installed (needed for web service)
if [[ ! -f "/opt/netguard/venv/bin/gunicorn" ]]; then
    echo "[2/3] Installing gunicorn..."
    sudo /opt/netguard/venv/bin/pip install gunicorn 2>&1 | tail -3
fi

# Fix log permissions
echo "[3/3] Fixing permissions..."
sudo mkdir -p /var/log/netguard
sudo chown -R netguard:netguard /var/log/netguard
sudo chmod 755 /var/log/netguard

# Start all services
echo ""
echo "Starting NetGuard AI services..."
sudo systemctl start redis-server
sudo systemctl start postgresql
sudo systemctl start netguard-capture
sudo systemctl start netguard-processor
sudo systemctl start netguard-web

echo ""
echo "=================================="
echo "  NetGuard AI is running!         "
echo "=================================="
echo ""
echo "Web Dashboard: http://localhost:8765"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status netguard-*"
echo "  sudo journalctl -u netguard-web -f"
echo "  sudo ./netguard.sh status"
echo ""
