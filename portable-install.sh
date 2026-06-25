#!/bin/bash
#
# NetGuard AI - Portable Installation Script (Flash Drive Friendly)
# This script installs NetGuard AI from the current directory.
# Designed to be run from a USB flash drive on any Ubuntu/Debian/Parrot system.
#
# Usage:
#   1. Copy the entire project folder to a flash drive
#   2. Plug flash drive into target system
#   3. cd /media/user/flash-drive/final-year-project
#   4. sudo ./portable-install.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================="
echo "  NetGuard AI Portable Installer  "
echo "=================================="
echo ""
echo "Source: $SCRIPT_DIR"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Check that required directories exist
if [[ ! -d "$SCRIPT_DIR/netguaedai/netguard/netguard/services" ]]; then
    echo "ERROR: Cannot find NetGuard services directory."
    echo "Make sure you run this script from the project root."
    exit 1
fi

# Run the main installer
bash "$SCRIPT_DIR/install.sh"
