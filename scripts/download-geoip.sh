#!/bin/bash
#
# NetGuard AI - GeoIP Database Download Helper
# Downloads a free GeoIP City database for IP geolocation enrichment.
#
# Usage:
#   sudo ./scripts/download-geoip.sh [install-dir]
#
# Environment variables:
#   GEOIP_LICENSE_KEY - MaxMind GeoLite2 license key (optional, for MaxMind download)
#
# If no license key is provided, the script tries the free DB-IP city-lite database,
# which does not require an account.

set -e

INSTALL_DIR="${1:-/opt/netguard}"
GEOIP_DIR="${INSTALL_DIR}"
GEOIP_DB="${GEOIP_DIR}/GeoLite2-City.mmdb"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

mkdir -p "${GEOIP_DIR}"

download_dbip() {
    print_step "Attempting to download free DB-IP City Lite database..."
    
    local year_month
    year_month="$(date +%Y-%m)"
    
    local url="https://download.db-ip.com/free/dbip-city-lite-${year_month}.mmdb.gz"
    local tmp_gz="/tmp/dbip-city-lite-${year_month}.mmdb.gz"
    local tmp_mmdb="/tmp/dbip-city-lite-${year_month}.mmdb"
    
    if curl -fsSL --max-time 60 "${url}" -o "${tmp_gz}" 2>/dev/null; then
        gunzip -f "${tmp_gz}"
        mv "${tmp_mmdb}" "${GEOIP_DB}"
        rm -f "${tmp_gz}"
        print_success "DB-IP City database downloaded to ${GEOIP_DB}"
        return 0
    else
        print_warning "DB-IP download failed (URL: ${url})"
        rm -f "${tmp_gz}" "${tmp_mmdb}"
        return 1
    fi
}

download_maxmind() {
    print_step "Attempting to download MaxMind GeoLite2-City database..."
    
    if [ -z "${GEOIP_LICENSE_KEY}" ]; then
        print_warning "GEOIP_LICENSE_KEY not set. Skipping MaxMind download."
        return 1
    fi
    
    if ! command -v geoipupdate >/dev/null 2>&1; then
        print_step "Installing geoipupdate..."
        apt-get update -qq
        apt-get install -y -qq geoipupdate
    fi
    
    local geoip_conf="/tmp/GeoIP.conf"
    cat > "${geoip_conf}" <<EOF
AccountID ${GEOIP_LICENSE_KEY%%_*}
LicenseKey ${GEOIP_LICENSE_KEY}
EditionIDs GeoLite2-City
DatabaseDirectory ${GEOIP_DIR}
EOF
    
    if geoipupdate -f "${geoip_conf}" --verbose; then
        mv "${GEOIP_DIR}/GeoLite2-City.mmdb" "${GEOIP_DB}" 2>/dev/null || true
        print_success "MaxMind GeoLite2-City database downloaded to ${GEOIP_DB}"
        rm -f "${geoip_conf}"
        return 0
    else
        print_warning "MaxMind download failed"
        rm -f "${geoip_conf}"
        return 1
    fi
}

verify_database() {
    print_step "Verifying GeoIP database..."
    
    if [ ! -f "${GEOIP_DB}" ]; then
        print_error "GeoIP database not found at ${GEOIP_DB}"
        return 1
    fi
    
    # Try to load and query with Python/geoip2
    if python3 - <<PY
import sys
try:
    import geoip2.database
    reader = geoip2.database.Reader('${GEOIP_DB}')
    reader.city('8.8.8.8')
    reader.close()
    print('GeoIP database verified successfully')
    sys.exit(0)
except Exception as e:
    print(f'GeoIP verification failed: {e}', file=sys.stderr)
    sys.exit(1)
PY
    then
        print_success "GeoIP database is valid"
        return 0
    else
        print_error "GeoIP database verification failed"
        return 1
    fi
}

print_fallback() {
    echo ""
    print_warning "Automatic GeoIP download failed. NetGuard will still work using the online fallback,"
    print_warning "but offline lookups will not be available."
    echo ""
    echo -e "${YELLOW}To enable offline GeoIP, manually download one of the following:${NC}"
    echo "  1. MaxMind GeoLite2-City.mmdb  -> place at ${GEOIP_DB}"
    echo "     (free account required at https://www.maxmind.com/en/geolite2/signup)"
    echo "  2. DB-IP City Lite .mmdb        -> rename to ${GEOIP_DB}"
    echo "     (free monthly downloads at https://db-ip.com/db/download/ip-to-city-lite)"
    echo ""
    echo -e "${YELLOW}Then set the environment variable if you use a custom path:${NC}"
    echo "  GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb"
    echo ""
}

# Main
echo "=================================="
echo "  NetGuard AI GeoIP Downloader"
echo "=================================="
echo ""

if [ -f "${GEOIP_DB}" ]; then
    print_success "GeoIP database already exists at ${GEOIP_DB}"
    if verify_database; then
        echo ""
        print_success "GeoIP is ready to use"
        exit 0
    fi
fi

# Try MaxMind first if key is provided, otherwise DB-IP
if [ -n "${GEOIP_LICENSE_KEY}" ]; then
    download_maxmind || download_dbip || true
else
    download_dbip || true
fi

if [ -f "${GEOIP_DB}" ]; then
    if verify_database; then
        echo ""
        print_success "GeoIP setup complete: ${GEOIP_DB}"
        exit 0
    fi
fi

print_fallback
exit 0
