#!/bin/bash
#
# NetGuard AI - Clean Installation Script
# Installs NetGuard AI on a fresh Debian/Ubuntu/Parrot system
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/netguard"
CONFIG_DIR="/etc/netguard"
LOG_DIR="/var/log/netguard"
SERVICE_USER="netguard"
DB_NAME="netguard"
DB_USER="netguard"
RETENTION_DAYS=30

print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    NetGuard AI Installer                     ║"
    echo "║         Network Intrusion Detection System                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

get_user_input() {
    echo ""
    echo -e "${YELLOW}=== Configuration ===${NC}"
    echo ""
    
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    
    while true; do
        read -s -p "Enter admin password: " ADMIN_PASS
        echo ""
        [[ -z "$ADMIN_PASS" ]] && { print_error "Password cannot be empty"; continue; }
        read -s -p "Confirm admin password: " ADMIN_PASS_CONFIRM
        echo ""
        [[ "$ADMIN_PASS" == "$ADMIN_PASS_CONFIRM" ]] && break
        print_error "Passwords do not match"
    done
    
    read -s -p "Enter database password (auto-generate if empty): " DB_PASS
    echo ""
    if [[ -z "$DB_PASS" ]]; then
        DB_PASS=$(openssl rand -base64 32)
        print_warning "Auto-generated DB password: $DB_PASS"
    fi
    
    read -p "Data retention days [30]: " RETENTION_INPUT
    RETENTION_DAYS=${RETENTION_INPUT:-30}
    
    echo ""
    echo "Available network interfaces:"
    ip -o link show | awk -F': ' '{print $2}' | grep -v lo | nl
    read -p "Select interface number [1]: " IFACE_NUM
    IFACE_NUM=${IFACE_NUM:-1}
    CAPTURE_INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | sed -n "${IFACE_NUM}p")
    
    print_success "Configuration complete"
    echo ""
}

install_deps() {
    print_step "Installing dependencies..."
    
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv \
        postgresql postgresql-contrib \
        libpcap-dev redis-server \
        wget curl net-tools dnsutils openssl
    
    print_success "Dependencies installed"
}

setup_database() {
    print_step "Setting up PostgreSQL..."
    
    systemctl start postgresql
    systemctl enable postgresql
    
    sudo -u postgres psql << EOF 2>/dev/null || true
DROP DATABASE IF EXISTS $DB_NAME;
DROP USER IF EXISTS $DB_USER;
CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
CREATE DATABASE $DB_NAME OWNER $DB_USER;
EOF

    sudo -u postgres psql -d $DB_NAME << EOF
CREATE TABLE IF NOT EXISTS connections (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    id BIGSERIAL PRIMARY KEY,
    src_ip INET,
    src_port INTEGER,
    dst_ip INET,
    dst_port INTEGER,
    domain TEXT DEFAULT '-',
    protocol TEXT,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    duration DOUBLE PRECISION,
    threat_score DOUBLE PRECISION DEFAULT 0.0,
    threat_type TEXT DEFAULT 'normal',
    threat_level TEXT DEFAULT 'LOW',
    src_country TEXT DEFAULT 'Unknown',
    src_city TEXT DEFAULT 'Unknown',
    dst_country TEXT DEFAULT 'Unknown',
    raw_packet JSONB
);

CREATE INDEX idx_connections_time ON connections (time DESC);
CREATE INDEX idx_connections_threat ON connections (threat_score) WHERE threat_score > 0.5;
CREATE INDEX idx_connections_threat_level ON connections (threat_level);
CREATE INDEX idx_connections_src_ip ON connections (src_ip);
CREATE INDEX idx_connections_dst_ip ON connections (dst_ip);
CREATE INDEX idx_connections_src_country ON connections (src_country);

CREATE TABLE IF NOT EXISTS alerts (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    id BIGSERIAL PRIMARY KEY,
    alert_type TEXT,
    severity TEXT,
    threat_level TEXT DEFAULT 'LOW',
    message TEXT,
    src_ip INET,
    dst_ip INET,
    acknowledged BOOLEAN DEFAULT FALSE
);

CREATE OR REPLACE FUNCTION cleanup_old_data() RETURNS void AS \$\$
BEGIN
    DELETE FROM connections WHERE time < NOW() - INTERVAL '${RETENTION_DAYS} days';
    DELETE FROM alerts WHERE time < NOW() - INTERVAL '${RETENTION_DAYS} days';
END;
\$\$ LANGUAGE plpgsql;

-- Migration: add GeoIP and threat_level columns if upgrading from older version
ALTER TABLE connections ADD COLUMN IF NOT EXISTS threat_level TEXT DEFAULT 'LOW';
ALTER TABLE connections ADD COLUMN IF NOT EXISTS src_country TEXT DEFAULT 'Unknown';
ALTER TABLE connections ADD COLUMN IF NOT EXISTS src_city TEXT DEFAULT 'Unknown';
ALTER TABLE connections ADD COLUMN IF NOT EXISTS dst_country TEXT DEFAULT 'Unknown';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS threat_level TEXT DEFAULT 'LOW';

CREATE INDEX IF NOT EXISTS idx_connections_threat_level ON connections (threat_level);
CREATE INDEX IF NOT EXISTS idx_connections_src_country ON connections (src_country);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;
EOF

    print_success "Database configured"
}

create_user() {
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d $INSTALL_DIR -M $SERVICE_USER
    fi
    usermod -aG pcap $SERVICE_USER 2>/dev/null || true
}

setup_dirs() {
    print_step "Setting up directories..."
    
    mkdir -p $INSTALL_DIR/{services,web,config}
    mkdir -p $LOG_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p /var/lib/netguard
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # Support both repo root and parent-project layouts
    if [[ -d "$SCRIPT_DIR/netguaedai/netguard/netguard/services" ]]; then
        cp -r "$SCRIPT_DIR/netguaedai/netguard/netguard/services/"* $INSTALL_DIR/services/
        cp -r "$SCRIPT_DIR/netguaedai/netguard/netguard/web/"* $INSTALL_DIR/web/
    else
        cp -r "$SCRIPT_DIR/netguard/netguard/services/"* $INSTALL_DIR/services/
        cp -r "$SCRIPT_DIR/netguard/netguard/web/"* $INSTALL_DIR/web/
    fi
    
    # Copy models if they exist
    if [[ -d "$SCRIPT_DIR/ai_training/models" ]]; then
        mkdir -p $INSTALL_DIR/models
        cp -r "$SCRIPT_DIR/ai_training/models/"* $INSTALL_DIR/models/
    fi
    
    chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
    chown -R $SERVICE_USER:$SERVICE_USER $LOG_DIR
    chmod 755 $LOG_DIR
    
    print_success "Directories created"
}

install_python() {
    print_step "Installing Python packages..."
    
    python3 -m venv $INSTALL_DIR/venv
    source $INSTALL_DIR/venv/bin/activate
    
    pip install -q --upgrade pip
    pip install -q scapy redis psycopg2-binary django requests python-dateutil numpy scikit-learn xgboost gunicorn daphne geoip2 paramiko
    
    print_success "Python packages installed"
}

setup_geoip() {
    print_step "Setting up GeoIP database..."
    
    source $INSTALL_DIR/venv/bin/activate
    
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    if [[ -f "$script_dir/scripts/download-geoip.sh" ]]; then
        bash "$script_dir/scripts/download-geoip.sh" "$INSTALL_DIR"
    else
        print_warning "GeoIP download script not found. Skipping automatic GeoIP setup."
    fi
    
    # Ensure netguard user can read the database if it exists
    if [[ -f "$INSTALL_DIR/GeoLite2-City.mmdb" ]]; then
        chown $SERVICE_USER:$SERVICE_USER "$INSTALL_DIR/GeoLite2-City.mmdb"
        chmod 644 "$INSTALL_DIR/GeoLite2-City.mmdb"
    fi
    
    print_success "GeoIP setup complete"
}

create_config() {
    print_step "Creating configuration..."
    
    cat > $CONFIG_DIR/netguard.conf << EOF
[database]
host = localhost
port = 5432
name = $DB_NAME
user = $DB_USER
password = $DB_PASS

[redis]
host = localhost
port = 6379
db = 0

[capture]
interface = $CAPTURE_INTERFACE
buffer_size = 65535
promiscuous = true

[processor]
batch_size = 50

[web]
host = 0.0.0.0
port = 8765

[retention]
days = $RETENTION_DAYS
EOF

    cat > $CONFIG_DIR/admin.conf << EOF
username=$ADMIN_USER
EOF
    chmod 600 $CONFIG_DIR/admin.conf
    
    echo "$ADMIN_PASS" > $CONFIG_DIR/.admin_pass
    chmod 600 $CONFIG_DIR/.admin_pass
    
    print_success "Configuration saved"
}

create_services() {
    print_step "Creating systemd services..."
    
    cat > /etc/systemd/system/netguard-capture.service << EOF
[Unit]
Description=NetGuard AI - Packet Capture
After=redis.service

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/services/capture.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/netguard-processor.service << EOF
[Unit]
Description=NetGuard AI - AI Processor
After=redis.service postgresql.service

[Service]
Type=simple
User=netguard
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/services/processor.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/netguard-web.service << EOF
[Unit]
Description=NetGuard AI - Web Interface
After=postgresql.service

[Service]
Type=simple
User=netguard
WorkingDirectory=$INSTALL_DIR/web
ExecStart=$INSTALL_DIR/venv/bin/daphne -b 0.0.0.0 -p 8765 netguard_web.asgi:application
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Services created"
}

setup_django() {
    print_step "Setting up Django..."
    
    cd $INSTALL_DIR/web
    
    sed -i 's/timescale.db.backends.postgresql/django.db.backends.postgresql/g' "$INSTALL_DIR/web/netguard_web/settings.py" 2>/dev/null || true
    
    $INSTALL_DIR/venv/bin/python manage.py migrate --noinput
    $INSTALL_DIR/venv/bin/python manage.py collectstatic --noinput
    
    print_success "Django configured"
}

create_admin() {
    print_step "Creating admin user..."
    
    ADMIN_USER=$(grep username $CONFIG_DIR/admin.conf | cut -d= -f2)
    ADMIN_PASS=$(cat $CONFIG_DIR/.admin_pass)
    
    cd $INSTALL_DIR/web
    $INSTALL_DIR/venv/bin/python << EOF
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netguard_web.settings')
django.setup()
from django.contrib.auth.models import User
if not User.objects.filter(username='$ADMIN_USER').exists():
    User.objects.create_superuser('$ADMIN_USER', '', '$ADMIN_PASS')
EOF
    
    rm -f $CONFIG_DIR/.admin_pass
    print_success "Admin user ready"
}

start_services() {
    print_step "Starting services..."
    
    systemctl start redis-server
    systemctl enable redis-server
    systemctl start postgresql
    
    systemctl start netguard-capture
    systemctl start netguard-processor
    systemctl start netguard-web
    
    systemctl enable netguard-capture netguard-processor netguard-web
    
    print_success "All services started"
}

main() {
    print_banner
    check_root
    get_user_input
    install_deps
    create_user
    setup_dirs
    setup_database
    install_python
    setup_geoip
    create_config
    create_services
    setup_django
    create_admin
    start_services
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  NetGuard AI Installed Successfully!   ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Web Interface: http://localhost:8765"
    echo "Username: $ADMIN_USER"
    echo ""
}

main
