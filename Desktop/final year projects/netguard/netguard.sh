#!/bin/bash
#
# NetGuard AI - Unified Management Script (Redis Version - No Kafka)
# Usage: ./netguard.sh [install|start|stop|restart|status|logs|uninstall]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Paths
INSTALL_DIR="/opt/netguard"
CONFIG_DIR="/etc/netguard"
LOG_DIR="/var/log/netguard"
SERVICE_USER="netguard"

# Defaults
DB_NAME="netguard"
DB_USER="netguard"
RETENTION_DAYS=30

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    NetGuard AI                               ║"
    echo "║         Network Intrusion Detection System                   ║"
    echo "║              (Lightweight - No Kafka)                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

is_installed() {
    [[ -d "$INSTALL_DIR" ]] && [[ -f "$CONFIG_DIR/netguard.conf" ]]
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
    raw_packet JSONB
);

CREATE INDEX idx_connections_time ON connections (time DESC);
CREATE INDEX idx_connections_threat ON connections (threat_score) WHERE threat_score > 0.5;
CREATE INDEX idx_connections_src_ip ON connections (src_ip);
CREATE INDEX idx_connections_dst_ip ON connections (dst_ip);

CREATE TABLE IF NOT EXISTS alerts (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    id BIGSERIAL PRIMARY KEY,
    alert_type TEXT,
    severity TEXT,
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
    cp -r "$SCRIPT_DIR/services/"* $INSTALL_DIR/services/ 2>/dev/null || true
    cp -r "$SCRIPT_DIR/web/"* $INSTALL_DIR/web/ 2>/dev/null || true
    
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
    pip install -q scapy redis psycopg2-binary django requests python-dateutil numpy scikit-learn
    
    print_success "Python packages installed"
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
batch_size = 100

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
    
    # Capture service
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

    # Processor service
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

    # Web service
    cat > /etc/systemd/system/netguard-web.service << EOF
[Unit]
Description=NetGuard AI - Web Interface
After=postgresql.service
[Service]
Type=simple
User=netguard
WorkingDirectory=$INSTALL_DIR/web
ExecStart=$INSTALL_DIR/venv/bin/gunicorn netguard_web.wsgi:application -b 0.0.0.0:8765 --workers 2
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Services created"
}

setup_django() {
    print_step "Setting up Django..."
    
    cd $INSTALL_DIR/web
    
    # Fix settings file - ensure regular PostgreSQL engine (not timescale)
    if [[ -f "$INSTALL_DIR/web/netguard_web/settings.py" ]]; then
        sed -i 's/timescale.db.backends.postgresql/django.db.backends.postgresql/g' "$INSTALL_DIR/web/netguard_web/settings.py"
        sed -i "/'channels'/d" "$INSTALL_DIR/web/netguard_web/settings.py"
    fi
    
    # Create minimal Django project if not exists
    if [[ ! -f "$INSTALL_DIR/web/manage.py" ]]; then
        $INSTALL_DIR/venv/bin/django-admin startproject netguard_web .
        $INSTALL_DIR/venv/bin/python manage.py startapp dashboard
        
        # Create basic files
        mkdir -p dashboard/templates/dashboard
        
        cat > netguard_web/settings.py << EOF
import os
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = 'netguard-secret-key-change-in-production'
DEBUG = False
ALLOWED_HOSTS = ['*']
INSTALLED_APPS = ['django.contrib.admin', 'django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'django.contrib.messages', 'django.contrib.staticfiles', 'dashboard']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.common.CommonMiddleware', 'django.middleware.csrf.CsrfViewMiddleware', 'django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.messages.middleware.MessageMiddleware']
ROOT_URLCONF = 'netguard_web.urls'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [BASE_DIR / 'templates'], 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.debug', 'django.template.context_processors.request', 'django.contrib.auth.context_processors.auth', 'django.contrib.messages.context_processors.messages']}}]
WSGI_APPLICATION = 'netguard_web.wsgi.application'
DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql', 'NAME': '$DB_NAME', 'USER': '$DB_USER', 'PASSWORD': '$DB_PASS', 'HOST': 'localhost', 'PORT': '5432'}}
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'
EOF

        cat > netguard_web/urls.py << EOF
from django.contrib import admin
from django.urls import path, include
urlpatterns = [path('admin/', admin.site.urls), path('', include('dashboard.urls'))]
EOF

        cat > dashboard/urls.py << EOF
from django.urls import path
from . import views
urlpatterns = [path('', views.dashboard_view, name='dashboard'), path('login/', views.login_view, name='login'), path('logout/', views.logout_view, name='logout'), path('api/stats/', views.api_stats, name='api_stats'), path('api/connections/', views.api_connections, name='api_connections')]
EOF

        cat > dashboard/views.py << EOF
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db import connections

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    error = None
    if request.method == 'POST':
        user = authenticate(request, username=request.POST.get('username'), password=request.POST.get('password'))
        if user:
            login(request, user)
            return redirect('dashboard')
        error = 'Invalid credentials'
    return render(request, 'dashboard/login.html', {'error': error})

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def dashboard_view(request):
    return render(request, 'dashboard/dashboard.html')

@login_required
def api_stats(request):
    try:
        with connections['default'].cursor() as cursor:
            cursor.execute("SELECT COUNT(*), COUNT(DISTINCT src_ip), SUM(bytes_in + bytes_out), COUNT(CASE WHEN threat_score > 0.5 THEN 1 END) FROM connections WHERE time > NOW() - INTERVAL '5 minutes'")
            row = cursor.fetchone()
            return JsonResponse({'connections_5min': row[0] or 0, 'unique_sources': row[1] or 0, 'total_bytes': row[2] or 0, 'threats': row[3] or 0})
    except:
        return JsonResponse({'connections_5min': 0, 'unique_sources': 0, 'total_bytes': 0, 'threats': 0})

@login_required
def api_connections(request):
    try:
        with connections['default'].cursor() as cursor:
            cursor.execute("SELECT time, src_ip, dst_ip, domain, protocol, bytes_in + bytes_out as bytes, threat_score, threat_type FROM connections ORDER BY time DESC LIMIT 100")
            columns = [desc[0] for desc in cursor.description]
            return JsonResponse({'connections': [dict(zip(columns, row)) for row in cursor.fetchall()]})
    except Exception as e:
        return JsonResponse({'connections': [], 'error': str(e)})
EOF

        # Templates
        cat > dashboard/templates/dashboard/login.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>NetGuard AI - Login</title><style>
body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login-box{background:#1e293b;padding:2rem;border-radius:8px;width:300px}
h1{color:#3b82f6;margin-top:0}input{width:100%;padding:0.5rem;margin:0.5rem 0;background:#0f172a;border:1px solid #334155;color:#fff}
button{width:100%;padding:0.75rem;background:#3b82f6;color:#fff;border:none;border-radius:4px;cursor:pointer}
.error{color:#ef4444;margin-bottom:1rem}
</style></head>
<body>
<div class="login-box">
<h1>NetGuard AI</h1>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="post">{% csrf_token %}
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
</div>
</body>
</html>
HTMLEOF

        cat > dashboard/templates/dashboard/dashboard.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>NetGuard AI</title><style>
body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;margin:0}
.navbar{background:#1e293b;padding:1rem 2rem;display:flex;justify-content:space-between}
.navbar a{color:#94a3b8;text-decoration:none}
.container{padding:2rem}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
.stat-card{background:#1e293b;padding:1rem;border-radius:8px}
.stat-label{color:#94a3b8;font-size:.875rem}
.stat-value{font-size:1.5rem;font-weight:bold}
table{width:100%;background:#1e293b;border-radius:8px}
th,td{padding:.75rem;text-align:left;border-bottom:1px solid #334155}
th{color:#94a3b8}
</style></head>
<body>
<div class="navbar">
<strong style="color:#3b82f6">NetGuard AI</strong>
<a href="{% url 'logout' %}">Logout</a>
</div>
<div class="container">
<h2>Dashboard</h2>
<div class="stats">
<div class="stat-card"><div class="stat-label">Connections (5m)</div><div class="stat-value" id="conn-count">-</div></div>
<div class="stat-card"><div class="stat-label">Sources</div><div class="stat-value" id="src-count">-</div></div>
<div class="stat-card"><div class="stat-label">Traffic</div><div class="stat-value" id="byte-count">-</div></div>
<div class="stat-card"><div class="stat-label">Threats</div><div class="stat-value" id="threat-count">-</div></div>
</div>
<h3>Recent Connections</h3>
<table id="conn-table">
<thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Domain</th><th>Protocol</th><th>Bytes</th><th>Threat</th></tr></thead>
<tbody></tbody>
</table>
</div>
<script>
async function loadData(){
const stats=await fetch('/api/stats/').then(r=>r.json());
document.getElementById('conn-count').textContent=stats.connections_5min;
document.getElementById('src-count').textContent=stats.unique_sources;
document.getElementById('byte-count').textContent=(stats.total_bytes/1024/1024).toFixed(2)+' MB';
document.getElementById('threat-count').textContent=stats.threats;
const conns=await fetch('/api/connections/').then(r=>r.json());
document.querySelector('#conn-table tbody').innerHTML=conns.connections.map(c=>`<tr><td>${new Date(c.time).toLocaleTimeString()}</td><td>${c.src_ip}</td><td>${c.dst_ip}</td><td>${c.domain||'-'}</td><td>${c.protocol}</td><td>${c.bytes}</td><td>${c.threat_score>0.5?'⚠️':'✓'}</td></tr>`).join('');
}
loadData();
setInterval(loadData,3000);
</script>
</body>
</html>
HTMLEOF
    fi
    
    # Run migrations properly
    $INSTALL_DIR/venv/bin/python manage.py migrate auth --noinput
    $INSTALL_DIR/venv/bin/python manage.py migrate admin --noinput
    $INSTALL_DIR/venv/bin/python manage.py migrate sessions --noinput
    $INSTALL_DIR/venv/bin/python manage.py migrate contenttypes --noinput
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

stop_services() {
    print_step "Stopping services..."
    systemctl stop netguard-web netguard-processor netguard-capture 2>/dev/null || true
    print_success "Services stopped"
}

show_status() {
    echo ""
    echo -e "${BLUE}=== NetGuard AI Status ===${NC}"
    echo ""
    for svc in redis-server postgresql netguard-capture netguard-processor netguard-web; do
        status=$(systemctl is-active $svc 2>/dev/null || echo "inactive")
        if [[ "$status" == "active" ]]; then
            echo -e "  ✅ $svc"
        else
            echo -e "  ❌ $svc"
        fi
    done
    echo ""
    if systemctl is-active netguard-web &>/dev/null; then
        print_success "Web UI: http://localhost:8765"
    fi
}

show_logs() {
    echo "Select log: 1) Capture 2) Processor 3) Web 4) All"
    read -p "Choice [1]: " choice
    choice=${choice:-1}
    case $choice in
        1) tail -f $LOG_DIR/capture.log ;;
        2) tail -f $LOG_DIR/processor.log ;;
        3) tail -f $LOG_DIR/web.log ;;
        4) tail -f $LOG_DIR/*.log ;;
    esac
}

uninstall() {
    print_warning "This will remove NetGuard AI!"
    read -p "Are you sure? (yes/no): " confirm
    [[ "$confirm" != "yes" ]] && { print_info "Cancelled"; exit 0; }
    
    stop_services
    rm -f /etc/systemd/system/netguard-*.service
    systemctl daemon-reload
    rm -rf $INSTALL_DIR $CONFIG_DIR $LOG_DIR
    
    print_success "NetGuard AI removed"
}

install() {
    if is_installed; then
        print_warning "Already installed"
        read -p "Reinstall? (yes/no): " confirm
        [[ "$confirm" != "yes" ]] && exit 0
        stop_services
    fi
    
    print_banner
    check_root
    get_user_input
    
    install_deps
    create_user
    setup_dirs
    setup_database
    install_python
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
    echo "Web Interface: http://localhost:8000"
    echo "Username: $ADMIN_USER"
    echo ""
    echo "Commands:"
    echo "  sudo ./netguard.sh status  - Check status"
    echo "  sudo ./netguard.sh stop    - Stop services"
    echo "  sudo ./netguard.sh start   - Start services"
    echo "  sudo ./netguard.sh logs    - View logs"
    echo ""
}

case "${1:-install}" in
    install) install ;;
    start) check_root; start_services; show_status ;;
    stop) check_root; stop_services ;;
    restart) check_root; stop_services; sleep 2; start_services; show_status ;;
    status) show_status ;;
    logs) show_logs ;;
    uninstall) check_root; uninstall ;;
    *)
        echo "Usage: $0 [install|start|stop|restart|status|logs|uninstall]"
        exit 1
        ;;
esac
