#!/bin/bash
set -e

# Default values
SERVICE_NAME=${SERVICE_NAME:-web}
CAPTURE_INTERFACE=${CAPTURE_INTERFACE:-eth0}
ADMIN_USER=${ADMIN_USER:-admin}
ADMIN_PASS=${ADMIN_PASS:-admin}
DB_NAME=${DB_NAME:-netguard}
DB_USER=${DB_USER:-netguard}
DB_PASS=${DB_PASS:-netguard}
DB_HOST=${DB_HOST:-postgres}
DB_PORT=${DB_PORT:-5432}
REDIS_HOST=${REDIS_HOST:-redis}
REDIS_PORT=${REDIS_PORT:-6379}

# Update config file with environment variables
sed -i "s/^host = .*/host = ${DB_HOST}/" /etc/netguard/netguard.conf
sed -i "s/^port = .*/port = ${DB_PORT}/" /etc/netguard/netguard.conf
sed -i "s/^name = .*/name = ${DB_NAME}/" /etc/netguard/netguard.conf
sed -i "s/^user = .*/user = ${DB_USER}/" /etc/netguard/netguard.conf
sed -i "s/^password = .*/password = ${DB_PASS}/" /etc/netguard/netguard.conf
sed -i "s/^host = .*/host = ${REDIS_HOST}/" /etc/netguard/netguard.conf
sed -i "s/^port = .*/port = ${REDIS_PORT}/" /etc/netguard/netguard.conf
sed -i "s/^interface = .*/interface = ${CAPTURE_INTERFACE}/" /etc/netguard/netguard.conf

echo "=== NetGuard AI Docker ==="
echo "Service: ${SERVICE_NAME}"
echo "Capture Interface: ${CAPTURE_INTERFACE}"
echo "Database: ${DB_HOST}:${DB_PORT}"
echo "Redis: ${REDIS_HOST}:${REDIS_PORT}"
echo "=========================="

# Setup function for database migrations and admin user
setup_django() {
    echo "Waiting for PostgreSQL..."
    until pg_isready -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" > /dev/null 2>&1; do
        sleep 1
    done
    echo "PostgreSQL is ready!"

    cd /opt/netguard/web

    echo "Running migrations..."
    python manage.py migrate --noinput

    echo "Collecting static files..."
    python manage.py collectstatic --noinput

    echo "Creating admin user..."
    python -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netguard_web.settings')
django.setup()
from django.contrib.auth.models import User
if not User.objects.filter(username='${ADMIN_USER}').exists():
    User.objects.create_superuser('${ADMIN_USER}', '', '${ADMIN_PASS}')
    print('Admin user created: ${ADMIN_USER}')
else:
    print('Admin user already exists: ${ADMIN_USER}')
"
}

# Route to correct service
case "${SERVICE_NAME}" in
    setup)
        setup_django
        echo "Setup complete!"
        ;;

    capture)
        echo "Starting Packet Capture..."
        exec python /opt/netguard/services/capture.py
        ;;

    processor)
        echo "Starting AI Processor..."
        # Wait for DB and Redis
        sleep 5
        exec python /opt/netguard/services/processor.py
        ;;

    web)
        setup_django
        echo "Starting Web Server..."
        cd /opt/netguard/web
        exec gunicorn netguard_web.wsgi:application \
            -b 0.0.0.0:8765 \
            --workers 2 \
            --timeout 60 \
            --access-logfile - \
            --error-logfile -
        ;;

    *)
        echo "Unknown service: ${SERVICE_NAME}"
        echo "Valid services: setup, capture, processor, web"
        exit 1
        ;;
esac
