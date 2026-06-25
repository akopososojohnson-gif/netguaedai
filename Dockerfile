FROM debian:bookworm-slim

# Prevent Python from writing pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV DOCKER_ENV=1

# Install Python 3.11 and system dependencies from Debian repos
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    libpcap-dev \
    gcc \
    libpq-dev \
    postgresql-client \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Ensure pip uses python3
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Create app directory
WORKDIR /opt/netguard

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application code
COPY netguard/netguard/services/ ./services/
COPY netguard/netguard/web/ ./web/
COPY docker/config/netguard.conf /etc/netguard/netguard.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create non-root user for processor and web
RUN useradd -r -s /bin/false netguard

# Create directories for logs and models
RUN mkdir -p /var/log/netguard /opt/netguard/models /opt/netguard/web/staticfiles \
    && chown -R netguard:netguard /var/log/netguard /opt/netguard

# Set PYTHONPATH
ENV PYTHONPATH=/opt/netguard
ENV DJANGO_SETTINGS_MODULE=netguard_web.settings

ENTRYPOINT ["/entrypoint.sh"]
