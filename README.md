
NetGuard AI
Network Intrusion Detection System with AI/ML Analysis
Features
·	Real-time Packet Capture - Scapy-based capture with immediate timestamps
·	AI Threat Detection - ML-powered analysis of network flows
·	Web Dashboard - Live view, historical search, alerts
·	Domain Resolution - Shows domain names for connections
·	30-Day Retention - Automatic data rotation
·	Offline Log Access - Access logs even when web UI is down
Architecture
Scapy Capture → Kafka → AI Processor → TimescaleDB → Django Web UI
     ↓              ↓         ↓              ↓              ↓
  systemd       systemd   systemd      systemd        systemd

Installation
Prerequisites
·	Ubuntu/Debian system
·	Root access (sudo)
·	Network interface for capture
One-Command Install
cd /path/to/netguard
sudo ./install.sh

This will:
1.	Install all dependencies (Python, PostgreSQL, TimescaleDB, Kafka)
2.	Create database and user
3.	Set up configuration files
4.	Create systemd services
Post-Install Setup
sudo ./install-services.sh

This will:
1.	Set up Django database
2.	Create admin user (from install.sh credentials)
3.	Start all services
4.	Enable auto-start on boot
Access
·	Web Interface: http://localhost:8000
·	Login: Credentials set during install.sh
Service Management
# View all services
systemctl status netguard-*

# Restart capture
sudo systemctl restart netguard-capture

# View logs
sudo journalctl -u netguard-capture -f
tail -f /var/log/netguard/capture.log

Offline Access (When Web UI is Down)
View Raw Capture Logs
tail -f /var/log/netguard/capture.log

Query Database Directly
sudo -u postgres psql netguard -c "SELECT * FROM connections ORDER BY time DESC LIMIT 10;"

View Kafka Topics
/opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic netguard-capture --from-beginning

Configuration
Edit /etc/netguard/netguard.conf:
[capture]
interface = eth0  # Change to your network interface

[retention]
days = 30  # Data retention period

[web]
port = 8000  # Web interface port

After changes, restart services:
sudo systemctl restart netguard-*

File Locations
Component	Location
Installation	/opt/netguard/
Configuration	/etc/netguard/
Logs	/var/log/netguard/
Database	PostgreSQL with TimescaleDB
Kafka Data	/var/lib/kafka/

Troubleshooting
Services won't start
# Check logs
sudo journalctl -xe

# Check specific service
sudo systemctl status netguard-capture
sudo tail -f /var/log/netguard/capture.log

No data in web interface
1.	Check capture is running: sudo systemctl status netguard-capture
2.	Check Kafka topics: /opt/kafka/bin/kafka-topics.sh --list --bootstrap-server localhost:9092
3.	Check database: sudo -u postgres psql netguard -c "SELECT COUNT(*) FROM connections;"
Permission denied on capture
Capture service runs as root (required for packet capture). Check:
sudo systemctl cat netguard-capture

License
MIT License
