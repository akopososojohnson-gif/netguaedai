# 🛡️ NetGuard AI

> **Real-Time Network Intrusion Detection System with AI/ML Analysis**

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.1-green?logo=django)](https://djangoproject.com)
[![Scapy](https://img.shields.io/badge/Scapy-2.6.1-orange)](https://scapy.net)
[![XGBoost](https://img.shields.io/badge/XGBoost-3.0-red)](https://xgboost.ai)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

NetGuard AI is a production-ready network intrusion detection system that captures live network traffic using **Scapy**, analyzes it with an **ensemble of machine learning models** (XGBoost, Random Forest, and Isolation Forest), and presents real-time alerts through a modern **Django web dashboard**.

---

## ✨ Features

- 🔴 **Real-Time Packet Capture** — Scapy-based capture with immediate timestamps
- 🤖 **AI Threat Detection** — Ensemble ML with XGBoost, Random Forest, and Isolation Forest
- 📊 **Live Web Dashboard** — Real-time view, historical search, alerts, and analytics
- 🌐 **Domain Resolution** — Shows domain names for DNS/HTTP/HTTPS connections
- 🔔 **Alert Notifications** — Desktop notifications for critical/high threats
- 📅 **30-Day Retention** — Automatic data rotation in PostgreSQL
- 📝 **Offline Log Access** — Access logs even when web UI is down
- 🐳 **Docker Support** — Optional containerized deployment
- ⚡ **Lightweight** — No Kafka dependency, uses Redis as message queue

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           NETGUARD AI PIPELINE                              │
└─────────────────────────────────────────────────────────────────────────────┘

   Network Traffic
        │
        ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────────────┐
│  Packet Capture │      │                 │      │                         │
│   (Scapy)       │─────▶│   Redis Queue   │─────▶│    AI Processor         │
│   Root Priv     │      │  netguard:      │      │  • XGBoost (0.5)        │
│                 │      │  capture        │      │  • Random Forest (0.3)  │
└─────────────────┘      │  netguard:      │      │  • Isolation Forest (0.2│
                         │  alerts         │      │                         │
                         └─────────────────┘      └───────────┬─────────────┘
                                                                │
                                                                ▼
                                                       ┌─────────────────┐
                                                       │   PostgreSQL    │
                                                       │  connections &  │
                                                       │    alerts       │
                                                       └────────┬────────┘
                                                                │
                                                                ▼
                                                       ┌─────────────────┐
                                                       │  Django Web UI  │
                                                       │   Port 8765     │
                                                       └─────────────────┘
```

### Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Packet Capture** | Scapy | Raw packet capture from network interface |
| **Message Queue** | Redis | Decouples capture from AI processing |
| **AI Engine** | XGBoost + Random Forest + Isolation Forest | Threat classification and anomaly detection |
| **Database** | PostgreSQL | Persistent storage for connections and alerts |
| **Web Dashboard** | Django + Daphne | Real-time visualization and management |

---

## 📋 Prerequisites

- Ubuntu/Debian-based system (Parrot OS, Kali, Ubuntu)
- Root/sudo access
- Network interface for packet capture (e.g., `eth0`, `wlp2s0`)
- Python 3.11+
- PostgreSQL 16
- Redis 7

---

## 🚀 Quick Start

### Option 1: One-Command Start (Recommended)

```bash
cd "final year project"
sudo ./start.sh
```

Then open: **http://localhost:8765**

### Option 2: Manual Start/Stop

```bash
cd "final year project/netguaedai/netguard/netguard"

# Start all services
sudo ./netguard.sh start

# Check status
sudo ./netguard.sh status

# View logs
sudo ./netguard.sh logs

# Stop all services
sudo ./netguard.sh stop
```

---

## 🐳 Docker Deployment

> **Note**: Docker requires working DNS to pull base images. If you experience registry lookup errors, use the systemd method above.

```bash
cd "final year project"

# Start with Docker Compose
docker-compose up --build -d

# Start with packet capture (requires root)
sudo docker-compose --profile capture up --build -d

# View logs
docker-compose logs -f

# Stop everything
docker-compose down
```

### Docker Services

| Service | Description | Port |
|---------|-------------|------|
| `postgres` | PostgreSQL database | 5432 |
| `redis` | Redis message queue | 6379 |
| `web` | Django web dashboard | 8765 |
| `processor` | AI inference engine | — |
| `capture` | Packet capture (privileged) | — |

---

## 🔧 Installation from Scratch

If NetGuard is not yet installed:

```bash
cd "final year project/netguaedai/netguard/netguard"
sudo ./netguard.sh install
```

You will be prompted for:
- Admin username and password
- Database password
- Data retention days
- Network interface to monitor

---

## 🖥️ Dashboard

The web interface provides:

| Page | URL | Description |
|------|-----|-------------|
| **Dashboard** | `/` | Analytics, charts, and threat overview |
| **Connections** | `/connections/` | Live network connections table |
| **Threats** | `/threats/` | Detected threats in last 24 hours |
| **Alerts** | `/alerts/` | Security alerts with acknowledgment |
| **Login** | `/login/` | Authentication |

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats/` | GET | Current statistics |
| `/api/connections/` | GET | Recent connections |
| `/api/threats/` | GET | Detected threats |
| `/api/alerts/recent/` | GET | Recent alerts |
| `/api/alerts/<id>/acknowledge/` | POST | Acknowledge alert |
| `/api/search/` | GET | Historical search |

---

## 🤖 Machine Learning Models

### Model Performance

| Model | Type | Accuracy | Ensemble Weight |
|-------|------|----------|-----------------|
| **XGBoost** | Gradient Boosting | 99.88% | 0.5 |
| **Random Forest** | Bagging Ensemble | 99.80% | 0.3 |
| **Isolation Forest** | Anomaly Detection | 79.54% | 0.2 |

### Hyperparameters

**XGBoost:**
```python
xgb.XGBClassifier(
    objective='binary:logistic',
    eval_metric='logloss',
    max_depth=8,
    learning_rate=0.1,
    n_estimators=200,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=5.86,
    random_state=42,
    n_jobs=-1
)
```

**Random Forest:**
```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
```

### Class Imbalance Handling

- **No SMOTE** was used (avoids synthetic overfitting on rare attacks like Heartbleed)
- XGBoost: `scale_pos_weight=5.86`
- Random Forest: `class_weight='balanced'`

### Threat Thresholds

| Score | Classification |
|-------|---------------|
| `< 0.5` | Normal |
| `0.5 – 0.7` | Suspicious |
| `≥ 0.7` | Threat (alert generated) |
| `≥ 0.9` | Critical |

---

## 📊 Performance Characteristics

| Metric | Value |
|--------|-------|
| **Detection Latency** | ~2–5 ms |
| **Max Throughput** | ~500–800 flows/sec |
| **Total RAM Usage** | ~1 GB |
| **Web API Throughput** | ~100 req/sec |
| **Redis Queue Capacity** | 10,000 packets |

---

## 🔒 Security

- **Privilege Separation**: Capture runs as root; processor and web run as unprivileged `netguard` user
- **CSRF Protection**: Django CSRF middleware enabled
- **Session Management**: 1-hour expiry
- **Parameterized Queries**: Prevents SQL injection
- **Alert Audit Trail**: Every acknowledged alert logs username and timestamp
- **Port Whitelisting**: Reduces false positives for DNS, HTTP, HTTPS, NTP, DHCP

---

## 📁 Project Structure

```
final year project/
├── README.md
├── start.sh                          # One-command system starter
├── requirements.txt                  # Python dependencies
├── Dockerfile                        # Docker image
├── docker-compose.yml                # Docker orchestration
├── docker/
│   ├── entrypoint.sh
│   ├── config/netguard.conf
│   └── init-db.sql
├── ai_training/
│   ├── train_models.py              # Model training script
│   └── models/                      # Trained ML models
└── netguaedai/netguard/netguard/
    ├── netguard.sh                  # Install/management script
    ├── services/
    │   ├── capture.py               # Packet capture service
    │   └── processor.py             # AI inference service
    └── web/                         # Django web application
```

---

## 🛠️ Troubleshooting

### Web UI not loading
```bash
# Check web service
sudo systemctl status netguard-web

# Ensure gunicorn/daphne is installed
sudo /opt/netguard/venv/bin/pip install gunicorn daphne
sudo systemctl restart netguard-web
```

### No data in dashboard
```bash
# Check capture is running
sudo systemctl status netguard-capture

# Check Redis
redis-cli ping

# Check database
sudo -u postgres psql netguard -c "SELECT COUNT(*) FROM connections;"
```

### Too many false positives
The processor already uses weighted ensemble + port whitelisting. If still too high:
```bash
# Edit processor threshold
sudo nano /opt/netguard/services/processor.py
sudo systemctl restart netguard-processor
```

---

## 🧪 Training New Models

```bash
cd "final year project/ai_training"

# Install dependencies
pip3 install --user --break-system-packages pandas scikit-learn xgboost pyarrow

# Train models (place CICIDS2017 parquet files in cicsd dataset/archive/)
python3 train_models.py

# Copy models to system
sudo cp -r models/* /opt/netguard/models/
sudo systemctl restart netguard-processor
```

---

## 📜 License

MIT License — see LICENSE file for details.

---

## 🙏 Acknowledgments

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) — Canadian Institute for Cybersecurity
- [Scapy](https://scapy.net/) — Packet manipulation library
- [XGBoost](https://xgboost.ai/) — Gradient boosting framework
- [Django](https://www.djangoproject.com/) — Web framework
