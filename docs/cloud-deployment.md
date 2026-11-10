# Cyber Digital Twin — Enterprise Cloud Deployment & Containerization Guide

**Subsystem Status**: Complete & Production-Ready  
**Specification Version**: 1.0.0 (Phase 31 & Phase 32)  
**Target Environments**: Linux Bare-Metal, AWS (EC2/ECS), GCP (Compute Engine/Cloud Run), Azure (VM/ACI), Docker Compose, Kubernetes

---

## 1. Executive Architecture Overview

Cyber Digital Twin employs an enterprise three-tier microservice architecture designed for high availability, zero-trust security isolation, and horizontal scalability across Linux cloud environments.

```
                  +----------------------------------------------+
                  |         Internet / Corporate Ingress         |
                  +----------------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |   Nginx Reverse Proxy / WAF   |
                         |   (Port 80/443, SSL/TLS, Gzip)|
                         +-------------------------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                       v                                   v
        +-----------------------------+     +-----------------------------+
        |   Frontend Static Assets    |     |  Backend FastAPI API Hub    |
        |   (Vanilla JS, Chart.js,    |     |  (Uvicorn 4-worker cluster) |
        |    Tailwind/Cyber CSS)      |     |  Port 8000 (Internal)       |
        +-----------------------------+     +-----------------------------+
                                                           |
                                                           v
                                            +-----------------------------+
                                            |     PostgreSQL 16 Engine    |
                                            |   (Persistent Volume Mount) |
                                            |   Port 5432 (Internal VPC)  |
                                            +-----------------------------+
```

### Core Components
1. **Frontend Service (`Dockerfile.frontend`)**:
   - High-performance `nginx:alpine` image serving cybernetic monitoring dashboard assets.
   - Built-in reverse proxy routing `/api/`, `/health`, and documentation `/docs` to backend.
   - Security headers preconfigured: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`.

2. **Backend Service (`Dockerfile.backend`)**:
   - Python 3.12-slim multi-stage hardened image.
   - Runs as unprivileged non-root service user `appuser` (UID 10001).
   - High-throughput Uvicorn ASGI server with 4 asynchronous worker processes.
   - Integrated TTL cache layer and automatic graceful failover for offline environments.

3. **Database Tier (`docker-compose.yml`)**:
   - PostgreSQL 16 Alpine container with parameterized credentials and volume persistency (`postgres_data`).
   - Integrated health check probe verifying SQL connectivity every 10 seconds.

---

## 2. Docker Compose Deployment

### 2.1 Quickstart
To launch the entire platform with a single command:

```bash
# Clone the repository
git clone https://github.com/mjishaan59-cell/CYBER-TWIN.git
cd CYBER-TWIN

# Launch container stack in detached mode
docker compose up -d --build

# Verify container status and health
docker compose ps
```

### 2.2 Access Points & Default Authentication
- **Web UI & Security Operations Center (SOC)**: `http://localhost/` or `http://<server-ip>/`
- **Backend REST API**: `http://localhost:8000/` or `http://<server-ip>:8000/`
- **Interactive Swagger Docs**: `http://localhost/docs` or `http://localhost:8000/docs`
- **Health Check Probe**: `http://localhost/health`

#### Preconfigured Access Credentials:
| Account Role | Username | Password | Access Rights |
| :--- | :--- | :--- | :--- |
| **System Admin** | `admin` | `admin123` | Full superuser access to run playbooks, attack simulations, and configure fleet. |
| **Security Analyst** | `analyst` | `analyst123` | Security monitoring, telemetry analytics, and dry-run playbooks. |
| **Read-Only Viewer** | `viewer` | `viewer123` | Read-only inspection of dashboards and historical metrics. |
| **PostgreSQL Database** | `postgres` | `postgres123` | Relational database engine on port `5432` (`cyber_digital_twin`). |

*(Tip: When opening `http://localhost/` or `http://localhost:8000/`, click "Auto-Fill & Enter Dashboard" to sign in instantly with administrator privileges.)*

---

## 3. Native Linux Deployment via Systemd

For enterprise bare-metal installations or dedicated Linux compute nodes where Docker is restricted:

### 3.1 System User and Directory Setup
```bash
sudo useradd -r -s /bin/false cybertwin
sudo mkdir -p /opt/cyber-twin/logs /opt/cyber-twin/data
sudo cp -r . /opt/cyber-twin/
sudo chown -R cybertwin:cybertwin /opt/cyber-twin
```

### 3.2 Virtual Environment & Dependencies
```bash
cd /opt/cyber-twin
sudo -u cybertwin python3 -m venv venv
sudo -u cybertwin ./venv/bin/pip install --upgrade pip
sudo -u cybertwin ./venv/bin/pip install -r requirements.txt
```

### 3.3 Systemd Service Activation
Copy the included service unit into `/etc/systemd/system/`:
```bash
sudo cp deployment/systemd/cyber-twin-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cyber-twin-backend
sudo systemctl status cyber-twin-backend
```

---

## 4. Cloud Provider Deployment Playbooks

### 4.1 Amazon Web Services (AWS)
#### Option A: EC2 Elastic Compute Cloud
1. Launch an Ubuntu 24.04 LTS `t3.medium` instance with an attached EBS volume (min 30 GB).
2. Attach an IAM Role with Systems Manager (SSM) permissions.
3. Configure Security Group:
   - Inbound `80/tcp` & `443/tcp` from Allowed CIDRs or `0.0.0.0/0`.
   - Inbound `22/tcp` from corporate VPN only.
4. Run `deploy_cloud.sh` in the repository root.

#### Option B: Amazon ECS (Elastic Container Service) with Fargate
- Push `cyber-twin-backend` and `cyber-twin-frontend` images to Amazon ECR.
- Define an ECS Task Definition mapping container dependencies.
- Provision Amazon Aurora PostgreSQL Serverless v2 for auto-scaling persistence.
- Place an AWS Application Load Balancer (ALB) with ACM TLS certificate in front of the frontend task.

### 4.2 Google Cloud Platform (GCP)
#### Option A: Compute Engine
1. Deploy an `e2-standard-2` VM running Debian 12 or Ubuntu 24.04.
2. Grant Cloud SQL Client and Logging Writer roles to the Service Account.
3. Execute the automated installer:
   ```bash
   bash deployment/scripts/deploy_cloud.sh
   ```

#### Option B: Cloud Run + Cloud SQL
- Build and push containers to Google Artifact Registry:
  ```bash
  gcloud builds submit --tag gcr.io/$PROJECT_ID/cyber-twin-backend -f Dockerfile.backend
  ```
- Deploy backend to Cloud Run with direct Cloud SQL Auth Proxy VPC connection.

### 4.3 Microsoft Azure
#### Azure Virtual Machine
1. Create a `Standard_B2s` Linux VM in an isolated Virtual Network (VNet).
2. Install Docker and Docker Compose plugin.
3. Run `docker compose up -d` within `/opt/cyber-twin`.

---

## 5. SSL / TLS Hardening with Let's Encrypt

To provision free trusted SSL certificates via Certbot and Nginx:

```bash
# 1. Install Certbot
sudo apt-get update && sudo apt-get install -y certbot python3-certbot-nginx

# 2. Issue Certificate (Replace yourdomain.com with your FQDN)
sudo certbot --nginx -d cybertwin.example.com --non-interactive --agree-tos -m security@example.com

# 3. Verify Automatic Renewal
sudo certbot renew --dry-run
```

---

## 6. Backup and Disaster Recovery

### Automated Backup Pipeline
The included backup script (`deployment/scripts/backup_database.sh`) creates gzipped SQL dumps and rotates files older than 7 days:

```bash
# Execute on-demand backup
bash deployment/scripts/backup_database.sh

# Install Daily Cron Job (Runs at 02:00 AM UTC every day)
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/cyber-twin/deployment/scripts/backup_database.sh >> /var/log/cyber-twin-backup.log 2>&1") | crontab -
```

### Database Restoration Procedure
In the event of database corruption or failover recovery:

```bash
bash deployment/scripts/restore_database.sh /opt/cyber-twin/backups/cybertwin_backup_20261110_120000.sql.gz
```

---

## 7. Operational Readiness Checklist

| Category | Component | Status | Verification Command |
| :--- | :--- | :--- | :--- |
| **Container** | Docker Engine & Compose | Verified | `docker compose ps` |
| **Backend** | FastAPI + Uvicorn | Verified | `curl http://localhost:8000/health` |
| **Frontend** | Nginx Alpine Web Server | Verified | `curl -I http://localhost:80/` |
| **Database** | PostgreSQL 16 Persistence | Verified | `docker compose exec postgres pg_isready` |
| **Security** | Non-root Container User | Verified | `docker exec <backend_container> id` |
| **Service** | Linux Systemd Unit | Verified | `systemctl status cyber-twin-backend` |
| **Disaster Recovery** | Backup & Restore Pipeline | Verified | `bash deployment/scripts/backup_database.sh` |
