# ALDECI High Availability Deployment Guide

Production deployment guide for ALDECI with full HA guarantees.
Two deployment paths: Docker Compose (single-host HA) and Kubernetes/Helm (multi-node HA).

---

## Architecture

```
                        ┌──────────────────────────────────────────┐
                        │              Internet / VPN              │
                        └──────────────────┬───────────────────────┘
                                           │
                              ┌────────────▼────────────┐
                              │   Nginx Load Balancer   │
                              │   :80 / :443 (TLS)      │
                              │   /healthz /readyz      │
                              │   /startupz             │
                              └────┬──────────┬─────────┘
                                   │          │
                    ┌──────────────▼──┐  ┌───▼──────────────┐
                    │  ALDECI API #1  │  │  ALDECI API #2   │
                    │  FastAPI :8000  │  │  FastAPI :8000    │
                    │  gunicorn 2w    │  │  gunicorn 2w      │
                    └──────┬──────┬──┘  └──┬──────┬────────┘
                           │      │        │      │
              ┌────────────▼──────▼────────▼──┐   │
              │        Redis 7 (AOF)          │   │
              │   Cache + Sessions + Rate     │   │
              │   Limiting + Job Queue        │   │
              │   :6379                       │   │
              └───────────────────────────────┘   │
                                                  │
              ┌───────────────────────────────┐   │
              │   Shared Volume (SQLite DBs)  │◄──┘
              │   /app/data — 334 engine DBs  │
              │   WAL mode for concurrency    │
              └───────────────────────────────┘

              ┌───────────────────────────────┐
              │  PostgreSQL 16 Primary        │
              │  :5432 — future migration     │
              │  WAL archiving enabled        │
              └──────────────┬────────────────┘
                             │ streaming replication
              ┌──────────────▼────────────────┐
              │  PostgreSQL 16 Replica (RO)   │
              │  :5433 — read queries         │
              └───────────────────────────────┘

              ┌───────────────────────────────┐
              │   ALDECI UI (React 19)        │
              │   Nginx :80 → Vite build      │
              │   SPA fallback                │
              └───────────────────────────────┘
```

### Kubernetes Architecture

```
                        ┌──────────────────────────────────────────┐
                        │          Ingress Controller (nginx)      │
                        │  TLS termination, rate limiting, CORS    │
                        └──────────┬─────────────┬─────────────────┘
                                   │             │
                     ┌─────────────▼───┐   ┌─────▼─────────────┐
                     │  Service: API   │   │  Service: UI      │
                     │  ClusterIP:8000 │   │  ClusterIP:80     │
                     └────────┬────────┘   └──────┬────────────┘
                              │                   │
              ┌───────────────▼───────────────┐   │
              │  Deployment: aldeci-api        │   │
              │  3 replicas (HPA 3-10)        │   │
              │  Pod anti-affinity            │   │
              │  PDB: minAvailable=2          │   │
              │  Rolling update (0 downtime)  │   │
              └───────────────────────────────┘   │
                                                  │
              ┌───────────────────────────────────▼┐
              │  Deployment: aldeci-ui             │
              │  2 replicas (HPA 2-6)             │
              │  PDB: minAvailable=1              │
              └────────────────────────────────────┘

              ┌─────────────────┐  ┌─────────────────┐
              │  PVC: data      │  │  PVC: logs       │
              │  100Gi RWX      │  │  20Gi RWX        │
              └─────────────────┘  └─────────────────┘

              ┌─────────────────┐  ┌─────────────────┐
              │  Redis (HA)     │  │  PostgreSQL (HA) │
              │  via Bitnami    │  │  Primary+Replica │
              └─────────────────┘  └─────────────────┘
```

---

## Prerequisites

### Docker Compose HA

| Requirement       | Minimum          | Recommended       |
|-------------------|------------------|-------------------|
| Docker Engine     | 24.0+            | 25.0+             |
| Docker Compose    | v2.20+           | v2.28+            |
| CPU               | 4 cores          | 8 cores           |
| RAM               | 8 GB             | 16 GB             |
| Disk              | 50 GB SSD        | 100 GB NVMe       |
| OS                | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS  |

### Kubernetes / Helm

| Requirement       | Minimum          | Recommended       |
|-------------------|------------------|-------------------|
| Kubernetes        | 1.28+            | 1.30+             |
| Helm              | 3.14+            | 3.16+             |
| Nodes             | 3                | 5+                |
| CPU per node      | 4 cores          | 8 cores           |
| RAM per node      | 8 GB             | 16 GB             |
| Storage           | ReadWriteMany PV | NFS/EFS/Longhorn  |
| Ingress           | nginx-ingress    | nginx-ingress     |
| cert-manager      | 1.14+ (for TLS)  | 1.15+             |

---

## Option 1: Docker Compose HA

### 1. Clone and configure

```bash
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# Copy and edit environment file
cp docker/enterprise.env.example docker/.env
```

### 2. Set required secrets

Edit `docker/.env` with real values:

```bash
# Generate secrets
FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
FIXOPS_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
POSTGRES_PASSWORD=$(openssl rand -hex 24)

# Write to .env
cat >> docker/.env << EOF
FIXOPS_API_TOKEN=${FIXOPS_API_TOKEN}
FIXOPS_JWT_SECRET=${FIXOPS_JWT_SECRET}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
EOF
```

### 3. Make init script executable

```bash
chmod +x docker/postgres/pg-primary-init.sh
```

### 4. Start the HA stack

```bash
# Build images (first time or after code changes)
docker compose -f docker/docker-compose.ha.yml build

# Start all services
docker compose -f docker/docker-compose.ha.yml up -d

# Watch startup
docker compose -f docker/docker-compose.ha.yml logs -f
```

### 5. Verify health

```bash
# Nginx LB health
curl -s http://localhost/healthz | jq .

# Backend readiness
curl -s http://localhost/readyz | jq .

# Individual replicas
curl -s http://localhost:8000/health | jq .  # API replica 1
curl -s http://localhost:8001/health | jq .  # API replica 2

# PostgreSQL
docker exec aldeci-ha-pg-primary pg_isready -U aldeci

# PostgreSQL replication status
docker exec aldeci-ha-pg-primary psql -U aldeci -d aldeci \
  -c "SELECT client_addr, state, sent_lsn, write_lsn, replay_lsn FROM pg_stat_replication;"

# Redis
docker exec aldeci-ha-redis redis-cli ping
docker exec aldeci-ha-redis redis-cli info replication

# All services
docker compose -f docker/docker-compose.ha.yml ps
```

### 6. Seed demo data (optional)

```bash
# Re-run API replica 1 with demo seed flag
docker compose -f docker/docker-compose.ha.yml run --rm \
  -e ALDECI_SEED_DEMO=1 aldeci-api-1 api-only
```

### 7. Scaling

```bash
# Scale API replicas (modify compose or use Docker Swarm)
# For Docker Compose, add more service definitions or use deploy.replicas in swarm mode

# Adjust worker count per replica
FIXOPS_WORKERS=4 docker compose -f docker/docker-compose.ha.yml up -d
```

---

## Option 2: Kubernetes / Helm

### 1. Create namespace and secrets

```bash
# Create namespace
kubectl create namespace aldeci

# Create secrets (replace with real values)
kubectl create secret generic aldeci-secrets \
  --namespace aldeci \
  --from-literal=FIXOPS_JWT_SECRET="$(openssl rand -base64 48)" \
  --from-literal=FIXOPS_API_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=FIXOPS_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  --from-literal=REDIS_PASSWORD="$(openssl rand -hex 16)" \
  --from-literal=POSTGRES_PASSWORD="$(openssl rand -hex 24)" \
  --from-literal=WEBHOOK_SECRET="$(openssl rand -hex 32)"

# Create TLS secret (if not using cert-manager)
kubectl create secret tls aldeci-tls \
  --namespace aldeci \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key
```

### 2. Install with Helm (default values)

```bash
helm install aldeci ./docker/helm/aldeci \
  --namespace aldeci \
  --set secrets.create=false \
  --set secrets.existingSecret=aldeci-secrets
```

### 3. Install with HA values

```bash
helm install aldeci ./docker/helm/aldeci \
  --namespace aldeci \
  -f ./docker/helm/aldeci/values-ha.yaml \
  --set secrets.create=false \
  --set secrets.existingSecret=aldeci-secrets \
  --set ingress.hosts.ui.host=aldeci.yourdomain.com \
  --set ingress.hosts.api.host=api.aldeci.yourdomain.com \
  --set ingress.tls.hosts[0]=aldeci.yourdomain.com \
  --set ingress.tls.hosts[1]=api.aldeci.yourdomain.com
```

### 4. Verify deployment

```bash
# Check pods
kubectl get pods -n aldeci -o wide

# Check services
kubectl get svc -n aldeci

# Check ingress
kubectl get ingress -n aldeci

# Check HPA
kubectl get hpa -n aldeci

# Check PDB
kubectl get pdb -n aldeci

# Pod health
kubectl exec -n aldeci deploy/aldeci-api -- curl -s http://localhost:8000/health | jq .

# Logs
kubectl logs -n aldeci -l app.kubernetes.io/component=api --tail=100 -f
```

### 5. Upgrade

```bash
# Update values, then:
helm upgrade aldeci ./docker/helm/aldeci \
  --namespace aldeci \
  -f ./docker/helm/aldeci/values-ha.yaml \
  --set api.image.tag="2.6.0"

# Rolling restart (no downtime with PDB)
kubectl rollout restart deployment/aldeci-api -n aldeci
kubectl rollout status deployment/aldeci-api -n aldeci
```

---

## Health Check Endpoints

ALDECI exposes three probe endpoints following Kubernetes conventions:

| Endpoint     | Purpose              | Checks                                      | Timeout |
|-------------|----------------------|----------------------------------------------|---------|
| `/healthz`  | Liveness probe       | API process is alive and accepting requests  | 5s      |
| `/readyz`   | Readiness probe      | API + Redis + SQLite DBs all responding      | 5s      |
| `/startupz` | Startup probe        | API has finished initialization              | 10s     |

All three are proxied by nginx to the backend `/health` endpoint. In Kubernetes, the probes hit the pod directly (no nginx).

### Health check responses

```bash
# Healthy
curl -s http://localhost/healthz
{"status": "ok", "version": "2.5.0", "uptime": 3600}

# Unhealthy (503)
{"status": "error", "detail": "redis connection failed"}
```

### Nginx internal status

```bash
# From within the Docker network only
curl http://localhost:8080/nginx_status
Active connections: 12
server accepts handled requests
 1234 1234 5678
Reading: 0 Writing: 3 Waiting: 9
```

---

## Backup and Restore

### SQLite Backups (Docker Compose)

```bash
# Create backup
BACKUP_DIR="/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Stop writes briefly (WAL checkpoint)
docker exec aldeci-ha-api-1 python3 -c "
import sqlite3, glob, os
for db in glob.glob('/app/data/*.db'):
    conn = sqlite3.connect(db)
    conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    conn.close()
    print(f'Checkpointed: {os.path.basename(db)}')
"

# Copy all DBs
docker cp aldeci-ha-api-1:/app/data/ "$BACKUP_DIR/"

# Backup Redis
docker exec aldeci-ha-redis redis-cli BGSAVE
docker cp aldeci-ha-redis:/data/dump.rdb "$BACKUP_DIR/redis-dump.rdb"

echo "Backup complete: $BACKUP_DIR"
```

### PostgreSQL Backups

```bash
# Logical backup (pg_dump)
docker exec aldeci-ha-pg-primary \
  pg_dump -U aldeci -d aldeci -Fc -Z9 > "backup_$(date +%Y%m%d).dump"

# Point-in-time recovery backup (pg_basebackup from replica)
docker exec aldeci-ha-pg-replica \
  pg_basebackup -h pg-primary -U replicator -D /tmp/backup -Fp -Xs -P
```

### Restore SQLite

```bash
# Stop API replicas
docker compose -f docker/docker-compose.ha.yml stop aldeci-api-1 aldeci-api-2

# Restore from backup
docker cp "$BACKUP_DIR/data/" aldeci-ha-api-1:/app/

# Restart
docker compose -f docker/docker-compose.ha.yml start aldeci-api-1 aldeci-api-2
```

### Restore PostgreSQL

```bash
# Restore logical backup
docker exec -i aldeci-ha-pg-primary \
  pg_restore -U aldeci -d aldeci -c < "backup_20260422.dump"
```

### Kubernetes Backups

```bash
# Using a CronJob (already defined in kubernetes/cronjob-backup.yaml)
kubectl apply -f docker/kubernetes/cronjob-backup.yaml -n aldeci

# Manual trigger
kubectl create job --from=cronjob/aldeci-backup aldeci-backup-manual -n aldeci

# Check backup status
kubectl get jobs -n aldeci -l app=aldeci-backup
```

### Automated Backup Schedule

For Docker Compose, add a cron entry:

```bash
# /etc/cron.d/aldeci-backup
# Daily at 2:00 AM UTC
0 2 * * * root /opt/aldeci/scripts/backup.sh >> /var/log/aldeci-backup.log 2>&1
```

---

## Monitoring with Prometheus and Grafana

### Prometheus Metrics

ALDECI exposes Prometheus metrics at `/metrics`:

```
# HELP aldeci_requests_total Total API requests
# TYPE aldeci_requests_total counter
aldeci_requests_total{method="GET",endpoint="/api/v1/health",status="200"} 12345

# HELP aldeci_request_duration_seconds Request latency
# TYPE aldeci_request_duration_seconds histogram
aldeci_request_duration_seconds_bucket{le="0.1"} 9800

# HELP aldeci_engine_db_size_bytes SQLite database sizes
# TYPE aldeci_engine_db_size_bytes gauge
aldeci_engine_db_size_bytes{engine="brain_pipeline"} 4194304

# HELP aldeci_active_connections Current active connections
# TYPE aldeci_active_connections gauge
aldeci_active_connections 42
```

### Docker Compose: Add Prometheus + Grafana

Add to your `docker-compose.ha.yml` or create a monitoring overlay:

```yaml
# docker-compose.monitoring.yml
services:
  prometheus:
    image: prom/prometheus:v2.53.0
    container_name: aldeci-ha-prometheus
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ha-prometheus-data:/prometheus
    ports:
      - "9090:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=30d'
    networks:
      - aldeci-ha

  grafana:
    image: grafana/grafana:11.1.0
    container_name: aldeci-ha-grafana
    environment:
      GF_SECURITY_ADMIN_PASSWORD: "${GRAFANA_PASSWORD:-admin}"
    volumes:
      - ha-grafana-data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources:ro
    ports:
      - "3001:3000"
    networks:
      - aldeci-ha

volumes:
  ha-prometheus-data:
  ha-grafana-data:
```

Prometheus scrape config (`monitoring/prometheus.yml`):

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'aldeci-api'
    metrics_path: /metrics
    static_configs:
      - targets:
          - aldeci-api-1:8000
          - aldeci-api-2:8000
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance

  - job_name: 'nginx'
    metrics_path: /nginx_status
    static_configs:
      - targets: ['nginx:8080']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']

  - job_name: 'postgres'
    static_configs:
      - targets: ['pg-primary:5432']
```

### Kubernetes: ServiceMonitor

The Helm chart includes a `ServiceMonitor` resource (enabled in `values-ha.yaml`).
It requires the Prometheus Operator (kube-prometheus-stack):

```bash
# Install kube-prometheus-stack
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace

# The ServiceMonitor in aldeci namespace auto-discovers the API metrics
kubectl get servicemonitor -n aldeci
```

### Key Dashboards

| Dashboard              | Panels                                                 |
|-----------------------|--------------------------------------------------------|
| ALDECI Overview       | Request rate, error rate, latency p50/p95/p99, uptime |
| Engine Health         | DB sizes, query latency per engine, error counts       |
| Infrastructure        | CPU, memory, disk I/O, network, Redis hit rate         |
| PostgreSQL            | Connections, replication lag, query duration, cache hit |
| Security Operations   | Alert volume, MTTD, MTTR, open findings, scan rate     |

---

## Disaster Recovery

### RTO and RPO Targets

| Tier        | RTO          | RPO          | Strategy                           |
|------------|--------------|--------------|-------------------------------------|
| Standard   | 4 hours      | 1 hour       | Daily backups, manual failover     |
| Enterprise | 30 minutes   | 5 minutes    | Streaming replication, auto-restart|
| Critical   | 5 minutes    | Near-zero    | Multi-AZ, PG sync replication     |

### Failover Procedures

**API replica failure (Docker Compose):**
Nginx automatically routes traffic to the healthy replica. No manual intervention needed.
The failed container auto-restarts via `restart: unless-stopped`.

**PostgreSQL primary failure:**
1. Promote the replica: `docker exec aldeci-ha-pg-replica pg_ctl promote -D /var/lib/postgresql/data`
2. Update `DATABASE_URL` to point to the new primary
3. Restart API replicas

**Full host failure (Kubernetes):**
Kubernetes automatically reschedules pods to healthy nodes.
PDB ensures minimum availability during rescheduling.

---

## Troubleshooting

### Common Issues

**Nginx returns 502 Bad Gateway:**
- Check API replica health: `docker logs aldeci-ha-api-1 --tail=50`
- Verify network: `docker exec aldeci-ha-nginx ping aldeci-api-1`
- Check upstream config: `docker exec aldeci-ha-nginx nginx -T | grep upstream`

**PostgreSQL replication lag:**
```bash
docker exec aldeci-ha-pg-primary psql -U aldeci -d aldeci \
  -c "SELECT NOW() - pg_last_xact_replay_timestamp() AS replication_lag;"
```

**SQLite lock contention (shared volume):**
All ALDECI engines use WAL mode, which allows concurrent reads. If you see `database is locked` errors:
- Ensure only one replica handles writes to a given DB file
- Check WAL checkpoint status: the API runs 60-second checkpoint daemons

**Redis connection pool exhaustion:**
```bash
docker exec aldeci-ha-redis redis-cli info clients
# Check connected_clients vs maxclients
```

**HPA not scaling (Kubernetes):**
```bash
kubectl describe hpa -n aldeci
kubectl top pods -n aldeci
# Ensure metrics-server is running
kubectl get pods -n kube-system | grep metrics-server
```
