# ALdeci FixOps — Production Deployment Guide

**Version:** 2.0  
**Classification:** INTERNAL / SENSITIVE  
**Applicable Environments:** Air-Gapped, Gov Cloud, On-Premises  
**Last Updated:** 2026-03-08  

---

## Table of Contents

1. [Air-Gapped Deployment](#1-air-gapped-deployment)
2. [Docker Compose Production Setup](#2-docker-compose-production-setup)
3. [Kubernetes Helm Chart](#3-kubernetes-helm-chart)
4. [TLS/mTLS Configuration](#4-tlsmtls-configuration)
5. [Certificate Management](#5-certificate-management)
6. [Backup and Restore Procedures](#6-backup-and-restore-procedures)
7. [High Availability Setup](#7-high-availability-setup)
8. [Monitoring and Alerting](#8-monitoring-and-alerting)
9. [Log Aggregation](#9-log-aggregation)
10. [Incident Response Procedures](#10-incident-response-procedures)

---

## 1. Air-Gapped Deployment

Air-gapped deployments require all dependencies to be pre-packaged before transport to the classified environment. No internet access is assumed.

### 1.1 Pre-Deployment Package Preparation (Internet-Connected System)

```bash
# Step 1 — Export Docker image
docker build -t fixops:2.0.0 -f docker/Dockerfile .
docker save fixops:2.0.0 | gzip > fixops-2.0.0-image.tar.gz

# Also export supporting images
docker pull nginx:1.27-alpine
docker save nginx:1.27-alpine | gzip > nginx-1.27-image.tar.gz

docker pull prom/prometheus:v2.51.0
docker save prom/prometheus:v2.51.0 | gzip > prometheus-image.tar.gz

docker pull grafana/grafana:10.4.0
docker save grafana/grafana:10.4.0 | gzip > grafana-image.tar.gz

# Step 2 — Export Python dependencies for pip (offline wheel cache)
pip download \
    --no-deps \
    --dest ./pip-packages/ \
    -r requirements.txt

# Step 3 — Create deployment archive
tar -czf fixops-airgap-2.0.0.tar.gz \
    fixops-2.0.0-image.tar.gz \
    nginx-1.27-image.tar.gz \
    prometheus-image.tar.gz \
    grafana-image.tar.gz \
    pip-packages/ \
    docker/ \
    scripts/ \
    .env.production.template

# Step 4 — Sign the archive
gpg --armor --detach-sign fixops-airgap-2.0.0.tar.gz
sha256sum fixops-airgap-2.0.0.tar.gz > fixops-airgap-2.0.0.tar.gz.sha256

# Verify signatures before transport
gpg --verify fixops-airgap-2.0.0.tar.gz.asc
```

### 1.2 Air-Gapped Installation (Target System)

```bash
# Step 1 — Verify integrity before installation
sha256sum -c fixops-airgap-2.0.0.tar.gz.sha256
gpg --verify fixops-airgap-2.0.0.tar.gz.asc

# Step 2 — Extract archive
tar -xzf fixops-airgap-2.0.0.tar.gz
cd fixops-airgap-2.0.0/

# Step 3 — Load Docker images (no internet required)
gunzip -c fixops-2.0.0-image.tar.gz | docker load
gunzip -c nginx-1.27-image.tar.gz | docker load
gunzip -c prometheus-image.tar.gz | docker load
gunzip -c grafana-image.tar.gz | docker load

# Step 4 — Verify loaded images
docker images | grep -E "fixops|nginx|prometheus|grafana"

# Step 5 — Configure environment
cp .env.production.template .env.production
# Edit .env.production with your values (see .env.production)
nano .env.production

# Step 6 — Initialize secrets
# Generate API key
python3 -c "import secrets; print('fixops_sk_' + secrets.token_urlsafe(40))"

# Generate JWT secret
python3 -c "import secrets; print(secrets.token_urlsafe(48))"

# Generate evidence encryption key (AES-256 = 32 bytes)
python3 -c "import secrets; print(secrets.token_hex(32))"

# Step 7 — Deploy
docker compose -f docker/docker-compose.prod.yml up -d

# Step 8 — Verify deployment
curl -k https://localhost:8443/health
curl -k -H "X-API-Key: YOUR_KEY" https://localhost:8443/api/v1/status
```

### 1.3 Air-Gapped LLM Configuration

For air-gapped environments, configure vLLM for local LLM inference:

```bash
# Load vLLM image
gunzip -c vllm-image.tar.gz | docker load

# Configure in .env.production
VLLM_BASE_URL=http://vllm-service:8001/v1
VLLM_MODEL=meta-llama/Meta-Llama-3.1-70B-Instruct

# Disable all cloud LLM providers
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GOOGLE_API_KEY=
FIXOPS_CLOUD_LLM_DISABLED=true
```

### 1.4 Air-Gapped Update Procedure

```bash
# On internet-connected system
./scripts/build-airgap-update.sh --version 2.1.0

# Transfer to air-gapped system via approved media
# Verify hash on target:
sha256sum -c fixops-update-2.1.0.sha256

# Apply update
./scripts/apply-update.sh fixops-update-2.1.0.tar.gz
```

---

## 2. Docker Compose Production Setup

### 2.1 Production docker-compose.prod.yml

```yaml
# docker/docker-compose.prod.yml
# Production deployment — hardened configuration
# DO NOT use docker-compose.demo.yml in production

version: "3.9"

services:
  fixops-api:
    image: fixops:2.0.0
    container_name: fixops-api
    restart: unless-stopped
    user: "1001:1001"   # Non-root user
    read_only: true     # Immutable filesystem
    tmpfs:
      - /tmp:mode=1777,size=100m
      - /var/run:mode=755
    volumes:
      - fixops-data:/app/data:rw
      - fixops-logs:/app/logs:rw
      - /etc/fixops/certs:/app/certs:ro
      - /etc/fixops/.env.production:/app/.env:ro
    environment:
      - FIXOPS_ENV=production
    env_file:
      - /etc/fixops/.env.production
    ports: []    # No direct port exposure — traffic via Nginx only
    expose:
      - "8000"
    networks:
      - fixops-internal
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined   # Replace with custom seccomp profile
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE   # Only if binding to port < 1024
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 8G
        reservations:
          cpus: "1.0"
          memory: 2G
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"
        labels: "service=fixops-api"

  nginx:
    image: nginx:1.27-alpine
    container_name: fixops-nginx
    restart: unless-stopped
    volumes:
      - /etc/fixops/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/fixops/certs:/etc/nginx/certs:ro
      - fixops-logs:/var/log/nginx:rw
    ports:
      - "443:443"
      - "80:80"   # Redirect to HTTPS only
    networks:
      - fixops-internal
      - fixops-external
    depends_on:
      - fixops-api
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
      - NET_BIND_SERVICE

  prometheus:
    image: prom/prometheus:v2.51.0
    container_name: fixops-prometheus
    restart: unless-stopped
    user: "65534:65534"   # nobody
    volumes:
      - /etc/fixops/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - /etc/fixops/prometheus/alerts.yml:/etc/prometheus/alerts.yml:ro
      - prometheus-data:/prometheus:rw
    networks:
      - fixops-internal
    ports: []   # Not exposed externally
    command:
      - --config.file=/etc/prometheus/prometheus.yml
      - --storage.tsdb.retention.time=90d
      - --web.listen-address=:9090
      - --web.external-url=http://prometheus.internal/

  grafana:
    image: grafana/grafana:10.4.0
    container_name: fixops-grafana
    restart: unless-stopped
    user: "472:472"
    volumes:
      - grafana-data:/var/lib/grafana:rw
      - /etc/fixops/grafana/provisioning:/etc/grafana/provisioning:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD__FILE=/run/secrets/grafana_password
      - GF_SERVER_DOMAIN=monitoring.internal
      - GF_SERVER_ROOT_URL=https://monitoring.internal/
    networks:
      - fixops-internal

networks:
  fixops-internal:
    driver: bridge
    internal: true    # No direct internet access for internal network
    ipam:
      config:
        - subnet: 172.28.0.0/24
  fixops-external:
    driver: bridge

volumes:
  fixops-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /var/fixops/data
  fixops-logs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /var/fixops/logs
  prometheus-data:
  grafana-data:
```

### 2.2 Nginx Production Configuration

```nginx
# /etc/fixops/nginx/nginx.conf

worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # Security headers
    server_tokens off;
    more_clear_headers Server;
    more_set_headers "Server: FixOps";

    # TLS configuration
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_dhparam /etc/nginx/certs/dhparam.pem;  # 4096-bit DH params

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 127.0.0.53 valid=300s;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Security headers (OWASP)
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Buffer size limits (defense against buffer overflow)
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    client_max_body_size 10m;
    large_client_header_buffers 4 8k;

    # Timeouts
    client_body_timeout 15;
    client_header_timeout 15;
    keepalive_timeout 30;
    send_timeout 15;

    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
    limit_conn_zone $binary_remote_addr zone=conn:10m;

    # HTTP -> HTTPS redirect
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name fixops.agency.gov;

        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_client_certificate /etc/nginx/certs/ca-bundle.crt;  # mTLS CA
        ssl_verify_client optional;  # Use 'on' for mandatory mTLS

        # Connection limits
        limit_conn conn 50;

        # Log format
        access_log /var/log/nginx/access.log combined buffer=32k flush=5s;
        error_log /var/log/nginx/error.log warn;

        location /api/ {
            limit_req zone=api burst=20 nodelay;

            proxy_pass http://fixops-api:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # mTLS client cert forwarding
            proxy_set_header X-Client-Cert $ssl_client_cert;
            proxy_set_header X-Client-Verified $ssl_client_verify;
            proxy_set_header X-Client-Subject $ssl_client_s_dn;

            proxy_read_timeout 30s;
            proxy_connect_timeout 5s;
            proxy_send_timeout 30s;
        }

        location /api/v1/auth/ {
            limit_req zone=auth burst=3 nodelay;
            proxy_pass http://fixops-api:8000;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /metrics {
            # Restrict Prometheus scrape to internal network only
            allow 172.28.0.0/24;
            deny all;
            proxy_pass http://fixops-api:8000/metrics;
        }

        location /health {
            access_log off;
            proxy_pass http://fixops-api:8000/health;
        }
    }
}
```

---

## 3. Kubernetes Helm Chart

### 3.1 Chart Structure

```
fixops/
├── Chart.yaml
├── values.yaml
├── values-production.yaml
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   ├── secret.yaml
│   ├── configmap.yaml
│   ├── networkpolicy.yaml
│   ├── poddisruptionbudget.yaml
│   ├── serviceaccount.yaml
│   ├── hpa.yaml
│   └── persistentvolumeclaim.yaml
```

### 3.2 values-production.yaml (Key Security Values)

```yaml
# values-production.yaml
replicaCount: 3

image:
  repository: registry.agency.gov/fixops
  tag: "2.0.0"
  pullPolicy: IfNotPresent

imagePullSecrets:
  - name: registry-credentials

serviceAccount:
  create: true
  annotations: {}
  automountServiceAccountToken: false   # Disable unless needed

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  fsGroup: 1001
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities:
    drop:
      - ALL

resources:
  requests:
    cpu: "500m"
    memory: "1Gi"
  limits:
    cpu: "4000m"
    memory: "8Gi"

# Secrets managed via External Secrets Operator or Vault
secrets:
  secretRef: fixops-secrets   # K8s Secret name
  useExternalSecrets: true    # Prefer ExternalSecrets over hardcoded

persistence:
  enabled: true
  storageClass: "encrypted-gp3"   # Use encrypted storage class
  size: 50Gi
  accessModes:
    - ReadWriteOnce

networkPolicy:
  enabled: true
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: fixops-ingress
      ports:
        - port: 8000
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: fixops-db

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

podDisruptionBudget:
  enabled: true
  minAvailable: 2

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    nginx.ingress.kubernetes.io/limit-connections: "50"
    nginx.ingress.kubernetes.io/limit-rpm: "100"
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    - secretName: fixops-tls
      hosts:
        - fixops.agency.gov

livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 60
  periodSeconds: 30
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10
```

### 3.3 Deploy Commands

```bash
# Add chart repository
helm repo add fixops https://charts.aldeci.com

# Install with production values
helm upgrade --install fixops fixops/fixops \
  --namespace fixops \
  --create-namespace \
  -f values-production.yaml \
  --set image.tag=2.0.0 \
  --set secrets.secretRef=fixops-prod-secrets \
  --atomic \
  --timeout 10m

# Verify deployment
kubectl -n fixops get pods
kubectl -n fixops rollout status deployment/fixops
```

---

## 4. TLS/mTLS Configuration

### 4.1 TLS Configuration (One-Way)

FixOps requires TLS 1.3 minimum. Configure Nginx (or Uvicorn direct TLS for internal):

```bash
# Generate server key and CSR
openssl req -new -newkey rsa:4096 -nodes \
  -keyout /etc/fixops/certs/server.key \
  -out /etc/fixops/certs/server.csr \
  -subj "/C=US/ST=DC/O=Agency/OU=FixOps/CN=fixops.agency.gov"

# Submit CSR to your PKI / DoD PKI
# Install certificate
cp issued-cert.crt /etc/fixops/certs/server.crt
chmod 0600 /etc/fixops/certs/server.key
chmod 0644 /etc/fixops/certs/server.crt
chown fixops:fixops /etc/fixops/certs/server.key

# Generate DH parameters (4096-bit)
openssl dhparam -out /etc/fixops/certs/dhparam.pem 4096

# Set minimum TLS version in environment
FIXOPS_TLS_MIN_VERSION=TLSv1.3
```

### 4.2 mTLS Configuration (Mutual TLS)

For DoD environments requiring client certificate authentication:

```bash
# Step 1 — Obtain the DoD CA bundle
# Download from https://public.cyber.mil/pki-pke/
cp DoD_PKE_CA_chain.pem /etc/fixops/certs/ca-bundle.crt

# Step 2 — Configure Nginx for mandatory mTLS
# In nginx.conf:
#   ssl_verify_client on;    (mandatory mTLS)
#   ssl_client_certificate /etc/nginx/certs/ca-bundle.crt;

# Step 3 — Configure FixOps to require client cert header
FIXOPS_REQUIRE_MTLS=true
FIXOPS_CLIENT_CERT_HEADER=X-Client-Verified
FIXOPS_CLIENT_SUBJECT_HEADER=X-Client-Subject

# Step 4 — Test mTLS connection
curl --cert client.crt --key client.key \
  --cacert ca-bundle.crt \
  https://fixops.agency.gov/health
```

### 4.3 Cipher Suite Hardening

```bash
# Verify TLS configuration
nmap --script ssl-enum-ciphers -p 443 fixops.agency.gov

# Expected output should show only:
#   TLSv1.3:
#     TLS_AES_256_GCM_SHA384 - A
#     TLS_CHACHA20_POLY1305_SHA256 - A

# Verify with testssl.sh
./testssl.sh --severity HIGH fixops.agency.gov:443
```

---

## 5. Certificate Management

### 5.1 Certificate Inventory

Maintain the following certificates:

| Certificate | Purpose | Location | Renewal |
|-------------|---------|----------|---------|
| Server TLS cert | HTTPS endpoint | `/etc/fixops/certs/server.crt` | Annual (or per PKI policy) |
| CA Bundle | mTLS client validation | `/etc/fixops/certs/ca-bundle.crt` | Per DoD PKI updates |
| RSA Evidence Signing Key | Evidence bundle signing | `FIXOPS_RSA_PRIVATE_KEY_PATH` | Per `FIXOPS_RSA_KEY_ROTATION_DAYS` |
| JWT Signing Secret | JWT token signing | `FIXOPS_JWT_SECRET` | Quarterly |

### 5.2 Certificate Rotation Procedure

```bash
# Step 1 — Generate new RSA signing keypair
python3 -c "
from core.crypto import CryptoSigner
signer = CryptoSigner()
new_key_id = signer.rotate_key()
print(f'New key ID: {new_key_id}')
"

# Step 2 — Rotate TLS certificate
# a) Generate new CSR
openssl req -new -newkey rsa:4096 -nodes \
  -keyout /etc/fixops/certs/server.key.new \
  -out /etc/fixops/certs/server.csr.new \
  -subj "/C=US/ST=DC/O=Agency/OU=FixOps/CN=fixops.agency.gov"

# b) Submit to PKI and receive new cert
# c) Test new cert
openssl s_client -connect fixops.agency.gov:443 \
  -CAfile ca-bundle.crt < /dev/null

# d) Replace cert and reload Nginx (zero-downtime)
cp /etc/fixops/certs/server.key.new /etc/fixops/certs/server.key
cp /etc/fixops/certs/server.crt.new /etc/fixops/certs/server.crt
docker compose exec nginx nginx -s reload

# Step 3 — Rotate JWT secret (requires re-login for all users)
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# Update FIXOPS_JWT_SECRET in .env.production and restart API
```

### 5.3 Certificate Monitoring

```bash
# Check certificate expiry (add to monitoring system)
openssl s_client -connect fixops.agency.gov:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -dates

# Prometheus alert rule for certificate expiry (add to alerts.yml):
# - alert: TLSCertExpiryWarning
#   expr: fixops_tls_cert_expiry_seconds < 30 * 86400
#   for: 1h
#   labels:
#     severity: warning
#   annotations:
#     summary: "TLS certificate expires in {{ $value | humanizeDuration }}"
```

---

## 6. Backup and Restore Procedures

### 6.1 Backup Script

```bash
#!/bin/bash
# /etc/fixops/scripts/backup.sh
# Automated FixOps backup — run via cron or systemd timer

set -euo pipefail

BACKUP_DIR="${FIXOPS_BACKUP_DIR:-/var/fixops/backups}"
DATA_DIR="${FIXOPS_DATA_DIR:-/var/fixops/data}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"
RETAIN_DAYS="${FIXOPS_BACKUP_RETAIN_DAYS:-30}"

# Create backup directory
mkdir -p "${BACKUP_PATH}"

# Backup all SQLite databases using sqlite3 .backup (hot backup — no lock required)
for db_file in "${DATA_DIR}"/*.db; do
    db_name=$(basename "${db_file}")
    echo "Backing up ${db_name}..."
    sqlite3 "${db_file}" ".backup '${BACKUP_PATH}/${db_name}'"
done

# Backup configuration (excluding secrets)
cp /etc/fixops/.env.production.template "${BACKUP_PATH}/env.template"

# Backup RSA public key and key metadata (never backup private key to shared storage)
if [ -f "${FIXOPS_RSA_PUBLIC_KEY_PATH:-/etc/fixops/keys/public.pem}" ]; then
    cp "${FIXOPS_RSA_PUBLIC_KEY_PATH}" "${BACKUP_PATH}/rsa_public.pem"
fi

# Create compressed archive
tar -czf "${BACKUP_DIR}/fixops-backup-${TIMESTAMP}.tar.gz" \
    -C "${BACKUP_DIR}" "${TIMESTAMP}/"

# Encrypt backup (AES-256-CBC)
openssl enc -aes-256-cbc -salt -pbkdf2 \
    -in "${BACKUP_DIR}/fixops-backup-${TIMESTAMP}.tar.gz" \
    -out "${BACKUP_DIR}/fixops-backup-${TIMESTAMP}.tar.gz.enc" \
    -pass "env:FIXOPS_BACKUP_ENCRYPTION_KEY"

# Remove unencrypted archive
rm "${BACKUP_DIR}/fixops-backup-${TIMESTAMP}.tar.gz"
rm -rf "${BACKUP_PATH}"

# Calculate checksum
sha256sum "${BACKUP_DIR}/fixops-backup-${TIMESTAMP}.tar.gz.enc" \
    > "${BACKUP_DIR}/fixops-backup-${TIMESTAMP}.sha256"

echo "Backup complete: fixops-backup-${TIMESTAMP}.tar.gz.enc"

# Cleanup old backups
find "${BACKUP_DIR}" -name "*.enc" -mtime "+${RETAIN_DAYS}" -delete
find "${BACKUP_DIR}" -name "*.sha256" -mtime "+${RETAIN_DAYS}" -delete
```

### 6.2 Restore Procedure

```bash
#!/bin/bash
# Restore from encrypted backup

BACKUP_FILE="$1"
RESTORE_DIR="${FIXOPS_DATA_DIR:-/var/fixops/data}"

if [ -z "${BACKUP_FILE}" ]; then
    echo "Usage: restore.sh <backup-file.tar.gz.enc>"
    exit 1
fi

# Step 1 — Verify checksum
sha256sum -c "${BACKUP_FILE}.sha256"

# Step 2 — Stop FixOps API (prevents write conflicts)
docker compose -f docker/docker-compose.prod.yml stop fixops-api

# Step 3 — Decrypt backup
openssl enc -d -aes-256-cbc -pbkdf2 \
    -in "${BACKUP_FILE}" \
    -out /tmp/fixops-restore.tar.gz \
    -pass "env:FIXOPS_BACKUP_ENCRYPTION_KEY"

# Step 4 — Extract
mkdir -p /tmp/fixops-restore
tar -xzf /tmp/fixops-restore.tar.gz -C /tmp/fixops-restore

# Step 5 — Restore databases
BACKUP_TIMESTAMP=$(ls /tmp/fixops-restore/)
for db_file in "/tmp/fixops-restore/${BACKUP_TIMESTAMP}"/*.db; do
    db_name=$(basename "${db_file}")
    echo "Restoring ${db_name}..."
    cp "${RESTORE_DIR}/${db_name}" "${RESTORE_DIR}/${db_name}.pre-restore"
    sqlite3 "${db_file}" ".backup '${RESTORE_DIR}/${db_name}'"
done

# Step 6 — Restart API
docker compose -f docker/docker-compose.prod.yml start fixops-api

# Step 7 — Verify restore
curl -f http://localhost:8000/health

# Step 8 — Cleanup
rm -rf /tmp/fixops-restore /tmp/fixops-restore.tar.gz
echo "Restore complete."
```

### 6.3 Backup Schedule (Recommended)

| Backup Type | Frequency | Retention | Location |
|-------------|-----------|-----------|----------|
| Full database backup | Daily | 30 days | Local encrypted storage |
| Audit DB backup | Daily | 3 years (FISMA) | Separate encrypted volume |
| Configuration backup | On change | 90 days | Secrets manager |
| Offsite backup | Weekly | 1 year | Air-gapped secondary site |

---

## 7. High Availability Setup

### 7.1 HA Architecture

```
                    ┌─────────────────┐
                    │   Load Balancer │
                    │   (HAProxy/NLB) │
                    └────────┬────────┘
                             │
               ┌─────────────┼─────────────┐
               │             │             │
        ┌──────┴──┐   ┌──────┴──┐   ┌──────┴──┐
        │FixOps-1 │   │FixOps-2 │   │FixOps-3 │
        │ :8000   │   │ :8000   │   │ :8000   │
        └──────┬──┘   └──────┬──┘   └──────┬──┘
               │             │             │
               └─────────────┼─────────────┘
                             │
                    ┌────────┴────────┐
                    │  Shared Storage │
                    │ (NFS/EFS/Ceph)  │
                    └─────────────────┘
                             │
                    ┌────────┴────────┐
                    │   Redis Cluster │
                    │ (sessions/cache)│
                    └─────────────────┘
```

### 7.2 SQLite to PostgreSQL Migration (HA Databases)

For HA deployments, migrate from SQLite to PostgreSQL:

```bash
# Configure PostgreSQL connection
FIXOPS_DATABASE_URL=postgresql+asyncpg://fixops:password@postgres-primary:5432/fixops
FIXOPS_AUDIT_DATABASE_URL=postgresql+asyncpg://fixops:password@postgres-primary:5432/fixops_audit

# Run migration
python3 -m scripts.migrate_to_postgres

# Verify
python3 -m scripts.verify_migration
```

### 7.3 Redis for Session and Rate Limiting State

```bash
# Configure Redis for session management
FIXOPS_REDIS_URL=rediss://redis-cluster:6380   # TLS Redis
FIXOPS_REDIS_PASSWORD=<strong-password>
FIXOPS_REDIS_TLS=true

# Session manager will automatically use Redis when configured
```

---

## 8. Monitoring and Alerting

### 8.1 Prometheus Metrics Endpoint

FixOps exposes Prometheus metrics at `GET /metrics` (internal network only).

```yaml
# /etc/fixops/prometheus/prometheus.yml
global:
  scrape_interval: 30s
  evaluation_interval: 30s

rule_files:
  - alerts.yml

scrape_configs:
  - job_name: fixops-api
    scheme: http
    static_configs:
      - targets: ["fixops-api:8000"]
    metrics_path: /metrics
    scrape_interval: 30s
    scrape_timeout: 10s
    # Basic auth if metrics endpoint is protected
    # basic_auth:
    #   username: prometheus
    #   password_file: /etc/prometheus/prometheus_password
```

### 8.2 Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|----------------|
| `fixops_requests_total` | Total HTTP requests | — |
| `fixops_request_duration_seconds` | Request latency histogram | p99 > 5s |
| `fixops_auth_failures_total` | Authentication failures | > 10/min per IP |
| `fixops_rate_limit_hits_total` | Rate limit events | > 100/min |
| `fixops_audit_write_errors_total` | Audit log write failures | > 0 |
| `fixops_active_sessions` | Active user sessions | > 10000 |
| `fixops_tls_cert_expiry_seconds` | TLS cert time to expiry | < 30 days |
| `fixops_db_size_bytes` | SQLite database sizes | > 10GB |
| `fixops_security_events_total` | Security events by type | Injection attempts > 0 |

### 8.3 Alert Rules

```yaml
# /etc/fixops/prometheus/alerts.yml
groups:
  - name: fixops-security
    rules:
      - alert: HighAuthFailureRate
        expr: rate(fixops_auth_failures_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate: {{ $value }}/min"
          runbook: "Check /audit/logs for brute force. Consider IP block."

      - alert: AuditLogWriteFailure
        expr: fixops_audit_write_errors_total > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Audit log write failure — potential compliance violation"

      - alert: TLSCertExpiringSoon
        expr: fixops_tls_cert_expiry_seconds < 2592000   # 30 days
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "TLS certificate expires in {{ humanizeDuration $value }}"

      - alert: SecurityEventDetected
        expr: increase(fixops_security_events_total{type="sql_injection_attempt"}[5m]) > 0
        for: 0m
        labels:
          severity: high
        annotations:
          summary: "SQL injection attempt detected. Investigate immediately."

      - alert: HighResponseLatency
        expr: histogram_quantile(0.99, fixops_request_duration_seconds_bucket) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "P99 latency {{ $value }}s exceeds 5s threshold"
```

---

## 9. Log Aggregation

### 9.1 Structured JSON Logging Configuration

```python
# In .env.production
FIXOPS_LOG_LEVEL=INFO
FIXOPS_LOG_FORMAT=json
FIXOPS_LOG_INCLUDE_REQUEST_ID=true
FIXOPS_LOG_INCLUDE_USER_ID=true

# JSON log format example:
# {
#   "timestamp": "2026-03-08T02:34:56.789Z",
#   "level": "INFO",
#   "logger": "fixops.api",
#   "message": "Request completed",
#   "request_id": "550e8400-e29b-41d4-a716-446655440000",
#   "method": "POST",
#   "path": "/api/v1/scan",
#   "status_code": 200,
#   "duration_ms": 123,
#   "user_id": "user_abc123",
#   "org_id": "org_xyz789",
#   "ip": "10.0.0.50"
# }
```

### 9.2 Logging Configuration (Python)

```python
# logging_config.py
import logging.config

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "json",
            "filename": "/app/logs/fixops.log",
            "maxBytes": 104857600,  # 100MB
            "backupCount": 10,
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"],
    },
    "loggers": {
        "fixops": {"level": "INFO", "propagate": True},
        "uvicorn": {"level": "WARNING", "propagate": True},
        "fastapi": {"level": "WARNING", "propagate": True},
    },
}
```

### 9.3 SIEM Integration

```bash
# Forward logs to Splunk HEC
FIXOPS_SIEM_BACKEND=splunk
FIXOPS_SPLUNK_HEC_URL=https://splunk-hec.agency.gov:8088/services/collector
FIXOPS_SPLUNK_HEC_TOKEN=<splunk-hec-token>
FIXOPS_SPLUNK_INDEX=fixops-security

# Or forward to Elastic (ELK)
FIXOPS_SIEM_BACKEND=elasticsearch
FIXOPS_ELASTIC_URL=https://elasticsearch.agency.gov:9200
FIXOPS_ELASTIC_API_KEY=<elastic-api-key>
FIXOPS_ELASTIC_INDEX=fixops-logs

# Filebeat configuration for log shipping
# /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/fixops/logs/fixops.log
    json.keys_under_root: true
    json.overwrite_keys: true

output.elasticsearch:
  hosts: ["elasticsearch.agency.gov:9200"]
  index: "fixops-logs-%{+yyyy.MM.dd}"
```

---

## 10. Incident Response Procedures

### 10.1 Incident Classification

| Category | Description | Response Time | Examples |
|----------|-------------|---------------|---------|
| CAT 1 — Critical | Active compromise or data breach | Immediate (< 1 hour) | Admin credential theft, data exfiltration |
| CAT 2 — High | Significant security event | 4 hours | Privilege escalation, sustained injection attacks |
| CAT 3 — Medium | Security anomaly | 24 hours | Failed brute force, SSRF attempt |
| CAT 4 — Low | Policy violation / informational | 72 hours | Repeated rate limit hits |

### 10.2 Incident Response Runbook

#### Step 1 — Detection

```bash
# Query recent security events
curl -H "X-API-Key: $ADMIN_KEY" \
  "https://fixops.agency.gov/api/v1/audit/logs?event_type=SECURITY&severity=HIGH&limit=100"

# Check for active sessions from suspicious IPs
curl -H "X-API-Key: $ADMIN_KEY" \
  "https://fixops.agency.gov/api/v1/auth/active-sessions"
```

#### Step 2 — Containment

```bash
# Block a suspicious IP immediately
curl -X POST -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.100", "reason": "Active attack", "operator": "soc-analyst-1"}' \
  "https://fixops.agency.gov/api/v1/security/ip-block"

# Revoke all sessions for a compromised user
curl -X DELETE -H "X-API-Key: $ADMIN_KEY" \
  "https://fixops.agency.gov/api/v1/auth/users/{user_id}/sessions"

# Revoke a specific API key
curl -X DELETE -H "X-API-Key: $ADMIN_KEY" \
  "https://fixops.agency.gov/api/v1/auth/api-keys/{key_id}"
```

#### Step 3 — Evidence Collection

```bash
# Export audit log for incident window
curl -H "X-API-Key: $ADMIN_KEY" \
  "https://fixops.agency.gov/api/v1/audit/export?since=2026-03-08T00:00:00Z&until=2026-03-08T12:00:00Z&format=json" \
  > incident-audit-$(date +%Y%m%d_%H%M%S).json

# Capture system state
docker compose exec fixops-api python3 -c "
from core.audit_db import AuditDB
db = AuditDB()
# Export all events from last 24 hours
import json
events = db.get_recent_events(hours=24)
print(json.dumps(events, default=str, indent=2))
" > incident-evidence.json

# Sign evidence for chain of custody
gpg --armor --detach-sign incident-evidence.json
sha256sum incident-evidence.json > incident-evidence.sha256
```

#### Step 4 — Eradication and Recovery

```bash
# Rotate all API keys (invalidates all active sessions)
python3 scripts/emergency_key_rotation.py --confirm

# Rotate JWT secret (forces re-login for all users)
NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
# Update FIXOPS_JWT_SECRET in .env.production
sed -i "s/FIXOPS_JWT_SECRET=.*/FIXOPS_JWT_SECRET=${NEW_SECRET}/" /etc/fixops/.env.production

# Restart to apply new secret
docker compose -f docker/docker-compose.prod.yml restart fixops-api
```

#### Step 5 — Post-Incident Actions

1. Complete incident report within 24 hours (CAT 1/2) or 72 hours (CAT 3)
2. Update POA&M with new finding
3. Submit US-CERT report if required (CAT 1: within 1 hour; CAT 2: within 24 hours)
4. Conduct lessons-learned review within 5 business days
5. Update STIG checklist if new finding identified
6. Review and update security controls if gap identified

### 10.3 Emergency Contacts

```
# Populate with your organization's contacts
ISSO (Information System Security Officer): [NAME] [EMAIL] [PHONE]
ISSM (Information System Security Manager): [NAME] [EMAIL] [PHONE]
Authorizing Official: [NAME] [EMAIL] [PHONE]
US-CERT 24/7 Operations: 888-282-0870 / soc@us-cert.gov
CISA 24/7: 888-282-0870
DoD Cyber Crime Center (DC3): 410-981-0104
```

---

*This guide is a living document. Update after every security incident, deployment change, and annual review.*  
*Controlled document — do not distribute outside the authorization boundary.*
