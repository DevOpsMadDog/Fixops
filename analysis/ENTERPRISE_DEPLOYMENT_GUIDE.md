# FixOps Enterprise Deployment Guide: Gartner #1 Ready

## Overview

This guide provides comprehensive instructions for deploying FixOps in enterprise environments to meet Gartner Magic Quadrant #1 requirements. FixOps is designed to be the security platform that every company needs.

## Architecture Overview

### Enterprise Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer (HA)                        │
└──────────────────────┬───────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
┌───────▼────────┐          ┌────────▼────────┐
│  API Gateway   │          │  API Gateway    │
│   (Primary)    │          │  (Secondary)    │
└───────┬────────┘          └────────┬────────┘
        │                             │
        └──────────────┬───────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
┌───────▼────────┐          ┌────────▼────────┐
│  Application   │          │  Application    │
│   Servers      │          │   Servers       │
│  (Auto-scaling)│          │ (Auto-scaling)  │
└───────┬────────┘          └────────┬────────┘
        │                             │
        └──────────────┬───────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
┌───────▼────────┐          ┌────────▼────────┐
│   Database     │          │   Database      │
│  (Primary)     │◄────────►│  (Replica)      │
└────────────────┘          └─────────────────┘
        │
        │
┌───────▼────────┐
│  Object Store  │
│  (S3/GCS/Azure)│
└────────────────┘
```

## Deployment Requirements

### Infrastructure Requirements

#### Minimum (Development)
- **CPU**: 4 cores
- **Memory**: 16 GB RAM
- **Storage**: 100 GB SSD
- **Network**: 100 Mbps

#### Recommended (Production)
- **CPU**: 16+ cores
- **Memory**: 64+ GB RAM
- **Storage**: 1 TB+ SSD (NVMe preferred)
- **Network**: 1 Gbps+
- **High Availability**: Multi-region deployment

#### Enterprise (Gartner #1 Ready)
- **CPU**: 64+ cores (auto-scaling)
- **Memory**: 256+ GB RAM
- **Storage**: 10 TB+ (distributed)
- **Network**: 10 Gbps+
- **Availability Zones**: 3+ zones
- **Regions**: Multi-region for global deployment

### Software Requirements

- **OS**: Linux (Ubuntu 22.04 LTS, RHEL 8+, or containerized)
- **Python**: 3.11+
- **Database**: PostgreSQL 14+ (primary), Redis 7+ (cache)
- **Message Queue**: RabbitMQ 3.12+ or Apache Kafka
- **Container Runtime**: Docker 24+ or Kubernetes 1.28+
- **Orchestration**: Kubernetes (recommended)

## Deployment Options

### Option 1: Kubernetes (Recommended for Enterprise)

#### Prerequisites
- Kubernetes cluster 1.28+
- Helm 3.12+
- Ingress controller (NGINX, Traefik, etc.)
- Persistent volume provisioner

#### Deployment Steps

1. **Create Namespace**
```bash
kubectl create namespace fixops
```

2. **Install PostgreSQL**
```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgresql bitnami/postgresql \
  --namespace fixops \
  --set auth.postgresPassword=fixops_password \
  --set auth.database=fixops \
  --set persistence.size=100Gi
```

3. **Install Redis**
```bash
helm install redis bitnami/redis \
  --namespace fixops \
  --set auth.password=fixops_redis_password \
  --set master.persistence.size=50Gi
```

4. **Deploy FixOps**
```bash
# Clone FixOps repository
git clone https://github.com/fixops/fixops.git
cd fixops

# Install with Helm
helm install fixops ./deployment-packs/kubernetes \
  --namespace fixops \
  --set config.mode=enterprise \
  --set config.database.host=postgresql \
  --set config.redis.host=redis \
  --set replicas.api=3 \
  --set replicas.workers=5 \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=3 \
  --set autoscaling.maxReplicas=10
```

5. **Configure Ingress**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fixops-ingress
  namespace: fixops
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - fixops.yourcompany.com
    secretName: fixops-tls
  rules:
  - host: fixops.yourcompany.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: fixops-api
            port:
              number: 8000
```

### Option 2: Docker Compose (Development/Small Deployments)

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: fixops
      POSTGRES_USER: fixops
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  fixops-api:
    build: .
    environment:
      - FIXOPS_MODE=enterprise
      - DATABASE_URL=postgresql://fixops:${DB_PASSWORD}@postgres:5432/fixops
      - REDIS_URL=redis://redis:6379
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis
    volumes:
      - ./data:/app/data

  fixops-worker:
    build: .
    command: python -m risk.reachability.worker
    environment:
      - FIXOPS_MODE=enterprise
      - DATABASE_URL=postgresql://fixops:${DB_PASSWORD}@postgres:5432/fixops
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    volumes:
      - ./data:/app/data

volumes:
  postgres_data:
  redis_data:
```

### Option 3: Cloud-Native (AWS/Azure/GCP)

#### AWS Deployment

1. **ECS/Fargate**
```bash
# Deploy using AWS CDK or Terraform
cd deployment-packs/aws
terraform init
terraform plan
terraform apply
```

2. **EKS (Kubernetes)**
```bash
# Create EKS cluster
eksctl create cluster \
  --name fixops-cluster \
  --region us-east-1 \
  --node-type m5.2xlarge \
  --nodes 3 \
  --nodes-min 3 \
  --nodes-max 10
```

#### Azure Deployment

```bash
# Deploy using Azure CLI
az aks create \
  --resource-group fixops-rg \
  --name fixops-cluster \
  --node-count 3 \
  --node-vm-size Standard_D4s_v3 \
  --enable-cluster-autoscaler \
  --min-count 3 \
  --max-count 10
```

#### GCP Deployment

```bash
# Deploy using GKE
gcloud container clusters create fixops-cluster \
  --zone us-central1-a \
  --num-nodes 3 \
  --machine-type n1-standard-4 \
  --enable-autoscaling \
  --min-nodes 3 \
  --max-nodes 10
```

## Configuration

### Enterprise Configuration

Edit `config/fixops.overlay.yml`:

```yaml
mode: enterprise

# Database Configuration
database:
  host: ${DB_HOST}
  port: 5432
  name: fixops
  user: ${DB_USER}
  password: ${DB_PASSWORD}
  pool_size: 20
  max_overflow: 40
  ssl_mode: require

# Redis Configuration
redis:
  host: ${REDIS_HOST}
  port: 6379
  password: ${REDIS_PASSWORD}
  db: 0
  max_connections: 50

# Reachability Analysis
reachability_analysis:
  enabled: true
  enable_design_time: true
  enable_runtime: true
  enable_discrepancy_detection: true
  min_confidence_threshold: 0.5
  
  # Multi-tenancy
  multi_tenancy:
    enabled: true
    default_tier: enterprise
    default_sla: enterprise
  
  # Rate Limiting
  rate_limiting:
    enabled: true
    global_limit: 1000
    per_tenant_limit: 100
  
  # Quota Management
  quota_management:
    enabled: true
    max_concurrent_analyses: 50
    max_repositories: 1000
    max_components: 1000000
    storage_quota_gb: 1000
  
  # Job Queue
  job_queue:
    max_workers: 20
    max_retries: 3
    retry_delay_seconds: 60
    persistence_path: /data/reachability/jobs
  
  # Storage
  storage:
    database_path: /data/reachability/results.db
    cache_ttl_hours: 24
    max_cache_size_mb: 10000
  
  # Monitoring
  monitoring:
    enable_tracing: true
    enable_metrics: true
    metrics_endpoint: /metrics

# Security
security:
  enable_rbac: true
  enable_audit_logging: true
  session_timeout_minutes: 60
  max_login_attempts: 5
  password_min_length: 12
  require_mfa: true

# Compliance
compliance:
  enable_evidence_bundles: true
  enable_audit_trails: true
  retention_days: 2555  # 7 years
  encryption_at_rest: true
  encryption_in_transit: true
```

## High Availability Setup

### Database High Availability

1. **PostgreSQL Primary-Replica**
```bash
# Primary
helm install postgresql-primary bitnami/postgresql \
  --set replication.enabled=true \
  --set replication.synchronousCommit=on

# Replica
helm install postgresql-replica bitnami/postgresql \
  --set replication.enabled=true \
  --set replication.mode=replica \
  --set primary.host=postgresql-primary
```

2. **Redis Sentinel**
```bash
helm install redis bitnami/redis \
  --set sentinel.enabled=true \
  --set sentinel.quorum=2
```

### Application High Availability

1. **Multiple API Instances**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fixops-api
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: api
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
```

2. **Auto-scaling**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: fixops-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: fixops-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Monitoring and Observability

### Prometheus Metrics

FixOps exposes metrics at `/metrics`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: fixops-api-metrics
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8000"
    prometheus.io/path: "/metrics"
```

### Grafana Dashboards

Import dashboards from `deployment-packs/monitoring/grafana/`:

- FixOps Overview Dashboard
- Reachability Analysis Dashboard
- Performance Metrics Dashboard
- SLA Monitoring Dashboard

### Logging

Configure centralized logging:

```yaml
# Fluentd/Fluent Bit for log aggregation
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentd-config
data:
  fluent.conf: |
    <source>
      @type tail
      path /var/log/fixops/*.log
      pos_file /var/log/fluentd-fixops.log.pos
      tag fixops.*
      format json
    </source>
    <match fixops.**>
      @type elasticsearch
      host elasticsearch.logging.svc.cluster.local
      port 9200
      index_name fixops
      type_name _doc
    </match>
```

## Security Hardening

### Network Security

1. **Network Policies**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fixops-network-policy
spec:
  podSelector:
    matchLabels:
      app: fixops
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
    ports:
    - protocol: TCP
      port: 5432
```

2. **TLS/SSL**
- Use Let's Encrypt or internal CA
- Enable TLS 1.3 only
- Regular certificate rotation

### Access Control

1. **RBAC**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: fixops-admin
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
```

2. **SSO/SAML**
Configure in `config/fixops.overlay.yml`:
```yaml
authentication:
  provider: saml
  saml:
    entity_id: https://fixops.yourcompany.com
    sso_url: https://sso.yourcompany.com/saml
    certificate_path: /etc/fixops/saml/cert.pem
```

## Performance Optimization

### Caching Strategy

1. **Redis Caching**
- Analysis results: 24 hours
- Repository metadata: 7 days
- Threat intelligence: 1 hour

2. **CDN for Static Assets**
- Use CloudFront, Cloudflare, or Fastly
- Cache static files for 1 year

### Database Optimization

1. **Connection Pooling**
```yaml
database:
  pool_size: 20
  max_overflow: 40
  pool_timeout: 30
  pool_recycle: 3600
```

2. **Indexes**
```sql
CREATE INDEX idx_reachability_cve ON reachability_results(cve_id);
CREATE INDEX idx_reachability_component ON reachability_results(component_name, component_version);
CREATE INDEX idx_reachability_repo ON reachability_results(repo_url, repo_commit);
```

## Backup and Disaster Recovery

### Database Backups

```bash
# Automated backups
kubectl create cronjob postgres-backup \
  --image=postgres:15 \
  --schedule="0 2 * * *" \
  --restart=OnFailure \
  -- /bin/bash -c "pg_dump -h postgresql -U fixops fixops | gzip > /backups/fixops-$(date +%Y%m%d).sql.gz"
```

### Disaster Recovery Plan

1. **RTO (Recovery Time Objective)**: < 1 hour
2. **RPO (Recovery Point Objective)**: < 15 minutes
3. **Backup Retention**: 30 days daily, 12 months monthly
4. **Multi-Region Replication**: Active-active in 3 regions

## Support and SLA

### Support Tiers

1. **Standard**: Business hours, < 4 hour response
2. **Premium**: 24/7, < 1 hour response
3. **Enterprise**: 24/7, < 15 minute response, dedicated support

### SLA Guarantees

- **Uptime**: 99.99% (Enterprise tier)
- **Performance**: < 5 second API response (p95)
- **Availability**: Multi-region redundancy

## Conclusion

This deployment guide ensures FixOps meets Gartner Magic Quadrant #1 requirements with:

- ✅ Enterprise-grade architecture
- ✅ High availability and scalability
- ✅ Security and compliance
- ✅ Performance optimization
- ✅ Monitoring and observability
- ✅ Disaster recovery

**Result**: FixOps becomes the security platform that every company needs.
