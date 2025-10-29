# FixOps Telemetry Bridge

Multi-cloud telemetry ingestion and evidence generation system for FixOps that integrates with the existing overlay framework.

## Overview

The Telemetry Bridge streams runtime telemetry from **AWS**, **Azure**, and **GCP** into FixOps' Operate stage in near real-time, without ballooning costs. It provides:

- **Cloud Connectors**: AWS Lambda, Azure Function, GCP Cloud Function for ingesting logs from CloudWatch, Event Hub, and Pub/Sub
- **Edge Collector**: FastAPI service with `/telemetry` and `/evidence` endpoints for aggregation at the edge
- **Ring Buffer**: In-memory retention of raw logs (default 6 hours) for on-demand evidence generation
- **Evidence Bundles**: Compressed, cryptographically-signed JSONL bundles with SHA256 hashes
- **Multi-Cloud Deployment**: ECS Fargate, Azure Container Apps (with Dapr), GKE Autopilot, and AKS (with KEDA)
- **Cost Optimization**: Edge aggregation, lifecycle policies, and configurable retention periods

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Cloud Provider Logs                          │
│  AWS CloudWatch │ Azure Event Hub │ GCP Pub/Sub                 │
└────────┬────────────────┬────────────────┬──────────────────────┘
         │                │                │
         ▼                ▼                ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│  AWS Lambda    │ │ Azure Function │ │ GCP Function   │
│  (Python 3.11) │ │  (Python)      │ │ (Python 3.11)  │
└────────┬───────┘ └────────┬───────┘ └────────┬───────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │   Edge Collector      │
                │   (FastAPI)           │
                │                       │
                │  • /telemetry         │
                │  • /evidence          │
                │  • Ring Buffer        │
                └───────────┬───────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
         ▼                  ▼                  ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│  Fluent Bit    │ │     Vector     │ │   FixOps API   │
│  (Lua agg)     │ │  (VRL agg)     │ │   /operate     │
└────────────────┘ └────────────────┘ └────────────────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │  Cloud Object Store   │
                │  S3 │ Blob │ GCS      │
                │  (Lifecycle Policies) │
                └───────────────────────┘
```

## Configuration

### Overlay Integration

All configuration is managed through the **existing FixOps overlay system**:

- **Default**: `config/fixops.overlay.yml`
- **Override**: Set `FIXOPS_OVERLAY_PATH` environment variable

The telemetry bridge extends the overlay with a top-level `telemetry_bridge` section:

```yaml
telemetry_bridge:
  mode: http                    # or 'file' for local testing
  fixops_url: https://fixops.example/api/v1/telemetry
  api_key_secret_ref: fixops-api-key
  
  # Cost & retention controls
  ring_buffer:
    max_lines: 200000           # ~200K lines in memory
    max_seconds: 21600          # 6 hours retention
  
  retention_days:
    raw: 7                      # Raw logs: 7 days
    summary: 30                 # Summaries: 30 days
    evidence: 365               # Evidence: 1 year (then archive)
  
  # Fluent Bit configuration
  fluentbit:
    input_path: /var/log/waf/*.log
    aggregation_interval: 60    # seconds
    retry_limit: 5
  
  # Vector configuration
  vector:
    input_path: /logs/app.log
    flush_interval: 30          # seconds
  
  # Cloud-specific settings
  aws:
    region: ap-southeast-2
    s3_bucket: fixops-evidence
    cw_log_groups: []
  
  azure:
    location: australiaeast
    storage_account: fixopsevidence
    event_hub: platform-logs
    key_vault_name: fixops-kv
  
  gcp:
    project_id: my-fixops
    gcs_bucket: fixops-evidence
```

### Telemetry Schema

All connectors emit identical JSON matching `shared/schemas/ops-telemetry.schema.json`:

```json
{
  "alerts": [
    {
      "rule": "waf-blocks",
      "count": 25
    }
  ],
  "latency_ms_p95": 350
}
```

## Deployment

### Prerequisites

- Python 3.11+
- Docker and Docker Compose (for local development)
- Terraform 1.0+ (for IaC deployments)
- Cloud provider CLI tools (AWS CLI, Azure CLI, gcloud)

### Local Development with Docker Compose

1. **Start services**:
   ```bash
   cd telemetry_bridge
   docker-compose up -d
   ```

2. **Verify health**:
   ```bash
   curl http://localhost:8080/health
   ```

3. **Ingest telemetry**:
   ```bash
   curl -X POST http://localhost:8080/telemetry \
     -H "Content-Type: application/json" \
     -d '{
       "alerts": [{"rule": "waf-blocks", "count": 10}],
       "latency_ms_p95": 250
     }'
   ```

4. **Generate evidence bundle**:
   ```bash
   curl "http://localhost:8080/evidence?since=3600&asset=app-1"
   ```

5. **Run with FixOps CLI**:
   ```bash
   cd ..
   python -m core.cli demo --mode demo --output out/pipeline-demo.json
   ```

6. **Stop services**:
   ```bash
   docker-compose down -v
   ```

### AWS Deployment (Lambda + ECS Fargate)

#### 1. Deploy Lambda Connector

```bash
cd telemetry_bridge/aws_lambda/terraform

# Initialize Terraform
terraform init

# Deploy
terraform apply \
  -var="aws_region=ap-southeast-2" \
  -var="prefix=fixops" \
  -var="fixops_api_key=YOUR_API_KEY"

# Outputs: lambda_function_arn, log_group_name
```

#### 2. Deploy Edge Collector on ECS Fargate

```bash
cd ../../edge_collector/terraform

# Build and push Docker images
aws ecr get-login-password --region ap-southeast-2 | \
  docker login --username AWS --password-stdin ACCOUNT_ID.dkr.ecr.ap-southeast-2.amazonaws.com

docker build -t fixops-collector-api ../collector_api
docker tag fixops-collector-api:latest ACCOUNT_ID.dkr.ecr.ap-southeast-2.amazonaws.com/fixops-collector-api:latest
docker push ACCOUNT_ID.dkr.ecr.ap-southeast-2.amazonaws.com/fixops-collector-api:latest

docker build -t fixops-fluent-bit ../fluent-bit
docker tag fixops-fluent-bit:latest ACCOUNT_ID.dkr.ecr.ap-southeast-2.amazonaws.com/fixops-fluent-bit:latest
docker push ACCOUNT_ID.dkr.ecr.ap-southeast-2.amazonaws.com/fixops-fluent-bit:latest

# Create Secrets Manager secret for API key
aws secretsmanager create-secret \
  --name fixops-api-key \
  --secret-string "YOUR_API_KEY" \
  --region ap-southeast-2

# Deploy ECS Fargate
terraform init
terraform apply \
  -var="aws_region=ap-southeast-2" \
  -var="prefix=fixops" \
  -var="fixops_api_key_secret_arn=arn:aws:secretsmanager:..."

# Outputs: alb_url, ecs_cluster_name, s3_bucket_name
```

### Azure Deployment (Function + Container Apps)

#### 1. Deploy Azure Function Connector

```bash
cd telemetry_bridge/azure_function/bicep

# Login to Azure
az login

# Create resource group
az group create --name fixops-telemetry-rg --location australiaeast

# Deploy Bicep template
az deployment group create \
  --resource-group fixops-telemetry-rg \
  --template-file main.bicep \
  --parameters prefix=fixops \
  --parameters fixopsApiKey=YOUR_API_KEY

# Outputs: functionAppName, eventHubNamespace
```

#### 2. Deploy Edge Collector on Azure Container Apps

```bash
cd ../../edge_collector/azure

# Build and push Docker images to ACR
az acr login --name fixopsacr

docker build -t fixopsacr.azurecr.io/collector-api:latest ../collector_api
docker push fixopsacr.azurecr.io/collector-api:latest

docker build -t fixopsacr.azurecr.io/fluent-bit:latest ../fluent-bit
docker push fixopsacr.azurecr.io/fluent-bit:latest

# Deploy Container Apps
az deployment group create \
  --resource-group fixops-telemetry-rg \
  --template-file main.bicep \
  --parameters prefix=fixops \
  --parameters fixopsApiKey=YOUR_API_KEY

# Outputs: containerAppUrl, storageAccountName
```

### GCP Deployment (Cloud Function + GKE Autopilot)

#### 1. Deploy GCP Cloud Function Connector

```bash
cd telemetry_bridge/gcp_function/terraform

# Login to GCP
gcloud auth application-default login

# Deploy
terraform init
terraform apply \
  -var="project_id=my-fixops" \
  -var="region=australia-southeast1" \
  -var="prefix=fixops" \
  -var="fixops_api_key=YOUR_API_KEY"

# Outputs: function_name, pubsub_topic, storage_bucket
```

#### 2. Deploy Edge Collector on GKE Autopilot

```bash
cd ../../edge_collector/gcp

# Build and push Docker images to Artifact Registry
gcloud auth configure-docker australia-southeast1-docker.pkg.dev

docker build -t australia-southeast1-docker.pkg.dev/my-fixops/fixops-images/collector-api:latest ../collector_api
docker push australia-southeast1-docker.pkg.dev/my-fixops/fixops-images/collector-api:latest

docker build -t australia-southeast1-docker.pkg.dev/my-fixops/fixops-images/fluent-bit:latest ../fluent-bit
docker push australia-southeast1-docker.pkg.dev/my-fixops/fixops-images/fluent-bit:latest

# Deploy GKE Autopilot
terraform init
terraform apply \
  -var="project_id=my-fixops" \
  -var="region=australia-southeast1" \
  -var="prefix=fixops" \
  -var="fixops_api_key=YOUR_API_KEY"

# Get cluster credentials
gcloud container clusters get-credentials fixops-autopilot-cluster \
  --region australia-southeast1 \
  --project my-fixops

# Verify deployment
kubectl get pods -n fixops-telemetry

# Outputs: cluster_name, collector_service_url
```

### AKS Deployment (Helm + KEDA)

```bash
cd telemetry_bridge/edge_collector/aks

# Login to Azure
az login

# Create AKS cluster (if not exists)
az aks create \
  --resource-group fixops-telemetry-rg \
  --name fixops-aks \
  --location australiaeast \
  --enable-managed-identity \
  --node-count 2

# Get credentials
az aks get-credentials --resource-group fixops-telemetry-rg --name fixops-aks

# Install KEDA
helm repo add kedacore https://kedacore.github.io/charts
helm repo update
helm install keda kedacore/keda --namespace keda --create-namespace

# Create secrets
kubectl create secret generic fixops-api-key \
  --from-literal=api-key=YOUR_API_KEY

kubectl create secret generic storage-connection-string \
  --from-literal=connection-string="DefaultEndpointsProtocol=https;..."

kubectl create secret generic eventhub-connection-string \
  --from-literal=connection-string="Endpoint=sb://..."

# Install Helm chart
helm install fixops-telemetry . \
  --set image.collectorApi.repository=fixopsacr.azurecr.io/collector-api \
  --set image.fluentBit.repository=fixopsacr.azurecr.io/fluent-bit \
  --set keda.enabled=true \
  --set keda.eventHub.enabled=true

# Verify deployment
kubectl get pods
kubectl get scaledobject

# Outputs: Service URL via kubectl get svc
```

## Testing

### Unit Tests

Run unit tests for all components:

```bash
# AWS Lambda
cd telemetry_bridge/aws_lambda
pytest test_handler.py -v

# Azure Function
cd ../azure_function
pytest test_function.py -v

# GCP Cloud Function
cd ../gcp_function
pytest test_main.py -v

# Edge Collector API
cd ../edge_collector/collector_api
pytest test_app.py -v
```

### Integration Tests

Run end-to-end integration tests:

```bash
cd telemetry_bridge
pytest tests/test_integration.py -v
```

Integration tests cover:
- Health check endpoints
- Telemetry ingestion (file and HTTP modes)
- Evidence bundle generation
- Ring buffer functionality
- Multi-source telemetry handling
- CLI integration
- Cloud connector simulations

## Usage

### Ingesting Telemetry

**HTTP Mode** (production):
```python
import requests

telemetry = {
    "alerts": [{"rule": "waf-blocks", "count": 25}],
    "latency_ms_p95": 350
}

response = requests.post(
    "https://collector.fixops.example/telemetry",
    json=telemetry,
    headers={"X-API-Key": "YOUR_API_KEY"}
)
```

**File Mode** (local testing):
```bash
# Telemetry is written to demo_decision_inputs/ops-telemetry.json
curl -X POST http://localhost:8080/telemetry \
  -H "Content-Type: application/json" \
  -d '{"alerts":[{"rule":"waf-blocks","count":10}],"latency_ms_p95":200}'

# Use with FixOps CLI
python -m core.cli demo --mode demo
```

### Generating Evidence Bundles

```bash
# Generate evidence for last hour
curl "http://localhost:8080/evidence?since=3600"

# Filter by asset
curl "http://localhost:8080/evidence?since=3600&asset=app-1"
```

Response includes:
- Compressed JSONL bundle (gzipped)
- SHA256 hash for integrity verification
- Upload confirmation to cloud storage
- Metadata (timestamp, line count, size)

### Querying Evidence

Evidence bundles are stored in cloud object storage with lifecycle policies:

**AWS S3**:
```bash
aws s3 ls s3://fixops-evidence/evidence/
aws s3 cp s3://fixops-evidence/evidence/evidence-20240115-120000-abc12345.jsonl.gz .
```

**Azure Blob**:
```bash
az storage blob list --account-name fixopsevidence --container-name evidence
az storage blob download --account-name fixopsevidence --container-name evidence \
  --name evidence-20240115-120000-abc12345.jsonl.gz --file ./evidence.jsonl.gz
```

**GCP GCS**:
```bash
gsutil ls gs://fixops-evidence/evidence/
gsutil cp gs://fixops-evidence/evidence/evidence-20240115-120000-abc12345.jsonl.gz .
```

## Monitoring

### Health Checks

```bash
# Collector API health
curl http://collector-api:8080/health

# Expected response:
# {"status": "healthy", "timestamp": "2024-01-15T12:00:00.000Z"}
```

### Metrics

The Edge Collector exposes Prometheus-compatible metrics:

- `telemetry_requests_total`: Total telemetry ingestion requests
- `evidence_bundles_generated_total`: Total evidence bundles created
- `ring_buffer_size`: Current ring buffer size
- `ring_buffer_evictions_total`: Number of evicted entries

### Logs

**AWS CloudWatch**:
```bash
aws logs tail /ecs/fixops-collector --follow
```

**Azure Log Analytics**:
```bash
az monitor log-analytics query \
  --workspace fixops-logs \
  --analytics-query "ContainerAppConsoleLogs_CL | where ContainerName_s == 'collector-api'"
```

**GCP Cloud Logging**:
```bash
gcloud logging read "resource.type=k8s_container AND resource.labels.namespace_name=fixops-telemetry"
```

## Cost Optimization

The Telemetry Bridge is designed for cost efficiency:

1. **Edge Aggregation**: Fluent Bit/Vector aggregate at the edge (60s intervals)
2. **Ring Buffer**: Only 6 hours of raw logs in memory (200K lines)
3. **On-Demand Evidence**: Bundles generated only when FixOps escalates risk
4. **Lifecycle Policies**:
   - Raw logs: 7 days → delete
   - Summaries: 30 days → delete
   - Evidence: 90 days (hot) → 180 days (cool) → 365 days (archive)
5. **Serverless Functions**: Pay-per-invocation for cloud connectors
6. **Auto-scaling**: KEDA scales based on Event Hub lag

## Troubleshooting

### Collector API not responding

```bash
# Check container logs
docker-compose logs collector-api

# Verify overlay configuration
cat config/fixops.overlay.yml | grep telemetry_bridge

# Test health endpoint
curl -v http://localhost:8080/health
```

### Telemetry not reaching FixOps

```bash
# Check mode configuration
echo $TELEMETRY_MODE  # Should be 'http' for production

# Verify API key
echo $FIXOPS_API_KEY

# Test connectivity
curl -X POST https://fixops.example/api/v1/telemetry \
  -H "X-API-Key: $FIXOPS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"alerts":[],"latency_ms_p95":null}'
```

### Evidence bundles not uploading

```bash
# Check cloud provider credentials
aws sts get-caller-identity  # AWS
az account show              # Azure
gcloud auth list             # GCP

# Verify storage bucket exists
aws s3 ls s3://fixops-evidence/        # AWS
az storage container show --name evidence  # Azure
gsutil ls gs://fixops-evidence/        # GCP
```

### KEDA not scaling

```bash
# Check ScaledObject status
kubectl get scaledobject -o yaml

# Verify Event Hub connection
kubectl logs -l app=collector-api | grep "eventhub"

# Check KEDA operator logs
kubectl logs -n keda -l app=keda-operator
```

## Security

- **API Keys**: Stored in cloud secret managers (Secrets Manager, Key Vault, Secret Manager)
- **Evidence Signing**: RSA-SHA256 signatures on all bundles
- **Encryption**: TLS in transit, encryption at rest for cloud storage
- **RBAC**: Workload identity (GKE), managed identity (AKS/ACA), IAM roles (ECS)
- **Network Isolation**: Private subnets, security groups, network policies

## Contributing

1. Follow existing overlay configuration patterns
2. Emit standardized telemetry JSON schema
3. Include comprehensive unit and integration tests
4. Update this README with new deployment targets
5. Ensure all IaC reads from overlay configuration

## License

Copyright © 2024 FixOps. All rights reserved.

## Support

For issues or questions:
- GitHub Issues: https://github.com/DevOpsMadDog/Fixops/issues
- Documentation: https://docs.fixops.example
- Email: support@fixops.example
