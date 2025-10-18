# FixOps Deployment Packs

Complete Infrastructure-as-Code (IAC) deployment packs for FixOps Decision Engine with Backstage.io integration.

## Overview

This directory contains production-ready deployment configurations for deploying FixOps to various platforms:

- **AWS**: EKS deployment with Terraform
- **Azure**: AKS deployment with Terraform
- **Kubernetes**: Vanilla Kubernetes manifests (works with any K8s distribution)
- **Docker**: Docker Compose for standalone/edge deployments

Each deployment pack includes:
- Infrastructure-as-Code templates
- Backstage.io software templates
- Deployment automation scripts
- Configuration examples
- Comprehensive documentation

## Quick Start

### Choose Your Platform

| Platform | Best For | Complexity | Time to Deploy |
|----------|----------|------------|----------------|
| **Docker** | Development, Edge, Standalone | Low | 5 minutes |
| **Kubernetes** | Any K8s cluster, On-prem | Medium | 15 minutes |
| **AWS** | AWS EKS, Cloud-native | High | 30 minutes |
| **Azure** | Azure AKS, Enterprise | High | 30 minutes |

### Deployment Methods

#### Option 1: Backstage.io (Recommended)

1. Import templates into your Backstage instance:
   ```yaml
   # app-config.yaml
   catalog:
     locations:
       - type: url
         target: https://github.com/DevOpsMadDog/Fixops/tree/main/deployment-packs/aws/backstage/template.yaml
       - type: url
         target: https://github.com/DevOpsMadDog/Fixops/tree/main/deployment-packs/azure/backstage/template.yaml
       - type: url
         target: https://github.com/DevOpsMadDog/Fixops/tree/main/deployment-packs/kubernetes/backstage/template.yaml
       - type: url
         target: https://github.com/DevOpsMadDog/Fixops/tree/main/deployment-packs/docker/backstage/template.yaml
   ```

2. Navigate to "Create Component" in Backstage
3. Select "Deploy FixOps to [Platform]"
4. Fill in the configuration form
5. Click "Create" to generate and deploy

#### Option 2: Manual Deployment

Navigate to the specific deployment pack directory and follow the README:

```bash
# AWS
cd deployment-packs/aws
terraform init
terraform apply

# Azure
cd deployment-packs/azure
terraform init
terraform apply

# Kubernetes
cd deployment-packs/kubernetes
kubectl apply -k .

# Docker
cd deployment-packs/docker
docker-compose up -d
```

## Deployment Packs

### AWS Deployment Pack

**Location**: `deployment-packs/aws/`

**Features**:
- EKS cluster integration
- EBS persistent storage with encryption
- Application Load Balancer ingress
- Auto-scaling with HPA
- ACM certificate management
- S3 backend for Terraform state

**Prerequisites**:
- AWS CLI configured
- Existing EKS cluster
- VPC and subnets
- S3 bucket for Terraform state
- DynamoDB table for state locking

**Quick Deploy**:
```bash
cd deployment-packs/aws/terraform
terraform init
terraform plan -var="emergent_llm_key=$EMERGENT_LLM_KEY"
terraform apply
```

**Backstage Template**: `aws/backstage/template.yaml`

### Azure Deployment Pack

**Location**: `deployment-packs/azure/`

**Features**:
- AKS cluster integration
- Azure Disk persistent storage
- Application Gateway ingress
- Auto-scaling with HPA
- Azure Monitor integration
- Azure Storage backend for Terraform state

**Prerequisites**:
- Azure CLI configured
- Existing AKS cluster
- Resource group
- Storage account for Terraform state

**Quick Deploy**:
```bash
cd deployment-packs/azure/terraform
terraform init
terraform plan -var="emergent_llm_key=$EMERGENT_LLM_KEY"
terraform apply
```

**Backstage Template**: `azure/backstage/template.yaml`

### Kubernetes Deployment Pack

**Location**: `deployment-packs/kubernetes/`

**Features**:
- Vanilla Kubernetes manifests
- Works with any K8s distribution (k3s, k8s, OpenShift, Rancher)
- Kustomize support for overlays
- RBAC configuration
- Horizontal Pod Autoscaler
- Ingress with TLS support

**Prerequisites**:
- kubectl configured
- Access to Kubernetes cluster
- Storage class available

**Quick Deploy**:
```bash
cd deployment-packs/kubernetes
kubectl apply -k .
```

**Backstage Template**: `kubernetes/backstage/template.yaml`

### Docker Deployment Pack

**Location**: `deployment-packs/docker/`

**Features**:
- Docker Compose configuration
- Multi-container architecture
- Health checks and resource limits
- Optional frontend, Nginx, monitoring
- Persistent volumes
- Service profiles for optional components

**Prerequisites**:
- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum

**Quick Deploy**:
```bash
cd deployment-packs/docker
cp .env.example .env
# Edit .env with your configuration
docker-compose up -d
```

**Backstage Template**: `docker/backstage/template.yaml`

## Architecture

### Common Components

All deployment packs include:

1. **FixOps Backend**: FastAPI application (port 8001)
2. **MongoDB**: Evidence Lake database
3. **Redis**: Caching layer
4. **Persistent Storage**: Evidence and upload data
5. **Health Checks**: Liveness and readiness probes
6. **Resource Limits**: CPU and memory constraints

### Optional Components

- **Frontend**: React UI (port 3000)
- **Ingress/Load Balancer**: External access
- **Monitoring**: Prometheus and Grafana
- **Auto-scaling**: Horizontal Pod Autoscaler

## Configuration

### Required Secrets

All deployments require these secrets:

| Secret | Description | Example |
|--------|-------------|---------|
| `EMERGENT_LLM_KEY` | Emergent LLM API key | `sk-...` |
| `SECRET_KEY` | Application secret | `openssl rand -hex 32` |
| `MONGO_PASSWORD` | MongoDB password | `openssl rand -hex 16` |
| `REDIS_PASSWORD` | Redis password | `openssl rand -hex 16` |

### Optional Integrations

| Secret | Description |
|--------|-------------|
| `JIRA_TOKEN` | Jira API token for business context |
| `CONFLUENCE_TOKEN` | Confluence API token for threat models |

### Environment Variables

Common configuration across all platforms:

```bash
FIXOPS_ENVIRONMENT=production
FIXOPS_DEMO_MODE=false
FIXOPS_AUTH_DISABLED=false
FIXOPS_LOG_LEVEL=info
```

## Backstage.io Integration

### Template Features

All Backstage templates provide:

1. **Interactive Forms**: Guided configuration with validation
2. **Automated Deployment**: One-click infrastructure provisioning
3. **Service Catalog**: Automatic registration in Backstage
4. **Documentation**: Embedded README and guides
5. **Links**: Quick access to deployed services

### Template Structure

```yaml
apiVersion: scaffolder.backstage.io/v1beta3
kind: Template
metadata:
  name: fixops-{platform}-deployment
  title: Deploy FixOps to {Platform}
spec:
  parameters:
    - Configuration forms
  steps:
    - Fetch templates
    - Generate configuration
    - Deploy infrastructure
    - Register in catalog
  output:
    - Links to resources
```

### Importing Templates

Add to your Backstage `app-config.yaml`:

```yaml
catalog:
  locations:
    # AWS Template
    - type: url
      target: https://github.com/DevOpsMadDog/Fixops/tree/main/deployment-packs/aws/backstage/template.yaml
      rules:
        - allow: [Template]
    
    # Azure Template
    - type: url
      target: https://github.com/DevOpsMadDog/Fixops/tree/main/deployment-packs/azure/backstage/template.yaml
      rules:
        - allow: [Template]
    
    # Kubernetes Template
    - type: url
      target: https://github.com/DevOpsMadDog/Fixops/tree/main/deployment-packs/kubernetes/backstage/template.yaml
      rules:
        - allow: [Template]
    
    # Docker Template
    - type: url
      target: https://github.com/DevOpsMadDog/Fixops/tree/main/deployment-packs/docker/backstage/template.yaml
      rules:
        - allow: [Template]
```

## Comparison Matrix

| Feature | AWS | Azure | Kubernetes | Docker |
|---------|-----|-------|------------|--------|
| **Cloud Provider** | AWS | Azure | Any | Any |
| **Orchestration** | EKS | AKS | K8s | Docker Compose |
| **IAC Tool** | Terraform | Terraform | kubectl/kustomize | docker-compose |
| **Load Balancer** | ALB | App Gateway | Ingress | Nginx (optional) |
| **Storage** | EBS | Azure Disk | PVC | Volumes |
| **Auto-scaling** | ✅ | ✅ | ✅ | ❌ |
| **HA Support** | ✅ | ✅ | ✅ | Limited |
| **Monitoring** | CloudWatch | Azure Monitor | Prometheus | Prometheus (optional) |
| **Complexity** | High | High | Medium | Low |
| **Best For** | AWS Cloud | Azure Cloud | Any K8s | Dev/Edge |

## Security Best Practices

### All Platforms

1. **Secrets Management**:
   - Never commit secrets to Git
   - Use environment variables or secret managers
   - Rotate secrets regularly

2. **Network Security**:
   - Restrict ingress to necessary ports
   - Use TLS/SSL for external access
   - Implement network policies

3. **Access Control**:
   - Enable authentication (`FIXOPS_AUTH_DISABLED=false`)
   - Use RBAC for Kubernetes deployments
   - Implement least-privilege IAM roles

4. **Data Protection**:
   - Enable encryption at rest
   - Backup evidence lake regularly
   - Set appropriate retention policies

### Platform-Specific

**AWS**:
- Use AWS Secrets Manager or Parameter Store
- Enable VPC flow logs
- Use AWS WAF for ALB

**Azure**:
- Use Azure Key Vault
- Enable Azure Security Center
- Use Azure Firewall

**Kubernetes**:
- Use Pod Security Standards
- Implement Network Policies
- Use cert-manager for TLS

**Docker**:
- Use Docker secrets
- Restrict network access with firewall
- Keep images updated

## Monitoring and Observability

### Metrics

FixOps exposes Prometheus metrics at `/metrics`:

- `fixops_http_requests_total`: Total HTTP requests
- `fixops_decision_latency_seconds`: Decision engine latency
- `fixops_evidence_lake_size_bytes`: Evidence storage size

### Logs

Access logs via:

**Kubernetes**:
```bash
kubectl logs -f deployment/fixops-backend -n fixops
```

**Docker**:
```bash
docker-compose logs -f fixops-backend
```

### Health Checks

All deployments include health endpoints:

- `/health`: Liveness probe
- `/ready`: Readiness probe
- `/metrics`: Prometheus metrics

## Troubleshooting

### Common Issues

**Backend won't start**:
- Check MongoDB connection string
- Verify secrets are set correctly
- Review logs for errors

**Database connection failed**:
- Ensure MongoDB is running and healthy
- Check network connectivity
- Verify credentials

**High memory usage**:
- Reduce worker count
- Increase resource limits
- Check for memory leaks in logs

**Ingress not accessible**:
- Verify DNS configuration
- Check TLS certificates
- Review ingress controller logs

### Platform-Specific

**AWS**:
- Check EKS cluster status
- Verify IAM roles and policies
- Review ALB target group health

**Azure**:
- Check AKS cluster status
- Verify managed identity permissions
- Review Application Gateway backend health

**Kubernetes**:
- Check storage class availability
- Verify ingress controller is running
- Review pod events

**Docker**:
- Check Docker daemon status
- Verify port availability
- Review container logs

## Support and Contributing

### Documentation

- [FixOps Architecture](../ARCHITECTURE.md)
- [Configuration Guide](../docs/CONFIG_GUIDE.md)
- [Security Guide](../docs/SECURITY.md)

### Getting Help

- GitHub Issues: https://github.com/DevOpsMadDog/Fixops/issues
- Documentation: https://github.com/DevOpsMadDog/Fixops/tree/main/docs

### Contributing

Contributions welcome! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](../LICENSE) for details.
