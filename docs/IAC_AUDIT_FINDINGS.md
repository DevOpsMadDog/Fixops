# IaC Infrastructure Audit Findings

**Date:** 2025-11-01  
**Audit Type:** Comprehensive IaC review for FixOps platform  
**Purpose:** Identify issues, security concerns, and improvements needed in infrastructure as code

## Overview

The FixOps platform has infrastructure code spread across multiple locations:
- Docker Compose files for local/enterprise deployment
- Terraform modules for AWS, Azure, GCP deployments
- Kubernetes manifests (archived legacy)
- Dockerfiles for containerization

## Active IaC Files

### Docker Compose
1. **docker-compose.enterprise.yml** - Enterprise mode with ChromaDB
2. **Archived:** docker-compose.yml (removed per README)

### Dockerfiles
1. **Dockerfile.enterprise** - Enterprise container with ChromaDB
2. **Dockerfile.demo** - Demo mode container
3. **frontend/Dockerfile** - Frontend container
4. **telemetry_bridge/*/Dockerfile** - Telemetry collector containers

### Terraform Modules
1. **deployment-packs/aws/terraform/main.tf** - AWS EKS deployment
2. **deployment-packs/azure/terraform/main.tf** - Azure deployment
3. **telemetry_bridge/aws_lambda/terraform/main.tf** - AWS Lambda telemetry
4. **telemetry_bridge/gcp_function/terraform/main.tf** - GCP function telemetry
5. **telemetry_bridge/edge_collector/terraform/main.tf** - Edge collector

## Issues Found

### Issue #1: Missing Backend State Configuration (AWS Terraform)
**Severity:** HIGH  
**Location:** `deployment-packs/aws/terraform/main.tf:19-22`

**Problem:**
```hcl
backend "s3" {
  # terraform init -backend-config="bucket=BUCKET" -backend-config="key=fixops/ENV/terraform.tfstate" \
  encrypt = true
}
```

The S3 backend is defined but requires manual configuration via CLI flags. This is error-prone and not documented.

**Impact:**
- State file location not clear
- No DynamoDB table for state locking configured
- Risk of concurrent modifications
- No automated state management

**Recommendation:**
- Use variables for backend configuration
- Document backend initialization in README
- Add DynamoDB table resource for state locking
- Consider using Terraform Cloud or Atlantis for team collaboration

### Issue #2: Hardcoded Image Tags
**Severity:** MEDIUM  
**Location:** `deployment-packs/aws/terraform/main.tf:291`

**Problem:**
```hcl
image = "fixops/backend:latest"
```

Using `:latest` tag in production deployments is an anti-pattern.

**Impact:**
- No version control for deployments
- Unpredictable rollbacks
- Cannot track which version is deployed
- Cache issues with image pulls

**Recommendation:**
- Use semantic versioning tags (e.g., `fixops/backend:v1.2.3`)
- Add variable for image tag
- Implement CI/CD pipeline to update image tags
- Use image digests for immutable deployments

### Issue #3: Missing Resource Limits in Docker Compose
**Severity:** MEDIUM  
**Location:** `docker-compose.enterprise.yml`

**Problem:**
No resource limits defined for the container.

**Impact:**
- Container can consume all host resources
- No protection against memory leaks
- Poor multi-tenant isolation
- Potential host instability

**Recommendation:**
```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 4G
    reservations:
      cpus: '0.5'
      memory: 1G
```

### Issue #4: Secrets in Environment Variables
**Severity:** HIGH  
**Location:** `docker-compose.enterprise.yml:26-28`

**Problem:**
```yaml
- OPENAI_API_KEY=${OPENAI_API_KEY:-}
- ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
- GOOGLE_API_KEY=${GOOGLE_API_KEY:-}
```

While using environment variable substitution, there's no guidance on secure secret management.

**Impact:**
- Secrets may be logged
- No rotation mechanism
- No audit trail
- Risk of exposure in process listings

**Recommendation:**
- Use Docker secrets or external secret management (AWS Secrets Manager, HashiCorp Vault)
- Document secret rotation procedures
- Add secret scanning to CI/CD
- Implement least-privilege access

### Issue #5: Missing Health Check in Docker Compose
**Severity:** LOW  
**Location:** `docker-compose.enterprise.yml`

**Problem:**
No healthcheck defined for the service.

**Impact:**
- Docker doesn't know if service is healthy
- No automatic restart on failure
- Poor orchestration with dependent services

**Recommendation:**
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Issue #6: Incomplete Terraform Variables Documentation
**Severity:** LOW  
**Location:** `deployment-packs/aws/terraform/main.tf`

**Problem:**
Variables like `emergent_llm_key` (line 84) reference outdated naming.

**Impact:**
- Confusion about required variables
- Outdated references to "emergent" LLM
- Poor developer experience

**Recommendation:**
- Update variable names to match current architecture
- Add comprehensive variable descriptions
- Create terraform.tfvars.example file
- Document all required and optional variables

### Issue #7: Missing Network Policies
**Severity:** MEDIUM  
**Location:** `deployment-packs/aws/terraform/main.tf`

**Problem:**
No Kubernetes NetworkPolicies defined.

**Impact:**
- All pods can communicate freely
- No network segmentation
- Increased blast radius for security incidents
- Non-compliance with zero-trust principles

**Recommendation:**
- Add NetworkPolicy resources
- Restrict ingress/egress by default
- Allow only necessary pod-to-pod communication
- Document network architecture

### Issue #8: Missing Backup Strategy
**Severity:** HIGH  
**Location:** `deployment-packs/aws/terraform/main.tf:215-232`

**Problem:**
Evidence Lake PVC has no backup configuration.

**Impact:**
- Risk of data loss
- No disaster recovery plan
- Cannot restore to previous state
- Compliance issues

**Recommendation:**
- Implement EBS snapshot lifecycle policy
- Add backup to S3 with versioning
- Document restore procedures
- Test backup/restore regularly

### Issue #9: Telemetry Lambda Missing Error Handling
**Severity:** MEDIUM  
**Location:** `telemetry_bridge/aws_lambda/terraform/main.tf`

**Problem:**
Lambda function has no dead-letter queue or retry configuration.

**Impact:**
- Lost telemetry data on failures
- No visibility into processing errors
- Cannot replay failed events

**Recommendation:**
- Add SQS dead-letter queue
- Configure retry attempts
- Add CloudWatch alarms for failures
- Implement idempotent processing

### Issue #10: Missing Cost Controls
**Severity:** MEDIUM  
**Location:** All Terraform modules

**Problem:**
No cost management resources (budgets, alerts).

**Impact:**
- Unexpected cloud costs
- No spending visibility
- Cannot track cost per environment

**Recommendation:**
- Add AWS Budgets resources
- Implement cost allocation tags
- Add CloudWatch billing alarms
- Document expected costs per environment

## Positive Findings

1. ✅ Encryption enabled for EBS volumes (line 210)
2. ✅ Resource tagging implemented (local.common_tags)
3. ✅ Horizontal pod autoscaling configured
4. ✅ Liveness and readiness probes defined
5. ✅ TLS/HTTPS enforced via ALB
6. ✅ IRSA (IAM Roles for Service Accounts) used for EBS CSI driver

## Recommendations Summary

### High Priority
1. Fix S3 backend state configuration
2. Implement secret management solution
3. Add backup strategy for Evidence Lake
4. Remove `:latest` image tags

### Medium Priority
5. Add resource limits to Docker Compose
6. Implement Kubernetes NetworkPolicies
7. Add dead-letter queue for Lambda
8. Implement cost controls

### Low Priority
9. Add health checks to Docker Compose
10. Update variable documentation
11. Add comprehensive examples

## Next Steps

1. Create fixed IaC files with all issues addressed
2. Add comprehensive documentation
3. Create deployment runbooks
4. Implement automated testing for IaC
5. Add security scanning (tfsec, checkov)
