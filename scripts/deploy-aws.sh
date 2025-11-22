#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TERRAFORM_DIR="$ROOT_DIR/deployment-packs/aws/terraform"

echo "========================================="
echo "   FixOps AWS EKS Deployment"
echo "========================================="
echo ""

if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install: https://aws.amazon.com/cli/"
    exit 1
fi

if ! command -v terraform &> /dev/null; then
    echo "❌ Terraform not found. Please install: https://www.terraform.io/downloads"
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

read -p "AWS Region [us-east-1]: " AWS_REGION
AWS_REGION="${AWS_REGION:-us-east-1}"

read -p "Environment (development/staging/production) [production]: " ENVIRONMENT
ENVIRONMENT="${ENVIRONMENT:-production}"

read -p "Cluster Name [fixops-${ENVIRONMENT}]: " CLUSTER_NAME
CLUSTER_NAME="${CLUSTER_NAME:-fixops-${ENVIRONMENT}}"

read -p "Domain Name: " DOMAIN_NAME
if [[ -z "$DOMAIN_NAME" ]]; then
    echo "❌ Domain name is required"
    exit 1
fi

if [[ -z "${EMERGENT_LLM_KEY:-}" ]]; then
    read -sp "Emergent LLM Key: " EMERGENT_LLM_KEY
    echo ""
    if [[ -z "$EMERGENT_LLM_KEY" ]]; then
        echo "❌ Emergent LLM key is required"
        exit 1
    fi
fi

export TF_VAR_emergent_llm_key="$EMERGENT_LLM_KEY"

read -p "Terraform State S3 Bucket: " STATE_BUCKET
if [[ -z "$STATE_BUCKET" ]]; then
    echo "❌ Terraform state bucket is required"
    exit 1
fi

read -p "Terraform Lock DynamoDB Table: " LOCK_TABLE
if [[ -z "$LOCK_TABLE" ]]; then
    echo "❌ Terraform lock table is required"
    exit 1
fi

read -p "VPC ID: " VPC_ID
if [[ -z "$VPC_ID" ]]; then
    echo "❌ VPC ID is required"
    exit 1
fi

read -p "Subnet IDs (comma-separated): " SUBNET_IDS
if [[ -z "$SUBNET_IDS" ]]; then
    echo "❌ Subnet IDs are required"
    exit 1
fi

cat > "$TERRAFORM_DIR/terraform.tfvars" <<EOF
aws_region              = "$AWS_REGION"
environment             = "$ENVIRONMENT"
cluster_name            = "$CLUSTER_NAME"
domain_name             = "$DOMAIN_NAME"
terraform_state_bucket  = "$STATE_BUCKET"
terraform_lock_table    = "$LOCK_TABLE"
vpc_id                  = "$VPC_ID"
subnet_ids              = ["${SUBNET_IDS//,/\",\"}"]
backend_replicas        = 3
enable_monitoring       = true
enable_autoscaling      = true
enable_backup           = true
backup_retention_days   = 30
EOF

if ! grep -q "terraform.tfvars" "$ROOT_DIR/.gitignore" 2>/dev/null; then
    echo "terraform.tfvars" >> "$ROOT_DIR/.gitignore"
    echo "✅ Added terraform.tfvars to .gitignore"
fi

echo ""
echo "📝 Configuration saved to terraform.tfvars (secrets passed via environment)"
echo ""

cd "$TERRAFORM_DIR"

echo "🔧 Initializing Terraform..."
terraform init

echo ""
echo "📋 Planning deployment..."
terraform plan

echo ""
read -p "Proceed with deployment? (yes/no): " PROCEED
if [[ "$PROCEED" != "yes" ]]; then
    echo "Deployment cancelled"
    exit 0
fi

echo ""
echo "🚀 Deploying to AWS EKS..."
START_TIME=$(date +%s)

terraform apply -auto-approve

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))

echo ""
echo "========================================="
echo "✅ Deployment Complete!"
echo "========================================="
echo "Time taken: ${MINUTES} minutes"
echo ""
echo "API Endpoint: $(terraform output -raw fixops_api_url)"
echo "Namespace: $(terraform output -raw namespace)"
echo ""
echo "Next steps:"
echo "  1. Update DNS records to point to the Load Balancer"
echo "  2. Configure kubectl: aws eks update-kubeconfig --name $CLUSTER_NAME --region $AWS_REGION"
echo "  3. Verify deployment: kubectl get pods -n fixops"
echo ""
