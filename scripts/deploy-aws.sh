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

read -sp "Emergent LLM Key: " EMERGENT_LLM_KEY
echo ""
if [[ -z "$EMERGENT_LLM_KEY" ]]; then
    echo "❌ Emergent LLM key is required"
    exit 1
fi

cat > "$TERRAFORM_DIR/terraform.tfvars" <<EOF
aws_region              = "$AWS_REGION"
environment             = "$ENVIRONMENT"
cluster_name            = "$CLUSTER_NAME"
domain_name             = "$DOMAIN_NAME"
emergent_llm_key        = "$EMERGENT_LLM_KEY"
backend_replicas        = 3
enable_monitoring       = true
enable_autoscaling      = true
enable_backup           = true
backup_retention_days   = 30
EOF

echo ""
echo "📝 Configuration saved to terraform.tfvars"
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
