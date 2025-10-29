#!/bin/bash

# FixOps Complete Deployment via Backstage.io + Terraform
# Bank-grade automated deployment pipeline

set -e

echo "🏦 FixOps Bank Deployment via Backstage + Terraform"
echo "==================================================="

# Configuration
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-fixops-production}"
ENVIRONMENT="${ENVIRONMENT:-production}"
CLUSTER="${CLUSTER:-bank-prod-cluster}"
NAMESPACE="${NAMESPACE:-fixops}"

echo "📋 Deployment Configuration:"
echo "  Name: $DEPLOYMENT_NAME"
echo "  Environment: $ENVIRONMENT"
echo "  Cluster: $CLUSTER"
echo "  Namespace: $NAMESPACE"
echo ""

# Step 1: Validate Prerequisites
echo "🔍 Step 1: Validating Prerequisites..."

# Check required tools
for tool in kubectl terraform helm; do
    if ! command -v $tool &> /dev/null; then
        echo "❌ $tool not found. Please install $tool."
        exit 1
    fi
    echo "✅ $tool available"
done

# Check Kubernetes connectivity
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to Kubernetes cluster"
    exit 1
fi
echo "✅ Kubernetes cluster accessible"

# Check required environment variables
required_vars=("EMERGENT_LLM_KEY" "MONGODB_PASSWORD" "REDIS_PASSWORD")
for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Required environment variable $var not set"
        exit 1
    fi
    echo "✅ $var configured"
done

echo "✅ All prerequisites validated"
echo ""

# Step 2: Deploy Infrastructure via Terraform
echo "🏗️ Step 2: Deploying Infrastructure via Terraform..."

cd terraform/

# Initialize Terraform
echo "  Initializing Terraform backend..."
terraform init

# Plan deployment  
echo "  Planning infrastructure deployment..."
terraform plan \
    -var="environment=$ENVIRONMENT" \
    -var="namespace=$NAMESPACE" \
    -var="emergent_llm_key=$EMERGENT_LLM_KEY" \
    -var="mongodb_password=$MONGODB_PASSWORD" \
    -var="redis_password=$REDIS_PASSWORD" \
    -var="replicas=${REPLICAS:-3}" \
    -var="storage_size=${STORAGE_SIZE:-10Gi}" \
    -out=fixops.plan

# Apply infrastructure
echo "  Applying infrastructure changes..."
terraform apply -auto-approve fixops.plan

echo "✅ Infrastructure deployed successfully"
echo ""

# Step 3: Build and Deploy FixOps Containers
echo "🐳 Step 3: Building and Deploying FixOps Containers..."

cd ..

# Build containers
echo "  Building FixOps backend container..."
docker build -t core/decision-engine:latest .

echo "  Building FixOps frontend container..."
docker build -t core/frontend:latest ./frontend

# Push to registry (if configured)
if [ -n "$DOCKER_REGISTRY" ]; then
    echo "  Pushing to registry $DOCKER_REGISTRY..."
    docker tag core/decision-engine:latest $DOCKER_REGISTRY/core/decision-engine:latest
    docker tag core/frontend:latest $DOCKER_REGISTRY/core/frontend:latest
    docker push $DOCKER_REGISTRY/core/decision-engine:latest
    docker push $DOCKER_REGISTRY/core/frontend:latest
fi

echo "✅ Containers built and deployed"
echo ""

# Step 4: Verify Deployment
echo "🔍 Step 4: Verifying Deployment..."

echo "  Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l app=fixops-backend -n $NAMESPACE --timeout=300s
kubectl wait --for=condition=ready pod -l app=fixops-frontend -n $NAMESPACE --timeout=180s

echo "  Running health checks..."
API_URL=$(terraform -chdir=terraform output -raw fixops_api_url)
UI_URL=$(terraform -chdir=terraform output -raw fixops_ui_url)

# Health check
if curl -f "$API_URL/health" &> /dev/null; then
    echo "✅ FixOps API health check passed"
else
    echo "❌ FixOps API health check failed"
    exit 1
fi

# Readiness check
if curl -f "$API_URL/ready" &> /dev/null; then
    echo "✅ FixOps readiness check passed"
else
    echo "❌ FixOps readiness check failed"
    exit 1
fi

echo "✅ All health checks passed"
echo ""

# Step 5: Run Integration Tests
echo "🧪 Step 5: Running Integration Tests..."

# Test decision API
DECISION_RESPONSE=$(curl -s -X POST "$API_URL/api/v1/cicd/decision" \
    -H "Content-Type: application/json" \
    --data '{
        "service_name": "deployment-test",
        "environment": "production",
        "business_criticality": "medium"
    }')

DECISION=$(echo $DECISION_RESPONSE | jq -r '.decision')
CONFIDENCE=$(echo $DECISION_RESPONSE | jq -r '.confidence_score')

echo "  Test decision: $DECISION (confidence: $CONFIDENCE)"

if [ "$DECISION" != "null" ] && [ "$CONFIDENCE" != "null" ]; then
    echo "✅ Decision API integration test passed"
else
    echo "❌ Decision API integration test failed"
    exit 1
fi

echo "✅ Integration tests completed"
echo ""

# Step 6: Register with Backstage (if configured)
if [ -n "$BACKSTAGE_API_URL" ] && [ -n "$BACKSTAGE_TOKEN" ]; then
    echo "📋 Step 6: Registering with Backstage Software Catalog..."
    
    curl -X POST "$BACKSTAGE_API_URL/api/catalog/locations" \
        -H "Authorization: Bearer $BACKSTAGE_TOKEN" \
        -H "Content-Type: application/json" \
        --data '{
            "type": "url",
            "target": "https://git.bank.internal/platform/fixops-decision-engine/blob/main/backstage/catalog-info.yaml"
        }'
    
    echo "✅ Registered with Backstage catalog"
else
    echo "⚠️  Backstage registration skipped (BACKSTAGE_API_URL or BACKSTAGE_TOKEN not set)"
fi
echo ""

# Step 7: Display Access Information
echo "🌐 Step 7: Deployment Complete - Access Information"
echo "=================================================="

echo "🎯 FixOps Endpoints:"
echo "  API (CI/CD): $API_URL"
echo "  UI (Teams): $UI_URL"
echo "  Health: $API_URL/health"
echo "  Metrics: $API_URL/metrics"
echo ""

echo "🔧 Integration Commands:"
echo "  Test API: curl $API_URL/health"
echo "  View pods: kubectl get pods -n $NAMESPACE"
echo "  View logs: kubectl logs -f deployment/fixops-backend -n $NAMESPACE"
echo ""

echo "📊 Monitoring:"
echo "  Prometheus: $API_URL/metrics"
echo "  Grafana: https://grafana.bank.internal/d/fixops-dashboard"
echo ""

echo "🧪 Testing:"
echo "  Postman: Import collections from postman/ directory"
echo "  Newman: ./test-bank-api.sh"
echo ""

echo "🎉 FixOps successfully deployed and ready for bank CI/CD integration!"
echo ""

# Optional: Open browser to UI (if running locally)
if [[ "$OSTYPE" == "darwin"* ]] && [ "$ENVIRONMENT" = "development" ]; then
    echo "🌐 Opening FixOps UI..."
    open "$UI_URL"
fi

echo "📖 Next Steps:"
echo "  1. Add FixOps call to your CI/CD pipelines"
echo "  2. Upload security scan files via UI or API"  
echo "  3. Monitor decisions via Backstage service catalog"
echo "  4. Access Evidence Lake for compliance audits"
