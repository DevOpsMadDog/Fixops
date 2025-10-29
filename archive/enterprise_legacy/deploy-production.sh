#!/bin/bash

# FixOps Production Deployment Script
# Deploy to real domain: fixops.devops.ai

set -e

echo "🚀 FixOps Production Deployment"
echo "==============================="
echo "🌐 Domain: fixops.devops.ai" 
echo "📱 API: api.fixops.devops.ai"
echo "🛒 Marketplace: marketplace.fixops.devops.ai"
echo ""

# Configuration
DOMAIN="devops.ai"
SUBDOMAIN="fixops"
API_SUBDOMAIN="api.fixops"
MARKETPLACE_SUBDOMAIN="marketplace.fixops"
NAMESPACE="fixops"

echo "📋 Deployment Configuration:"
echo "  Main UI: https://$SUBDOMAIN.$DOMAIN"
echo "  API Endpoint: https://$API_SUBDOMAIN.$DOMAIN" 
echo "  Marketplace: https://$MARKETPLACE_SUBDOMAIN.$DOMAIN"
echo "  Kubernetes Namespace: $NAMESPACE"
echo ""

# Step 1: Validate Prerequisites
echo "🔍 Step 1: Validating Prerequisites..."

# Check required tools
for tool in kubectl docker helm; do
    if ! command -v $tool &> /dev/null; then
        echo "❌ $tool not found. Please install $tool."
        exit 1
    fi
    echo "✅ $tool available"
done

# Check domain ownership
echo "🌐 Validating domain ownership..."
if dig +short $DOMAIN | grep -q .; then
    echo "✅ Domain $DOMAIN resolves"
else
    echo "⚠️  Domain $DOMAIN may not be configured yet"
fi

echo "✅ Prerequisites validated"
echo ""

# Step 2: Build Production Images
echo "🐳 Step 2: Building Production Images..."

# Build backend
echo "  Building FixOps backend..."
docker build -t core/decision-engine:production .

# Build frontend  
echo "  Building FixOps frontend..."
docker build -t core/frontend:production ./frontend

echo "✅ Production images built"
echo ""

# Step 3: Create Production Secrets
echo "🔐 Step 3: Configuring Production Secrets..."

# Create namespace if not exists
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Create secrets (prompt for values if not set)
if [ -z "$EMERGENT_LLM_KEY" ]; then
    echo "⚠️  EMERGENT_LLM_KEY not set in environment"
    read -s -p "Enter Emergent LLM API Key: " EMERGENT_LLM_KEY
    echo ""
fi

if [ -z "$MONGODB_PASSWORD" ]; then
    MONGODB_PASSWORD=$(openssl rand -base64 32)
    echo "🔑 Generated MongoDB password"
fi

if [ -z "$REDIS_PASSWORD" ]; then
    REDIS_PASSWORD=$(openssl rand -base64 32)  
    echo "🔑 Generated Redis password"
fi

# Create secret
kubectl create secret generic fixops-secrets \
    --from-literal=EMERGENT_LLM_KEY="$EMERGENT_LLM_KEY" \
    --from-literal=MONGO_URL="mongodb://fixops:$MONGODB_PASSWORD@mongodb:27017/fixops_production?authSource=admin" \
    --from-literal=REDIS_URL="redis://:$REDIS_PASSWORD@redis:6379/0" \
    --from-literal=SECRET_KEY="fixops-production-$(openssl rand -hex 16)" \
    --namespace $NAMESPACE \
    --dry-run=client -o yaml | kubectl apply -f -

echo "✅ Secrets configured"
echo ""

# Step 4: Deploy to Kubernetes
echo "🚀 Step 4: Deploying to Kubernetes..."

# Update image tags in deployments
sed -i.bak "s|core/decision-engine:latest|core/decision-engine:production|g" kubernetes/backend-deployment.yaml
sed -i.bak "s|core/frontend:latest|core/frontend:production|g" kubernetes/frontend-deployment.yaml

# Apply all manifests
kubectl apply -f kubernetes/

echo "✅ FixOps deployed to Kubernetes"
echo ""

# Step 5: Wait for Deployment
echo "⏳ Step 5: Waiting for Deployment to be Ready..."

echo "  Waiting for backend pods..."
kubectl wait --for=condition=ready pod -l app=fixops-backend -n $NAMESPACE --timeout=300s

echo "  Waiting for frontend pods..."
kubectl wait --for=condition=ready pod -l app=fixops-frontend -n $NAMESPACE --timeout=180s

echo "✅ All pods are ready"
echo ""

# Step 6: Configure DNS (Instructions)
echo "🌐 Step 6: DNS Configuration Required"
echo "======================================"
echo ""
echo "To complete deployment, configure these DNS records in your devops.ai domain:"
echo ""
echo "A Records (point to your Kubernetes ingress IP):"
INGRESS_IP=$(kubectl get service -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "YOUR_INGRESS_IP")
echo "  $SUBDOMAIN.$DOMAIN           → $INGRESS_IP"
echo "  $API_SUBDOMAIN.$DOMAIN       → $INGRESS_IP"  
echo "  $MARKETPLACE_SUBDOMAIN.$DOMAIN → $INGRESS_IP"
echo ""
echo "Or CNAME Records (if using cloud load balancer):"
INGRESS_HOSTNAME=$(kubectl get service -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "your-lb-hostname.cloud.com")
echo "  $SUBDOMAIN.$DOMAIN           → $INGRESS_HOSTNAME"
echo "  $API_SUBDOMAIN.$DOMAIN       → $INGRESS_HOSTNAME"
echo "  $MARKETPLACE_SUBDOMAIN.$DOMAIN → $INGRESS_HOSTNAME"
echo ""

# Step 7: Validate Deployment
echo "🧪 Step 7: Validating Deployment..."

echo "  Testing internal health..."
BACKEND_POD=$(kubectl get pods -l app=fixops-backend -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}')
kubectl exec $BACKEND_POD -n $NAMESPACE -- curl -f http://localhost:8001/health

echo "  Testing decision API..."
kubectl exec $BACKEND_POD -n $NAMESPACE -- curl -s -X POST http://localhost:8001/api/v1/cicd/decision \
    -H "Content-Type: application/json" \
    --data '{"service_name":"deployment-test","environment":"production"}' | head -1

echo "✅ Internal validation passed"
echo ""

# Step 8: Display Access Information  
echo "🎯 Step 8: FixOps Production Deployment Complete!"
echo "================================================="
echo ""
echo "🌐 FixOps Endpoints (after DNS configuration):"
echo "  Main UI:     https://$SUBDOMAIN.$DOMAIN"
echo "  API:         https://$API_SUBDOMAIN.$DOMAIN"
echo "  Marketplace: https://$MARKETPLACE_SUBDOMAIN.$DOMAIN"
echo "  Health:      https://$API_SUBDOMAIN.$DOMAIN/health"
echo "  Metrics:     https://$API_SUBDOMAIN.$DOMAIN/metrics"
echo ""
echo "🔧 CI/CD Integration:"
echo "  Decision API: https://$API_SUBDOMAIN.$DOMAIN/api/v1/cicd/decision"
echo "  Upload API:   https://$API_SUBDOMAIN.$DOMAIN/api/v1/scans/upload"
echo ""
echo "🧪 Test Commands (after DNS):"
echo "  curl https://$API_SUBDOMAIN.$DOMAIN/health"
echo "  curl -X POST https://$API_SUBDOMAIN.$DOMAIN/api/v1/cicd/decision \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    --data '{\"service_name\":\"test\",\"environment\":\"production\"}'"
echo ""
echo "📊 Kubernetes Management:"
echo "  View pods:    kubectl get pods -n $NAMESPACE"
echo "  View logs:    kubectl logs -f deployment/fixops-backend -n $NAMESPACE"
echo "  Scale:        kubectl scale deployment fixops-backend --replicas=5 -n $NAMESPACE"
echo ""
echo "🎉 FixOps is ready for production at fixops.devops.ai!"
echo "   Configure DNS records above to complete deployment."
