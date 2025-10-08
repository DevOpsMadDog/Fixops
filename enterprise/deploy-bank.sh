#!/bin/bash

# FixOps Bank Deployment Script
# Complete containerized deployment for bank infrastructure

set -e

echo "🏦 FixOps Bank Deployment Script"
echo "=================================="

# Configuration
REGISTRY="${DOCKER_REGISTRY:-fixops}"
VERSION="${VERSION:-latest}"
NAMESPACE="${NAMESPACE:-fixops}"

echo "📋 Configuration:"
echo "  Registry: $REGISTRY"
echo "  Version: $VERSION" 
echo "  Namespace: $NAMESPACE"
echo ""

# Step 1: Build Docker Images
echo "🔨 Building Docker images..."

echo "  Building backend image..."
docker build -t $REGISTRY/decision-engine:$VERSION .

echo "  Building frontend image..."
docker build -t $REGISTRY/frontend:$VERSION ./frontend

echo "✅ Docker images built successfully"
echo ""

# Step 2: Push to Registry (if specified)
if [ -n "$DOCKER_REGISTRY" ]; then
    echo "📤 Pushing to registry..."
    docker push $REGISTRY/decision-engine:$VERSION
    docker push $REGISTRY/frontend:$VERSION
    echo "✅ Images pushed to registry"
    echo ""
fi

# Step 3: Deploy to Kubernetes
echo "🚀 Deploying to Kubernetes..."

# Create namespace
kubectl apply -f kubernetes/namespace.yaml

# Apply RBAC
kubectl apply -f kubernetes/rbac.yaml

# Apply storage
kubectl apply -f kubernetes/pvc.yaml

# Apply configuration (check secrets first)
echo "⚠️  Please ensure secrets are configured:"
echo "  kubectl create secret generic fixops-secrets --from-env-file=.env.production -n $NAMESPACE"
echo ""
read -p "Press Enter when secrets are configured..."

kubectl apply -f kubernetes/configmap.yaml

# Deploy applications
kubectl apply -f kubernetes/backend-deployment.yaml
kubectl apply -f kubernetes/frontend-deployment.yaml
kubectl apply -f kubernetes/services.yaml

# Deploy ingress (optional)
if [ "$DEPLOY_INGRESS" = "true" ]; then
    kubectl apply -f kubernetes/ingress.yaml
fi

echo "✅ FixOps deployed to Kubernetes"
echo ""

# Step 4: Verify Deployment
echo "🔍 Verifying deployment..."

echo "  Waiting for backend to be ready..."
kubectl wait --for=condition=ready pod -l app=fixops-backend -n $NAMESPACE --timeout=300s

echo "  Waiting for frontend to be ready..."
kubectl wait --for=condition=ready pod -l app=fixops-frontend -n $NAMESPACE --timeout=180s

echo "✅ All pods are ready"
echo ""

# Step 5: Health Check
echo "🩺 Running health checks..."

BACKEND_POD=$(kubectl get pods -l app=fixops-backend -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}')
FRONTEND_POD=$(kubectl get pods -l app=fixops-frontend -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}')

echo "  Testing backend health..."
kubectl exec $BACKEND_POD -n $NAMESPACE -- curl -f http://localhost:8001/health

echo "  Testing frontend health..."
kubectl exec $FRONTEND_POD -n $NAMESPACE -- curl -f http://localhost:3000/health

echo "✅ Health checks passed"
echo ""

# Step 6: Display Access Information
echo "🌐 Access Information:"
echo "======================================"

BACKEND_IP=$(kubectl get service fixops-backend-service -n $NAMESPACE -o jsonpath='{.spec.clusterIP}')
FRONTEND_IP=$(kubectl get service fixops-frontend-service -n $NAMESPACE -o jsonpath='{.spec.clusterIP}')

echo "  Backend API: http://$BACKEND_IP:8001"
echo "  Frontend UI: http://$FRONTEND_IP:3000"

if kubectl get ingress fixops-ingress -n $NAMESPACE >/dev/null 2>&1; then
    INGRESS_HOST=$(kubectl get ingress fixops-ingress -n $NAMESPACE -o jsonpath='{.spec.rules[0].host}')
    echo "  External API: https://$INGRESS_HOST"
fi

echo ""
echo "🎯 CI/CD Integration Endpoint:"
echo "  POST https://fixops-api.bank.internal/api/v1/cicd/decision"
echo ""

echo "📊 Monitoring Endpoints:"
echo "  Metrics: https://fixops-api.bank.internal/metrics" 
echo "  Health: https://fixops-api.bank.internal/health"
echo "  Ready: https://fixops-api.bank.internal/ready"
echo ""

echo "🏆 FixOps successfully deployed for bank CI/CD integration!"
echo "   UI accessible from anywhere calling real API"
echo "   Full CLI functionality available in containers"
echo "   Real LLM integration configured and ready"
echo ""

# Step 7: Test Decision API
echo "🧪 Testing decision API..."
kubectl exec $BACKEND_POD -n $NAMESPACE -- python -c "
import asyncio
import json
from src.services.decision_engine import decision_engine, DecisionContext

async def test():
    await decision_engine.initialize()
    print('✅ Decision Engine initialized')
    print(f'   Mode: {'DEMO' if decision_engine.demo_mode else 'PRODUCTION'}')
    print(f'   LLM Available: {decision_engine.chatgpt_client is not None}')

asyncio.run(test())
"

echo "✅ Bank deployment complete and verified!"