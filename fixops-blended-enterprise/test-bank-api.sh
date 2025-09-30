#!/bin/bash

# FixOps API Testing Suite for Bank Validation
# Automated testing using Newman (Postman CLI)

set -e

echo "🏦 FixOps Bank API Validation Suite"
echo "===================================="

# Configuration
FIXOPS_API_URL="${FIXOPS_API_URL:-http://localhost:8001}"
ENVIRONMENT="${ENVIRONMENT:-development}"
RESULTS_DIR="./test-results/$(date +%Y%m%d_%H%M%S)"

# Create results directory
mkdir -p "$RESULTS_DIR"

echo "📋 Configuration:"
echo "  API URL: $FIXOPS_API_URL"
echo "  Environment: $ENVIRONMENT"
echo "  Results: $RESULTS_DIR"
echo ""

# Check if Newman is installed
if ! command -v newman &> /dev/null; then
    echo "❌ Newman not found. Installing..."
    npm install -g newman newman-reporter-html
fi

# Function to run collection with reporting
run_collection() {
    local collection_name="$1"
    local collection_file="$2"
    local environment_file="$3"
    
    echo "🧪 Running $collection_name..."
    
    newman run "$collection_file" \
        --environment "$environment_file" \
        --env-var "BASE_URL=$FIXOPS_API_URL" \
        --reporters cli,json,html \
        --reporter-json-export "$RESULTS_DIR/$collection_name-results.json" \
        --reporter-html-export "$RESULTS_DIR/$collection_name-report.html" \
        --timeout-request 30000 \
        --timeout-script 30000 \
        --bail \
        || echo "⚠️  Some tests failed in $collection_name"
    
    echo "✅ $collection_name completed"
    echo ""
}

# 1. Health & Basic API Tests
echo "🩺 Phase 1: Health & Readiness Validation"
run_collection "health-tests" \
    "postman/FixOps-Bank-API-Collection.json" \
    "postman/FixOps-Bank-Development.postman_environment.json"

# 2. CI/CD Integration Tests
echo "⚙️ Phase 2: CI/CD Pipeline Integration"
run_collection "cicd-integration" \
    "postman/FixOps-CICD-Tests.postman_collection.json" \
    "postman/FixOps-Bank-Development.postman_environment.json"

# 3. Performance & Load Tests
echo "🚀 Phase 3: Performance & SLA Validation"
run_collection "performance-tests" \
    "postman/FixOps-Performance-Tests.postman_collection.json" \
    "postman/FixOps-Bank-Development.postman_environment.json"

echo "🏦 FixOps Bank API validation completed!"
echo "📁 Results: $RESULTS_DIR"