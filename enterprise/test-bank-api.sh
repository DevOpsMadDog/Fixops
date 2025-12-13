#!/bin/bash
# FixOps Bank API Validation Script
# This script runs the multi-phase bank validation flow using Newman (Postman CLI)
#
# Prerequisites:
#   - Newman installed: npm install -g newman
#   - FixOps API server running on localhost:8000
#   - API token configured in environment or collections
#
# Usage:
#   ./test-bank-api.sh [--env production|staging|local]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTMAN_DIR="${SCRIPT_DIR}/postman"
ENV="${1:-local}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           FixOps Bank API Validation Suite                   ║${NC}"
echo -e "${BLUE}║                  Multi-Phase Testing                         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Verify Newman is installed
if ! command -v newman &> /dev/null; then
    echo -e "${RED}Error: Newman is not installed. Install with: npm install -g newman${NC}"
    exit 1
fi

# Verify collection files exist
COLLECTIONS=(
    "FixOps-Bank-API-Collection.json"
    "FixOps-CICD-Tests.postman_collection.json"
    "FixOps-Performance-Tests.postman_collection.json"
)

for collection in "${COLLECTIONS[@]}"; do
    if [[ ! -f "${POSTMAN_DIR}/${collection}" ]]; then
        echo -e "${RED}Error: Missing collection file: ${collection}${NC}"
        exit 1
    fi
done

echo -e "${GREEN}All collection files verified.${NC}"
echo ""

# ============================================================================
# Phase 1: Health & Readiness Validation
# ============================================================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Phase 1: Health & Readiness Validation                       ${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Running health checks and monitoring endpoint validation..."
echo ""

newman run "${POSTMAN_DIR}/FixOps-Bank-API-Collection.json" \
    --folder "Health & Monitoring" \
    --reporters cli,json \
    --reporter-json-export "reports/phase1-health-results.json" \
    || { echo -e "${RED}Phase 1 failed!${NC}"; exit 1; }

echo ""
echo -e "${GREEN}Phase 1 completed successfully.${NC}"
echo ""

# ============================================================================
# Phase 2: CI/CD Pipeline Integration
# ============================================================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Phase 2: CI/CD Pipeline Integration                          ${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Running CI/CD decision tests (ALLOW, BLOCK, DEFER scenarios)..."
echo ""

newman run "${POSTMAN_DIR}/FixOps-CICD-Tests.postman_collection.json" \
    --reporters cli,json \
    --reporter-json-export "reports/phase2-cicd-results.json" \
    || { echo -e "${RED}Phase 2 failed!${NC}"; exit 1; }

echo ""
echo -e "${GREEN}Phase 2 completed successfully.${NC}"
echo ""

# ============================================================================
# Phase 3: Performance & SLA Validation
# ============================================================================
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Phase 3: Performance & SLA Validation                        ${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Running performance tests and SLA validation..."
echo ""

newman run "${POSTMAN_DIR}/FixOps-Performance-Tests.postman_collection.json" \
    --iteration-count 10 \
    --reporters cli,json \
    --reporter-json-export "reports/phase3-performance-results.json" \
    || { echo -e "${RED}Phase 3 failed!${NC}"; exit 1; }

echo ""
echo -e "${GREEN}Phase 3 completed successfully.${NC}"
echo ""

# ============================================================================
# Summary
# ============================================================================
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Validation Complete                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}All phases completed successfully!${NC}"
echo ""
echo "Reports generated:"
echo "  - reports/phase1-health-results.json"
echo "  - reports/phase2-cicd-results.json"
echo "  - reports/phase3-performance-results.json"
echo ""
