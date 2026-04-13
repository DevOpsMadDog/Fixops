#!/usr/bin/env bash
# =============================================================================
# setup_localstack.sh — Install LocalStack and seed AWS resources for ALDECI E2E tests
#
# Usage:
#   bash scripts/setup_localstack.sh [--start] [--seed-only]
#
# Options:
#   --start       Start LocalStack via Docker if not already running
#   --seed-only   Skip install/start, just run the seeding commands
# =============================================================================
set -euo pipefail

ENDPOINT="${AWS_ENDPOINT_URL:-http://localhost:4566}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
BUCKET="${ALDECI_S3_BUCKET:-aldeci-scan-results}"

AWS_CMD="aws --endpoint-url=${ENDPOINT} --region=${REGION}"

START_LOCALSTACK=false
SEED_ONLY=false

for arg in "$@"; do
  case $arg in
    --start) START_LOCALSTACK=true ;;
    --seed-only) SEED_ONLY=true ;;
  esac
done

# ── Helper ─────────────────────────────────────────────────────────────────
log() { echo "[setup_localstack] $*"; }
ok()  { echo "[setup_localstack] OK: $*"; }
err() { echo "[setup_localstack] ERROR: $*" >&2; exit 1; }

# ── Prerequisites check ────────────────────────────────────────────────────
if ! $SEED_ONLY; then
  log "Checking prerequisites..."

  command -v docker >/dev/null 2>&1 || err "Docker not found. Install from https://docs.docker.com/get-docker/"
  command -v aws >/dev/null 2>&1 || {
    log "AWS CLI not found. Installing via pip..."
    pip install awscli-local 2>/dev/null || pip install awscli 2>/dev/null || err "Could not install AWS CLI"
  }

  ok "Prerequisites satisfied."
fi

# ── Start LocalStack ───────────────────────────────────────────────────────
if $START_LOCALSTACK; then
  log "Starting LocalStack via Docker..."

  if docker ps --format '{{.Names}}' | grep -q "localstack"; then
    log "LocalStack already running."
  else
    docker run -d \
      --name localstack-e2e \
      -p 4566:4566 \
      -e SERVICES=s3,iam,lambda,securityhub,cloudtrail,events,logs,sts \
      -e DEBUG=0 \
      -e PERSISTENCE=1 \
      -v /var/run/docker.sock:/var/run/docker.sock \
      localstack/localstack:3.4

    log "Waiting for LocalStack to be healthy..."
    for i in $(seq 1 30); do
      if curl -sf "${ENDPOINT}/_localstack/health" >/dev/null 2>&1; then
        ok "LocalStack is healthy."
        break
      fi
      sleep 2
      if [ "$i" -eq 30 ]; then
        err "LocalStack did not become healthy in 60s."
      fi
    done
  fi
fi

# ── Wait for endpoint ──────────────────────────────────────────────────────
log "Verifying LocalStack endpoint at ${ENDPOINT}..."
for i in $(seq 1 20); do
  if curl -sf "${ENDPOINT}/_localstack/health" >/dev/null 2>&1; then
    ok "Endpoint reachable."
    break
  fi
  sleep 3
  if [ "$i" -eq 20 ]; then
    err "LocalStack endpoint ${ENDPOINT} not reachable. Start it with --start flag."
  fi
done

# ── S3 Buckets ─────────────────────────────────────────────────────────────
log "Creating S3 buckets..."

for bucket in aldeci-scan-results aldeci-evidence-store aldeci-compliance-reports; do
  ${AWS_CMD} s3api create-bucket --bucket "${bucket}" 2>/dev/null && log "  Created: ${bucket}" || log "  Already exists: ${bucket}"
done

${AWS_CMD} s3api put-bucket-versioning \
  --bucket aldeci-scan-results \
  --versioning-configuration Status=Enabled 2>/dev/null || true

ok "S3 buckets ready."

# ── Upload a test object ────────────────────────────────────────────────────
log "Uploading test manifest to S3..."
echo '{"type":"aldeci-e2e","version":"1.0","timestamp":"'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"}' \
  | ${AWS_CMD} s3 cp - "s3://${BUCKET}/e2e-manifest.json" 2>/dev/null || true
ok "Test manifest uploaded."

# ── IAM Roles ──────────────────────────────────────────────────────────────
log "Creating IAM roles..."

TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

${AWS_CMD} iam create-role \
  --role-name aldeci-scanner-role \
  --assume-role-policy-document "${TRUST_POLICY}" 2>/dev/null || log "  Role aldeci-scanner-role already exists."

${AWS_CMD} iam attach-role-policy \
  --role-name aldeci-scanner-role \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null || true

ok "IAM roles ready."

# ── Security Hub ───────────────────────────────────────────────────────────
log "Enabling Security Hub..."
${AWS_CMD} securityhub enable-security-hub \
  --enable-default-standards 2>/dev/null || log "  Security Hub already enabled."

ACCOUNT_ID=$(${AWS_CMD} sts get-caller-identity --query Account --output text 2>/dev/null || echo "000000000000")
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log "Importing seed Security Hub findings..."
${AWS_CMD} securityhub batch-import-findings --findings "[
  {
    \"SchemaVersion\": \"2018-10-08\",
    \"Id\": \"aldeci-seed-finding-sqli-001\",
    \"ProductArn\": \"arn:aws:securityhub:${REGION}:${ACCOUNT_ID}:product/${ACCOUNT_ID}/default\",
    \"GeneratorId\": \"aldeci-setup-script\",
    \"AwsAccountId\": \"${ACCOUNT_ID}\",
    \"Types\": [\"Software and Configuration Checks/Vulnerabilities/CVE\"],
    \"CreatedAt\": \"${NOW}\",
    \"UpdatedAt\": \"${NOW}\",
    \"Severity\": {\"Label\": \"CRITICAL\", \"Normalized\": 90},
    \"Title\": \"SQL Injection - Seed finding for E2E test\",
    \"Description\": \"Seed finding to verify Security Hub integration works end-to-end.\",
    \"Resources\": [{\"Type\": \"Other\", \"Id\": \"aldeci-e2e-test-resource\"}],
    \"Compliance\": {\"Status\": \"FAILED\"},
    \"WorkflowState\": \"NEW\",
    \"RecordState\": \"ACTIVE\"
  }
]" 2>/dev/null || true

ok "Security Hub seeded."

# ── CloudTrail ─────────────────────────────────────────────────────────────
log "Setting up CloudTrail..."
${AWS_CMD} cloudtrail create-trail \
  --name aldeci-e2e-trail \
  --s3-bucket-name aldeci-scan-results \
  --is-multi-region-trail 2>/dev/null || log "  Trail already exists."

${AWS_CMD} cloudtrail start-logging \
  --name aldeci-e2e-trail 2>/dev/null || true

ok "CloudTrail ready."

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "======================================================================"
echo "  LocalStack E2E Setup Complete"
echo "======================================================================"
echo "  Endpoint:     ${ENDPOINT}"
echo "  Region:       ${REGION}"
echo "  S3 Buckets:   aldeci-scan-results, aldeci-evidence-store, aldeci-compliance-reports"
echo "  IAM Role:     aldeci-scanner-role"
echo "  Security Hub: enabled (1 seed finding)"
echo "  CloudTrail:   aldeci-e2e-trail → s3://aldeci-scan-results"
echo ""
echo "  Run E2E tests:"
echo "    python -m pytest tests/test_e2e_real.py -x --tb=short --timeout=30 -q"
echo "======================================================================"
