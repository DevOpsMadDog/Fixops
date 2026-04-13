#!/usr/bin/env bash
# =============================================================================
# LocalStack init script — runs on first start inside the container
# Creates S3 buckets, IAM roles, and seeds Security Hub findings.
# =============================================================================
set -euo pipefail

ENDPOINT="http://localhost:4566"
REGION="us-east-1"
AWS="aws --endpoint-url=${ENDPOINT} --region=${REGION}"

echo "[init-localstack] Starting AWS resource seeding..."

# ── S3 Buckets ─────────────────────────────────────────────────────────────
echo "[init-localstack] Creating S3 buckets..."
${AWS} s3api create-bucket --bucket aldeci-scan-results 2>/dev/null || true
${AWS} s3api create-bucket --bucket aldeci-evidence-store 2>/dev/null || true
${AWS} s3api create-bucket --bucket aldeci-compliance-reports 2>/dev/null || true

# Enable versioning on scan-results
${AWS} s3api put-bucket-versioning \
  --bucket aldeci-scan-results \
  --versioning-configuration Status=Enabled 2>/dev/null || true

echo "[init-localstack] S3 buckets ready."

# ── IAM Roles ──────────────────────────────────────────────────────────────
echo "[init-localstack] Creating IAM roles..."

TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

${AWS} iam create-role \
  --role-name aldeci-scanner-role \
  --assume-role-policy-document "${TRUST_POLICY}" 2>/dev/null || true

${AWS} iam attach-role-policy \
  --role-name aldeci-scanner-role \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null || true

echo "[init-localstack] IAM roles ready."

# ── Security Hub ───────────────────────────────────────────────────────────
echo "[init-localstack] Enabling Security Hub..."
${AWS} securityhub enable-security-hub \
  --enable-default-standards 2>/dev/null || true

# Seed with 3 test findings
ACCOUNT_ID=$(${AWS} sts get-caller-identity --query Account --output text 2>/dev/null || echo "000000000000")
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

${AWS} securityhub batch-import-findings --findings "[
  {
    \"SchemaVersion\": \"2018-10-08\",
    \"Id\": \"aldeci-e2e-finding-001\",
    \"ProductArn\": \"arn:aws:securityhub:${REGION}:${ACCOUNT_ID}:product/${ACCOUNT_ID}/default\",
    \"GeneratorId\": \"aldeci-e2e-test\",
    \"AwsAccountId\": \"${ACCOUNT_ID}\",
    \"Types\": [\"Software and Configuration Checks/Vulnerabilities/CVE\"],
    \"CreatedAt\": \"${NOW}\",
    \"UpdatedAt\": \"${NOW}\",
    \"Severity\": {\"Label\": \"HIGH\", \"Normalized\": 70},
    \"Title\": \"CVE-2021-44228 Log4Shell detected in WebGoat\",
    \"Description\": \"OWASP WebGoat contains Log4j 2.x vulnerable to Log4Shell RCE.\",
    \"Resources\": [{\"Type\": \"AwsEc2Instance\", \"Id\": \"i-webgoat-test\"}],
    \"Compliance\": {\"Status\": \"FAILED\"},
    \"WorkflowState\": \"NEW\",
    \"RecordState\": \"ACTIVE\"
  },
  {
    \"SchemaVersion\": \"2018-10-08\",
    \"Id\": \"aldeci-e2e-finding-002\",
    \"ProductArn\": \"arn:aws:securityhub:${REGION}:${ACCOUNT_ID}:product/${ACCOUNT_ID}/default\",
    \"GeneratorId\": \"aldeci-e2e-test\",
    \"AwsAccountId\": \"${ACCOUNT_ID}\",
    \"Types\": [\"Software and Configuration Checks/Industry and Regulatory Standards/OWASP\"],
    \"CreatedAt\": \"${NOW}\",
    \"UpdatedAt\": \"${NOW}\",
    \"Severity\": {\"Label\": \"CRITICAL\", \"Normalized\": 90},
    \"Title\": \"SQL Injection in Juice Shop login endpoint\",
    \"Description\": \"OWASP Juice Shop allows unauthenticated SQL injection via login form.\",
    \"Resources\": [{\"Type\": \"AwsEc2Instance\", \"Id\": \"i-juiceshop-test\"}],
    \"Compliance\": {\"Status\": \"FAILED\"},
    \"WorkflowState\": \"NEW\",
    \"RecordState\": \"ACTIVE\"
  },
  {
    \"SchemaVersion\": \"2018-10-08\",
    \"Id\": \"aldeci-e2e-finding-003\",
    \"ProductArn\": \"arn:aws:securityhub:${REGION}:${ACCOUNT_ID}:product/${ACCOUNT_ID}/default\",
    \"GeneratorId\": \"aldeci-e2e-test\",
    \"AwsAccountId\": \"${ACCOUNT_ID}\",
    \"Types\": [\"Software and Configuration Checks/Vulnerabilities/CVE\"],
    \"CreatedAt\": \"${NOW}\",
    \"UpdatedAt\": \"${NOW}\",
    \"Severity\": {\"Label\": \"MEDIUM\", \"Normalized\": 50},
    \"Title\": \"Hardcoded credentials in DVWA config\",
    \"Description\": \"DVWA config.inc.php contains hardcoded database credentials.\",
    \"Resources\": [{\"Type\": \"AwsEc2Instance\", \"Id\": \"i-dvwa-test\"}],
    \"Compliance\": {\"Status\": \"FAILED\"},
    \"WorkflowState\": \"NEW\",
    \"RecordState\": \"ACTIVE\"
  }
]" 2>/dev/null || true

echo "[init-localstack] Security Hub seeded with 3 findings."

# ── CloudTrail ─────────────────────────────────────────────────────────────
echo "[init-localstack] Creating CloudTrail..."
${AWS} cloudtrail create-trail \
  --name aldeci-e2e-trail \
  --s3-bucket-name aldeci-scan-results \
  --is-multi-region-trail 2>/dev/null || true

${AWS} cloudtrail start-logging \
  --name aldeci-e2e-trail 2>/dev/null || true

echo "[init-localstack] CloudTrail ready."
echo "[init-localstack] AWS resource seeding complete."
