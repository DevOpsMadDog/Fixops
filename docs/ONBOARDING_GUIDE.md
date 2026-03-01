# ALdeci Customer Onboarding Guide

> **Version**: 1.0 — Sprint 2 (Enterprise Demo)
> **Updated**: 2026-03-01
> **Author**: Sales Engineer Agent
> **Audience**: New ALdeci customers and their technical teams
> **Duration**: 2-4 hours from install to first actionable report

---

## Table of Contents

1. [Pre-Requisites Checklist](#1-pre-requisites-checklist)
2. [Installation — Docker (Recommended)](#2-installation--docker)
3. [Installation — Local Development](#3-installation--local-development)
4. [First Login & Configuration](#4-first-login--configuration)
5. [Connect Your Scanners](#5-connect-your-scanners)
6. [First Scan — Native Engines](#6-first-scan--native-engines)
7. [Brain Pipeline — Your First Decision](#7-brain-pipeline--your-first-decision)
8. [MPTE Verification — Prove Exploitability](#8-mpte-verification--prove-exploitability)
9. [AutoFix — Generate Your First Code Fix](#9-autofix--generate-your-first-code-fix)
10. [Compliance — Your First Evidence Bundle](#10-compliance--your-first-evidence-bundle)
11. [Success Metrics](#11-success-metrics)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Pre-Requisites Checklist

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Linux, macOS, Windows (Docker) | Linux (Ubuntu 22.04+) |
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4 GB | 8 GB (16 GB for self-hosted AI) |
| **Disk** | 10 GB | 20 GB |
| **Docker** | 20.10+ | 24.0+ |
| **Python** | 3.10+ (local only) | 3.11+ |
| **Network** | Optional (air-gapped supported) | Internet for threat feeds |

### Software Dependencies

- [ ] Docker and Docker Compose installed
- [ ] `curl` and `jq` available for API testing
- [ ] API token from your existing scanner (Snyk, Semgrep, etc.) — optional
- [ ] Network access to staging environment (for MPTE verification) — optional
- [ ] Compliance framework requirements documented (SOC2, PCI, etc.) — optional

### Pre-Configuration Decisions

- [ ] **Deployment mode**: Docker / Kubernetes / Local
- [ ] **AI backend**: Cloud LLMs (OpenAI/Anthropic) or Self-hosted (Llama 3.1)
- [ ] **Scanner integration**: Which existing scanners to connect
- [ ] **Compliance frameworks**: Which standards to map against
- [ ] **Air-gapped**: Does this environment have internet access?

---

## 2. Installation — Docker (Recommended)

### Step 1: Pull and Start

```bash
# Clone the repository (or use pre-built image)
git clone https://github.com/aldeci/fixops.git
cd fixops

# Start with Docker Compose
docker compose -f docker/docker-compose.yml up -d

# Wait for services to start (about 30 seconds)
sleep 10

# Verify health
curl -s http://localhost:8000/health | jq .
# Expected: {"status":"healthy","service":"aldeci-api"}
```

### Step 2: Get Your API Key

```bash
# The API key is printed to Docker logs on first start
docker logs aldeci-api 2>&1 | grep "API_TOKEN"

# Or set your own
export FIXOPS_API_TOKEN="your-secure-api-key"
```

### Step 3: Verify All Services

```bash
BASE="http://localhost:8000/api/v1"
API_KEY="your-api-key"

for svc in brain/stats autofix/health mpte/stats sast/status dast/status \
           secrets/status container/status cspm/status compliance-engine/status \
           knowledge-graph/status mcp/tools evidence/ feeds/health; do
  HTTP=$(curl -sf -o /dev/null -w "%{http_code}" -H "X-API-Key: $API_KEY" "$BASE/$svc")
  echo "$svc → HTTP $HTTP"
done
```

All services should return HTTP 200.

---

## 3. Installation — Local Development

```bash
# Prerequisites: Python 3.10+
cd fixops

# Install dependencies
pip install -r requirements.txt

# Set environment
export FIXOPS_MODE=enterprise
export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export FIXOPS_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

# Optional: LLM API keys (for AutoFix and AI Agent)
export OPENAI_API_KEY="sk-..."       # Optional
export ANTHROPIC_API_KEY="sk-ant-..."  # Optional

# Start the API server
python -m uvicorn apps.api.app:create_app --factory --port 8000

# In another terminal, seed demo data (optional)
python scripts/enterprise/seed_demo_data.py
```

---

## 4. First Login & Configuration

### API Authentication

All API calls require the `X-API-Key` header:

```bash
# Test authentication
curl -s -H "X-API-Key: $API_KEY" \
  http://localhost:8000/api/v1/system/health | jq .
```

### UI Access

Open your browser to: `http://localhost:3001`

The dashboard shows:
- **Posture Score**: Your overall security health (0-100)
- **Active Findings**: Current open vulnerabilities
- **Compliance Status**: Framework coverage at a glance
- **Recent Activity**: Latest scans, decisions, and fixes

---

## 5. Connect Your Scanners

ALdeci works with your existing scanners — no rip-and-replace required.

### Option A: Upload a Report (Fastest)

```bash
# Auto-detect scanner format and ingest
curl -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $API_KEY" \
  -F "file=@your-scan-report.json" \
  -F "scanner_type=auto"
```

Supported formats: Snyk JSON, Semgrep SARIF, ZAP JSON/XML, Burp XML, Nessus XML, Trivy JSON, Grype JSON, SARIF (any tool), CycloneDX SBOM, SPDX SBOM.

### Option B: Configure Connector (Continuous)

```bash
# Example: Connect to Snyk
curl -X POST http://localhost:8000/api/v1/connectors \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Snyk",
    "type": "snyk",
    "config": {
      "api_token": "your-snyk-token",
      "org_id": "your-snyk-org"
    }
  }'

# Test the connection
curl http://localhost:8000/api/v1/connectors \
  -H "X-API-Key: $API_KEY" | jq '.[] | {name, type, status}'
```

### Option C: CI/CD Webhook

```bash
# Configure your CI/CD to POST results to ALdeci
# Webhook URL: http://your-aldeci-host:8000/api/v1/scanner-ingest/webhook/snyk
# Method: POST
# Body: Raw scanner output JSON
```

---

## 6. First Scan — Native Engines

Even without external scanners, ALdeci can scan your code directly.

### SAST (Static Analysis)

```bash
# Scan a code snippet
curl -X POST http://localhost:8000/api/v1/sast/scan/code \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "your source code here",
    "language": "python",
    "filename": "app.py"
  }'
```

### Secrets Detection

```bash
# Scan for leaked credentials
curl -X POST http://localhost:8000/api/v1/secrets/scan \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "your code or config here",
    "filename": ".env"
  }'
```

### All 8 Native Scanners

| Scanner | Endpoint | What It Finds |
|---------|----------|---------------|
| **SAST** | `POST /api/v1/sast/scan/code` | SQL injection, XSS, command injection, path traversal |
| **DAST** | `POST /api/v1/dast/scan` | Web application vulnerabilities (live testing) |
| **Secrets** | `POST /api/v1/secrets/scan` | API keys, passwords, tokens, credentials |
| **Container** | `POST /api/v1/container/scan` | Dockerfile issues, image vulnerabilities |
| **CSPM/IaC** | `POST /api/v1/cspm/scan` | Terraform/CloudFormation misconfigurations |
| **API Fuzzer** | `POST /api/v1/api-fuzzer/fuzz` | API endpoint vulnerabilities |
| **Malware** | `POST /api/v1/malware/scan` | Malicious code patterns |
| **LLM Monitor** | `POST /api/v1/llm-monitor/analyze` | Prompt injection, jailbreak attempts |

---

## 7. Brain Pipeline — Your First Decision

Once findings are ingested, the Brain Pipeline processes them through 12 steps:

```bash
# Ingest a finding into the Brain Pipeline
curl -X POST http://localhost:8000/api/v1/brain/ingest/finding \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "my-first-finding",
    "title": "SQL Injection in login page",
    "severity": "CRITICAL",
    "cwe": "CWE-89",
    "source": "native-sast",
    "app_id": "my-app"
  }'

# Check the knowledge graph
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8000/api/v1/knowledge-graph/analytics | jq .

# Get the FAIL priority score
curl -X POST http://localhost:8000/api/v1/fail/score \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "my-first-finding",
    "cvss": 9.8,
    "epss": 0.87,
    "asset_criticality": "high",
    "reachable": true
  }'
```

---

## 8. MPTE Verification — Prove Exploitability

Don't just detect — prove:

```bash
# Verify a finding is actually exploitable
curl -X POST http://localhost:8000/api/v1/mpte/verify \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "my-first-finding",
    "vulnerability_type": "sql_injection",
    "target": "http://your-staging-app:8080/login",
    "context": {
      "cwe": "CWE-89",
      "parameter": "username"
    }
  }'
```

**Verdicts**:
- `VULNERABLE_VERIFIED` — Confirmed exploitable with evidence
- `NOT_VULNERABLE_VERIFIED` — Confirmed NOT exploitable (false positive)
- `NOT_APPLICABLE` — Cannot be tested with current context
- `UNVERIFIED` — Inconclusive, needs manual review

---

## 9. AutoFix — Generate Your First Code Fix

```bash
# Generate an AI-powered fix
curl -X POST http://localhost:8000/api/v1/autofix/generate \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "my-first-finding",
    "vulnerability_type": "sql_injection",
    "source_code": "your vulnerable code here",
    "language": "python",
    "fix_type": "CODE_PATCH"
  }'
```

**Confidence Levels**:
- **HIGH (>85%)**: Safe to auto-apply — creates PR automatically
- **MEDIUM (60-85%)**: Creates PR for human review
- **LOW (<60%)**: Suggestion only — human decision required

---

## 10. Compliance — Your First Evidence Bundle

```bash
# List supported frameworks
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8000/api/v1/compliance-engine/frameworks | jq .

# Assess compliance posture
curl -X POST http://localhost:8000/api/v1/compliance-engine/assess \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"framework": "SOC2"}'

# Generate signed audit bundle
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8000/api/v1/compliance-engine/audit-bundle | jq .
```

---

## 11. Success Metrics

After onboarding, track these metrics to measure ALdeci's impact:

| Metric | Before ALdeci | Target with ALdeci | How to Measure |
|--------|---------------|-------------------|----------------|
| Finding noise | 100% raw | 97% reduced | `GET /api/v1/analytics/dashboard/overview` → noise_reduction |
| False positive rate | ~68% | <5% | MPTE verifications with NOT_VULNERABLE verdict |
| MTTR | 14 days | <3 days | `GET /api/v1/analytics/dashboard/overview` → mttr_days |
| Audit prep time | 3 weeks | <2 hours | Time to generate compliance bundle |
| Fix confidence | Manual guess | AI-scored (0-100%) | `GET /api/v1/autofix/stats` → avg_confidence |

---

## 12. Troubleshooting

### API returns 401 Unauthorized

```bash
# Check your API key is set correctly
curl -v -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/system/health
# Look for "X-API-Key" in request headers
```

### Service returns 500 Internal Server Error

```bash
# Check Docker logs
docker logs aldeci-api --tail 50

# Restart the service
docker compose -f docker/docker-compose.yml restart
```

### MPTE returns UNVERIFIED

- Ensure the target URL is accessible from the ALdeci container
- Check that the staging environment allows test traffic
- Try with a simpler vulnerability type first (e.g., `sql_injection`)

### AutoFix returns low confidence

- Provide more source code context (full function, not just the vulnerable line)
- Ensure LLM API keys are configured (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`)
- For air-gapped: configure self-hosted model via vLLM or Ollama

### Need Help?

- **API Documentation**: `http://localhost:8000/docs` (Swagger UI)
- **Postman Collections**: `suite-integrations/postman/enterprise/` (7 collections)
- **CLI Help**: `python -m core.cli --help` (22 commands)

---

*Onboarding Guide v1.0 — Updated 2026-03-01 by Sales Engineer Agent*
