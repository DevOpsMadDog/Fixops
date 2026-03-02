# ALdeci Customer Onboarding Guide

> **Version**: 3.0 | **Platform**: CTEM+ Decision Intelligence for Application Security
> **Updated**: 2026-03-02 | **Duration**: 2-4 hours from install to first actionable report

---

## Pre-Requisites Checklist

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Docker** | 24.0+ with Compose v2 | Latest stable |
| **RAM** | 8 GB | 16 GB (for self-hosted LLM) |
| **Disk** | 20 GB | 50 GB (for scan data retention) |
| **Python** | 3.10+ (local dev only) | 3.11+ |
| **Ports** | 8000 (API), 3001 (UI) | — |

**Software Checklist:**
- [ ] Docker 24+ and Docker Compose v2 (`docker compose version`)
- [ ] `curl` and `jq` for API testing
- [ ] API key from your ALdeci account manager
- [ ] (Optional) Existing scanner API tokens (Snyk, Semgrep, SonarQube, etc.)
- [ ] (Optional) LLM provider API key (OpenAI or Anthropic) for AI features
- [ ] For air-gapped: No internet required after initial Docker image pull

---

## Step 1: Installation

### Option A: Docker (Recommended)

```bash
# Clone the repository (or receive the enterprise bundle)
git clone https://github.com/aldeci/fixops.git && cd fixops

# Copy and configure environment
cp .env.example .env
# Edit .env with your API token (see Step 2)

# Start everything
docker compose -f docker/docker-compose.yml up -d

# Verify health
curl -sf http://localhost:8000/health | jq .
# Expected: {"status": "healthy", "service": "aldeci-api"}
```

### Option B: Local Development

```bash
pip install -r requirements.txt
export FIXOPS_MODE=enterprise
export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export FIXOPS_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

# Optional: LLM API keys for AutoFix and AI Consensus
export OPENAI_API_KEY="sk-proj-..."       # or
export ANTHROPIC_API_KEY="sk-ant-..."

python -m uvicorn apps.api.app:create_app --factory --port 8000
```

### Option C: Air-Gapped Deployment

```bash
# On internet-connected machine:
docker compose -f docker/docker-compose.yml pull
docker save fixops:local aldeci-ui:local > aldeci-bundle.tar

# On air-gapped machine:
docker load < aldeci-bundle.tar
docker compose -f docker/docker-compose.air-gapped-test.yml up -d

# For self-hosted LLM, add to .env:
# VLLM_BASE_URL=http://localhost:8001/v1
# VLLM_MODEL=meta-llama/Meta-Llama-3.1-70B-Instruct
```

---

## Step 2: Initial Configuration

### API Authentication

All API calls require the `X-API-Key` header:

```bash
export API_KEY="your-api-key-here"
curl -s -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/system/health | jq .
```

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `FIXOPS_API_TOKEN` | — | API authentication key (required) |
| `FIXOPS_JWT_SECRET` | auto-generated | JWT token signing secret |
| `FIXOPS_MODE` | `enterprise` | Operating mode (`enterprise`, `demo`, `development`) |
| `FIXOPS_DATA_DIR` | `.fixops_data` | Data storage directory |
| `FIXOPS_ALLOWED_ORIGINS` | localhost:3000,3001 | Comma-separated CORS allowed origins |
| `FIXOPS_DISABLE_RATE_LIMIT` | `0` | Set to `1` to disable rate limiting |
| `OPENAI_API_KEY` | — | OpenAI key for AI consensus and AutoFix |
| `ANTHROPIC_API_KEY` | — | Anthropic key (alternative LLM provider) |
| `MPTE_BASE_URL` | `https://localhost:8443` | Micro-Pentest Engine URL |

---

## Step 3: Connect Your First Data Source

### Option A: Upload an Existing Scanner Report

```bash
# ALdeci supports 25+ scanner formats (Snyk, Nessus, ZAP, Burp, Trivy, etc.)
curl -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $API_KEY" \
  -F "file=@your-scan-report.json" \
  -F "scanner_type=snyk"

# Auto-detect format
curl -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $API_KEY" \
  -F "file=@scan-report.sarif" \
  -F "scanner_type=auto"

# List supported scanner formats
curl -s http://localhost:8000/api/v1/scanner-ingest/supported \
  -H "X-API-Key: $API_KEY" | jq .
```

Supported: Snyk, Semgrep (SARIF), ZAP, Burp, Nessus, Trivy, Grype, CycloneDX, SPDX, Dependabot, SonarQube, Checkmarx, Fortify, AWS SecurityHub, Wiz, Prisma Cloud, and more.

### Option B: Configure a Continuous Connector

```bash
curl -X POST http://localhost:8000/api/v1/connectors \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Snyk",
    "type": "snyk",
    "config": {"api_token": "your-snyk-token", "org_id": "your-org-id"}
  }'
```

### Option C: CI/CD Webhook

```bash
# In your CI/CD pipeline, POST scan results directly:
curl -X POST http://localhost:8000/api/v1/scanner-ingest/webhook/snyk \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d @snyk-ci-output.json
```

---

## Step 4: Run Your First Scan

ALdeci includes 8 native scanners that require no external tools.

### SAST (Static Analysis)

```bash
curl -X POST http://localhost:8000/api/v1/sast/scan/code \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "cursor.execute(\"SELECT * FROM users WHERE name = \" + user_input)",
    "language": "python",
    "filename": "app.py"
  }'
```

### All 8 Native Scanners

| Scanner | Endpoint | What It Detects |
|---------|----------|-----------------|
| **SAST** | `POST /api/v1/sast/scan/code` | SQL injection, XSS, command injection, path traversal |
| **DAST** | `POST /api/v1/dast/scan` | Web app vulnerabilities via live testing |
| **Secrets** | `POST /api/v1/secrets/scan` | API keys, passwords, tokens, credentials |
| **Container** | `POST /api/v1/container/scan` | Dockerfile issues, image CVEs |
| **CSPM/IaC** | `POST /api/v1/cspm/scan` | Terraform/CloudFormation misconfigurations |
| **API Fuzzer** | `POST /api/v1/api-fuzzer/fuzz` | API endpoint vulnerabilities |
| **Malware** | `POST /api/v1/malware/scan` | Malicious code patterns, backdoors |
| **LLM Monitor** | `POST /api/v1/llm-monitor/analyze` | Prompt injection, jailbreak attempts |

---

## Step 5: Brain Pipeline Processing

Every finding flows through ALdeci's 12-step decision intelligence pipeline:

| Step | Name | What It Does |
|------|------|--------------|
| 1 | **Connect** | Ingests findings from all connected sources |
| 2 | **Normalize** | Translates to `UnifiedFinding` schema |
| 3 | **Resolve Identity** | Fuzzy-matches findings across scanners |
| 4 | **Deduplicate** | Collapses duplicates into Exposure Cases |
| 5 | **Build Graph** | Constructs knowledge graph of assets and vulnerabilities |
| 6 | **Enrich Threats** | Adds EPSS probability, KEV status, CVSS scores |
| 7 | **Score Risk** | GNN algorithms and attack-path analysis |
| 8 | **Apply Policy** | Evaluates organizational policies and SLAs |
| 9 | **LLM Consensus** | Multi-LLM triage recommendations |
| 10 | **Micro-Pentest** | MPTE verification of real-world exploitability |
| 11 | **Run Playbooks** | Automated remediation (Jira, Slack, PRs) |
| 12 | **Generate Evidence** | Cryptographically signed SOC2 evidence bundles |

```bash
# Ingest a finding into the pipeline
curl -X POST http://localhost:8000/api/v1/brain/ingest/finding \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "onboarding-001",
    "title": "SQL Injection in login endpoint",
    "severity": "CRITICAL",
    "cwe": "CWE-89",
    "source": "native-sast",
    "app_id": "web-portal"
  }'

# Get the FAIL priority score (contextual, replaces raw CVSS)
curl -X POST http://localhost:8000/api/v1/fail/score \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"onboarding-001","cvss":9.8,"epss":0.87,"asset_criticality":"high","reachable":true}'

# Check pipeline stats
curl -s http://localhost:8000/api/v1/brain/stats -H "X-API-Key: $API_KEY" | jq .
```

---

## Step 6: View Results in the Dashboard

### Web UI

Open **http://localhost:3001** for the Mission Control dashboard showing posture score, active findings, risk trends, and compliance status.

### API-Based Dashboard

```bash
# Dashboard overview (posture score, finding counts, MTTR)
curl -s http://localhost:8000/api/v1/analytics/dashboard/overview \
  -H "X-API-Key: $API_KEY" | jq .

# Findings with filtering
curl -s "http://localhost:8000/api/v1/analytics/findings?severity=critical" \
  -H "X-API-Key: $API_KEY" | jq .

# Top risks
curl -s http://localhost:8000/api/v1/analytics/dashboard/top-risks \
  -H "X-API-Key: $API_KEY" | jq .

# Compliance status
curl -s http://localhost:8000/api/v1/analytics/dashboard/compliance-status \
  -H "X-API-Key: $API_KEY" | jq .

# Triage funnel (how findings flow through the pipeline)
curl -s http://localhost:8000/api/v1/analytics/triage-funnel \
  -H "X-API-Key: $API_KEY" | jq .

# Noise reduction metrics
curl -s http://localhost:8000/api/v1/analytics/noise-reduction \
  -H "X-API-Key: $API_KEY" | jq .
```

### Understanding Prioritization

ALdeci layers five prioritization signals:
1. **Raw Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
2. **CVSS Score**: 0.0-10.0
3. **EPSS Probability**: 0.0-1.0 (likelihood of exploitation in 30 days)
4. **FAIL Score**: 0-100 (ALdeci proprietary -- recommended metric)
5. **MPTE Verdict**: Verified exploitable, verified safe, or unverified

---

## Step 7: Configure Policies

```bash
# Create a policy with SLA enforcement
curl -X POST http://localhost:8000/api/v1/policies \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Critical-SLA-7d",
    "description": "Critical findings must be remediated within 7 days",
    "rules": {
      "max_mttr_days": 7,
      "auto_fix_threshold": "high",
      "severity_filter": ["CRITICAL"],
      "auto_assign": true
    }
  }'

# List policies
curl -s http://localhost:8000/api/v1/policies -H "X-API-Key: $API_KEY" | jq .

# Test a policy (dry run)
curl -X POST http://localhost:8000/api/v1/policies/{policy_id}/test \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{}'

# Enforce a policy
curl -X POST http://localhost:8000/api/v1/policies/{policy_id}/enforce \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{}'

# Check for policy conflicts
curl -s http://localhost:8000/api/v1/policies/conflicts -H "X-API-Key: $API_KEY" | jq .
```

---

## Step 8: Enable AutoFix

### View Fix Types and Confidence Levels

```bash
# List the 10 supported fix types
curl -s http://localhost:8000/api/v1/autofix/fix-types -H "X-API-Key: $API_KEY" | jq .

# Get confidence level definitions
curl -s http://localhost:8000/api/v1/autofix/confidence-levels -H "X-API-Key: $API_KEY" | jq .
```

**10 Fix Types**: `code_patch`, `dependency_update`, `config_hardening`, `iac_fix`, `secret_rotation`, `permission_fix`, `input_validation`, `output_encoding`, `waf_rule`, `container_fix`

**Confidence Thresholds**: HIGH (>85%, auto-apply) | MEDIUM (60-85%, PR for review) | LOW (<60%, suggestion only)

### Generate and Apply a Fix

```bash
# Generate an AI-powered fix
curl -X POST http://localhost:8000/api/v1/autofix/generate \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "onboarding-001",
    "vulnerability_type": "sql_injection",
    "source_code": "cursor.execute(\"SELECT * FROM users WHERE name = \" + user_input)",
    "language": "python",
    "fix_type": "code_patch"
  }'

# Apply a validated fix (creates a pull request)
curl -X POST http://localhost:8000/api/v1/autofix/apply \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"fix_id": "fix-abc123", "auto_merge": false}'

# Monitor AutoFix stats
curl -s http://localhost:8000/api/v1/autofix/stats -H "X-API-Key: $API_KEY" | jq .
```

---

## Step 9: Compliance Framework Setup

### Supported Frameworks

SOC 2 Type II, PCI DSS 4.0, HIPAA, ISO 27001:2022, NIST 800-53 Rev 5, NIST CSF 2.0, OWASP ASVS 4.0

```bash
# List supported frameworks
curl -s http://localhost:8000/api/v1/compliance-engine/frameworks \
  -H "X-API-Key: $API_KEY" | jq .

# Map findings to framework controls
curl -X POST http://localhost:8000/api/v1/compliance-engine/map-findings \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [{"finding_id":"onboarding-001","cwe":"CWE-89","severity":"CRITICAL"}],
    "framework": "soc2"
  }'

# Assess compliance posture
curl -X POST http://localhost:8000/api/v1/compliance-engine/assess \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"framework": "soc2"}'

# View compliance gaps
curl -s http://localhost:8000/api/v1/compliance-engine/gaps -H "X-API-Key: $API_KEY" | jq .

# Generate cryptographically signed audit bundle (RSA-SHA256)
curl -s http://localhost:8000/api/v1/compliance-engine/audit-bundle \
  -H "X-API-Key: $API_KEY" | jq .

# Look up CWE-to-control mappings
curl -s http://localhost:8000/api/v1/compliance-engine/cwe-mapping/CWE-89 \
  -H "X-API-Key: $API_KEY" | jq .
```

---

## Step 10: First Results Review

After completing steps 1-9, review your results end to end.

```bash
# Verify MPTE exploitability for critical findings
curl -X POST http://localhost:8000/api/v1/mpte/verify \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "onboarding-001",
    "vulnerability_type": "sql_injection",
    "target": "http://your-staging-app:8080/login",
    "context": {"cwe": "CWE-89", "parameter": "username"}
  }'
# Verdicts: VULNERABLE_VERIFIED | NOT_VULNERABLE_VERIFIED | NOT_APPLICABLE | UNVERIFIED

# Review pipeline decisions
curl -s http://localhost:8000/api/v1/analytics/decisions \
  -H "X-API-Key: $API_KEY" | jq '.[] | {finding_id, decision, confidence}'

# Overall summary
curl -s http://localhost:8000/api/v1/analytics/summary -H "X-API-Key: $API_KEY" | jq .

# ROI metrics
curl -s http://localhost:8000/api/v1/analytics/roi -H "X-API-Key: $API_KEY" | jq .
```

---

## Success Metrics

| Metric | Baseline | Week 1 Target | Week 2 Target |
|--------|----------|---------------|---------------|
| Findings ingested | 0 | 1,000+ | 5,000+ |
| Noise reduction | 0% | 50% | 90%+ |
| False positive elimination | 0% | 30% | 68%+ |
| MTTR (days) | 14 | 7 | 3 |
| AutoFix adoption | 0% | 20% | 50% |
| Compliance coverage | 0% | 60% | 90% |
| Audit prep time | 3 weeks | 1 week | < 2 hours |

---

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| API returns 401 | Missing or wrong API key | Verify `X-API-Key` header matches `FIXOPS_API_TOKEN` in `.env` |
| Container won't start | Port conflict | Run `lsof -i :8000` and kill the conflicting process |
| Slow responses | Insufficient resources | Set `FIXOPS_WORKERS=4` in `.env` and increase container RAM |
| Upload returns 413 | File exceeds 100 MB limit | Split large scan reports into smaller batches |
| Upload returns 422 | Invalid scanner type | Check `GET /api/v1/scanner-ingest/supported` or use `scanner_type=auto` |
| MPTE returns UNVERIFIED | Target unreachable | Ensure staging app is accessible from ALdeci container network |
| AutoFix low confidence | No LLM key configured | Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in `.env` |
| Air-gapped failures | Missing images | Run `docker images | grep -E "fixops\|aldeci"` to verify |

```bash
# General debugging
docker logs fixops-api --tail 50
docker logs aldeci-ui --tail 50
docker stats fixops-api
```

---

## Getting Help

| Resource | Location |
|----------|----------|
| API Reference | `docs/API_REFERENCE.md` |
| Architecture | `docs/ARCHITECTURE.md` |
| Demo Scripts | `docs/DEMO_PERSONA_SCRIPTS.md` |
| Swagger UI | `http://localhost:8000/docs` |
| CLI Help | `python -m core.cli --help` (22 commands) |
| Support | support@aldeci.com |

---

*ALdeci Customer Onboarding Guide v3.0 -- 2026-03-02*
