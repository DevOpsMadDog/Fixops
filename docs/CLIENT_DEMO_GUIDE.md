# ALdeci — Enterprise Client Guide

> **Last updated:** 2026-02-20
> **Platform version:** 3.0.0
> **CI status:** All checks GREEN ✅
> **Mode:** Enterprise (all real data, no demo flags)

---

## Table of Contents

1. [Quick Start — Docker](#1-quick-start--docker)
2. [Quick Start — Local](#2-quick-start--local)
3. [Authentication](#3-authentication)
4. [Workflow 1 — Platform Health & Status](#4-workflow-1--platform-health--status)
5. [Workflow 2 — Threat Intelligence & CVE Analysis](#5-workflow-2--threat-intelligence--cve-analysis)
6. [Workflow 3 — Compliance Assessment](#6-workflow-3--compliance-assessment)
7. [Workflow 4 — Vulnerability Discovery & CVSS](#7-workflow-4--vulnerability-discovery--cvss)
8. [Workflow 5 — Copilot Agents & Orchestration](#8-workflow-5--copilot-agents--orchestration)
9. [Workflow 6 — Decision Engine](#9-workflow-6--decision-engine)
10. [Workflow 7 — Reporting](#10-workflow-7--reporting)
11. [Workflow 8 — Business Context & SSVC](#11-workflow-8--business-context--ssvc)
12. [Workflow 9 — Marketplace](#12-workflow-9--marketplace)
13. [Workflow 10 — Remediation Pipeline](#13-workflow-10--remediation-pipeline)
14. [Workflow 11 — Attack Surface & Micro-Pentest](#14-workflow-11--attack-surface--micro-pentest)
15. [Interactive Testing Script](#15-interactive-testing-script)
16. [CLI Examples](#16-cli-examples)
17. [Full API Endpoint Reference](#17-full-api-endpoint-reference)
18. [Known Limitations & Integrations Required](#18-known-limitations--integrations-required)

---

## 1. Quick Start — Docker

```bash
# Pull the latest image (built automatically by CI)
docker pull devopsaico/fixops:latest

# Run in API-only mode (recommended)
docker run -d --name aldeci -p 8000:8000 devopsaico/fixops:latest api-only

# Or run with docker-compose for full stack (API + OTel + Dashboard)
cd docker && docker-compose -f docker-compose.yml up -d

# Verify health
curl http://localhost:8000/health
# Expected: {"status":"healthy","timestamp":"...","service":"aldeci-api"}
```

> **Note:** The Docker entrypoint auto-generates an enterprise token on startup.
> The token is printed to stdout — copy it for API calls.

**Docker entrypoint modes:**

| Mode | Command | Description |
|------|---------|-------------|
| `api-only` | `docker run -d -p 8000:8000 devopsaico/fixops:latest api-only` | API server only (default) |
| `interactive` | `docker run -it devopsaico/fixops:latest interactive` | Interactive API tester |
| `enterprise` | `docker run -it devopsaico/fixops:latest enterprise` | Enterprise E2E validation suite |
| `cli <args>` | `docker run -it devopsaico/fixops:latest cli --help` | CLI commands |
| `shell` | `docker run -it devopsaico/fixops:latest shell` | Bash shell inside container |

---

## 2. Quick Start — Local

```bash
# Prerequisites: Python 3.11+, pip
cd /path/to/Fixops

# Set PYTHONPATH (required for suite architecture)
export PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"

# Install dependencies
pip install -r requirements.txt

# Generate enterprise credentials
export FIXOPS_MODE=enterprise
export FIXOPS_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

# Start the API server
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000

# In another terminal:
curl http://localhost:8000/health
```

---

## 3. Authentication

All API endpoints require an enterprise API key:

```bash
# Generate an enterprise token (if not already set)
export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

# Set variables for the session
export API="http://localhost:8000"
export KEY="$FIXOPS_API_TOKEN"

# Test authentication
curl -s -H "X-API-Key: $KEY" "$API/api/v1/health" | python3 -m json.tool
```

> **Important:** Never use hardcoded tokens. Always generate unique enterprise tokens using `secrets.token_urlsafe(48)`.

---

## 4. Workflow 1 — Platform Health & Status

### 4.1 Health Check

```bash
curl -s "$API/health" | python3 -m json.tool
```

**Expected output:**
```json
{
  "status": "healthy",
  "timestamp": "2026-02-20T...",
  "service": "aldeci-api"
}
```

### 4.2 Versioned Health

```bash
curl -s -H "X-API-Key: $KEY" "$API/api/v1/health" | python3 -m json.tool
```

## 5. Workflow 2 — Threat Intelligence & CVE Analysis

> **Highlight:** Real-time EPSS scores and CISA KEV data — no mocks.

### 5.1 CVE Lookup (Real EPSS Data)

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/copilot/agents/analyst/cve/CVE-2024-3094" | python3 -m json.tool
```

**Expected output** (real data from FIRST.org EPSS feed):
```json
{
  "agent": "security_analyst",
  "cve_id": "CVE-2024-3094",
  "epss_score": 0.85192,
  "kev_listed": true,
  "summary": "xz/liblzma backdoor — high exploitability..."
}
```

### 5.2 Trending CVEs (Top by EPSS Score)

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/copilot/agents/analyst/trending" | python3 -m json.tool
```

### 5.3 Prioritize Findings by Risk

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/analyst/prioritize" \
  -d '{
    "findings": [
      {"id": "f1", "cve_id": "CVE-2024-3094", "severity": "CRITICAL"},
      {"id": "f2", "cve_id": "CVE-2023-44487", "severity": "HIGH"},
      {"id": "f3", "cve_id": "CVE-2021-44228", "severity": "CRITICAL"}
    ]
  }' | python3 -m json.tool
```

### 5.4 Threat Intelligence Report

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/analyst/threat-intel" \
  -d '{"cve_ids": ["CVE-2024-3094", "CVE-2021-44228"]}' | python3 -m json.tool
```

### 5.5 EPSS Feed (Raw Scores)

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/feeds/epss?limit=5" | python3 -m json.tool
```

---

## 6. Workflow 3 — Compliance Assessment

> **Highlight:** Real ComplianceEngine evaluation — not stubs.

### 6.1 Compliance Dashboard (All Frameworks)

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/copilot/agents/compliance/dashboard" | python3 -m json.tool
```

**Expected output:** Real baseline posture from ComplianceEngine for PCI-DSS, SOX, HIPAA, NIST, GDPR.

### 6.2 Map Findings to Compliance Frameworks

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/compliance/map-findings" \
  -d '{
    "findings": [
      {"id": "f1", "severity": "HIGH", "category": "injection", "title": "SQL Injection in login"},
      {"id": "f2", "severity": "MEDIUM", "category": "auth", "title": "Weak password policy"}
    ],
    "frameworks": ["pci_dss", "hipaa"]
  }' | python3 -m json.tool
```

### 6.3 Gap Analysis

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/compliance/gap-analysis" \
  -d '{"frameworks": ["pci_dss", "sox", "nist"]}' | python3 -m json.tool
```

### 6.4 Generate Compliance Report

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/compliance/generate-report" \
  -d '{"framework": "pci_dss", "format": "json"}' | python3 -m json.tool
```

### 6.5 Compliance Controls Metadata

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/copilot/agents/compliance/controls/pci-dss" | python3 -m json.tool
```

**Expected:** Returns control metadata and control counts per framework.

---

## 7. Workflow 4 — Vulnerability Discovery & CVSS

> **Highlight:** Real CVSS3 scoring using the `cvss` library.

### 7.1 List Discovered Vulnerabilities

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/vulns/discovered?limit=10" | python3 -m json.tool
```

### 7.2 Contribute a Finding (with CVSS Calculation)

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/vulns/contribute" \
  -d '{
    "title": "Remote Code Execution in API Gateway",
    "description": "Unauthenticated RCE via deserialization",
    "severity": "CRITICAL",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  }' | python3 -m json.tool
```

**Expected:** Returns a computed `cvss_score: 9.8` from the real CVSS3 library.

### 7.3 Reachability Metrics

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/reachability/metrics" | python3 -m json.tool
```

---

## 8. Workflow 5 — Copilot Agents & Orchestration

> **Highlight:** Multi-agent orchestration with security analyst, compliance, remediation agents.

### 8.1 Agent Status (Shows Available Capabilities)

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/copilot/agents/status" | python3 -m json.tool
```

**Expected:** Shows `security_analyst: ready`, `compliance_engine: connected`.

### 8.2 Orchestrate a Multi-Agent Task

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/orchestrate" \
  -d '{
    "objective": "Analyze CVE-2024-3094 and recommend remediation",
    "cve_ids": ["CVE-2024-3094"]
  }' | python3 -m json.tool
```

**Expected:**
```json
{
  "task_id": "...",
  "agent": "orchestrator",
  "status": "executing",
  "result": {
    "objective": "Analyze CVE-2024-3094 and recommend remediation",
    "agents_available": ["security_analyst"],
    "message": "Orchestration ready"
  }
}
```

### 8.3 Attack Path Analysis

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/attack-path/analyze" \
  -d '{"asset_id": "web-server-01", "depth": 3}' | python3 -m json.tool
```

### 8.4 Asset Risk Score

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/asset/risk-score" \
  -d '{"asset_id": "payment-api-prod", "include_context": true}' | python3 -m json.tool
```

---

## 9. Workflow 6 — Decision Engine

### 9.1 Core Components

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/decisions/core-components" | python3 -m json.tool
```

**Expected:** Returns SSVC decision engine components: exploitation status, automatable analysis, technical impact, mission prevalence, public well-being.

### 9.2 Get Decision for a Finding

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/decisions/decide" \
  -d '{
    "finding_id": "f-001",
    "severity": "CRITICAL",
    "cve_id": "CVE-2024-3094",
    "asset": "payment-gateway"
  }' | python3 -m json.tool
```

---

## 10. Workflow 7 — Reporting

### 10.1 List Reports

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/reports" | python3 -m json.tool
```

### 10.2 Generate a Report

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/reports/generate" \
  -d '{"type": "executive_summary", "format": "json"}' | python3 -m json.tool
```

---

## 11. Workflow 8 — Business Context & SSVC

### 11.1 List Supported Formats

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/business-context/formats" | python3 -m json.tool
```

**Expected:** Returns supported formats: `core.yaml`, `otm.json`, `sbom.json`, etc.

### 11.2 View Stored Business Contexts

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/business-context/stored" | python3 -m json.tool
```

---

## 12. Workflow 9 — Marketplace

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/marketplace/browse" | python3 -m json.tool
```

**Expected:** Returns production marketplace items with real ratings, download counts, and pricing models.

---

## 13. Workflow 10 — Remediation Pipeline

> **Note:** Remediation endpoints require external integrations (LLM API keys, Git providers, etc). The platform gracefully returns `integration_required: true` with clear setup instructions.

### 13.1 AI Fix Generation

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/remediation/generate-fix" \
  -d '{"finding_id": "f-001", "language": "python"}' | python3 -m json.tool
```

**Expected:** `"integration_required": true`, `"message": "LLM API key required..."`.

### 13.2 Create PR

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/remediation/create-pr" \
  -d '{"finding_id": "f-001", "fix_id": "fix-001"}' | python3 -m json.tool
```

### 13.3 Remediation Recommendations

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/remediation/recommendations" \
  -d '{"finding_ids": ["f-001", "f-002"]}' | python3 -m json.tool
```

### 13.4 Playbook Generation

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/remediation/playbook" \
  -d '{"finding_id": "f-001", "framework": "pci_dss"}' | python3 -m json.tool
```

---

## 14. Workflow 11 — Attack Surface & Micro-Pentest

### 14.1 Micro-Pentest Health

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/micro-pentest/health" | python3 -m json.tool
```

**Expected:** Shows MPTE connection status. When MPTE service is not connected, pentest endpoints return `"integration_required": true` with setup instructions.

### 14.2 PentAGI Capabilities

```bash
curl -s -H "X-API-Key: $KEY" \
  "$API/api/v1/pentagi/capabilities" | python3 -m json.tool
```

**Expected:** Lists all AI-powered penetration testing capabilities: threat intelligence, AI consensus, attack simulation, business impact analysis.

### 14.3 Attack Simulation (Requires MPTE)

```bash
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/pentest/simulate" \
  -d '{"target": "https://example.com", "mode": "passive"}' | python3 -m json.tool
```

---

## 15. Interactive Testing Script

The **enterprise interactive testing script** walks through the entire CTEM loop with real user input:

```bash
# Set enterprise token and run
export FIXOPS_API_TOKEN="$KEY"
export FIXOPS_API_URL="$API"
bash scripts/fixops-enterprise-test.sh
```

**Features:**
- Menu-driven interface with 5 CTEM stages
- Collects real CVE IDs, asset names, compliance frameworks from user
- Tests all 37+ engine health endpoints
- CVE deep-dive with NVD, EPSS, geo-risk, AI analyst
- Individual API endpoint testing mode
- Pass/fail tracking with summary report

---

## 16. CLI Examples

```bash
# Inside Docker container:
docker exec -it aldeci bash

# ALdeci CLI
aldeci --help
aldeci scan /app/tests/fixtures/
aldeci findings
aldeci evidence generate --framework SOC2
aldeci brain ask "What are the top 5 critical vulnerabilities?"

# FixOps CI CLI
fixops-ci sbom --help
fixops-ci risk --help
fixops-ci evidence bundle --tag v1.0.0
```

---

## 17. Full API Endpoint Reference

The platform exposes **624 routes across 65 prefixes**. Key domain areas:

| Domain | Prefix | Key Endpoints |
|--------|--------|---------------|
| Health | `/health`, `/api/v1/health` | Platform health checks |
| Decisions | `/api/v1/decisions` | Decision engine, core components |
| Copilot | `/api/v1/copilot` | AI chat, brain interface |
| Agents | `/api/v1/copilot/agents` | Analyst, compliance, remediation, pentest |
| Nerve Center | `/api/v1/nerve-center` | Dashboard, alerts, status |
| Brain/Pipeline | `/api/v1/brain` | Brain pipeline, knowledge graph |
| Feeds | `/api/v1/feeds` | EPSS, KEV, NVD threat intel |
| Vulns | `/api/v1/vulns` | Vulnerability management |
| Micro-Pentest | `/api/v1/micro-pentest` | Penetration testing |
| PentAGI | `/api/v1/pentagi` | AI pentest orchestration |
| Attack Sim | `/api/v1/attack-simulation` | Attack scenarios, MITRE |
| Compliance | `/api/v1/copilot/agents/compliance` | Framework assessment |
| Reports | `/api/v1/reports` | Report generation |
| Evidence | `/api/v1/evidence` | Evidence bundles |
| Risk | `/api/v1/risk` | Risk scoring |
| Reachability | `/api/v1/reachability` | Call-graph analysis |
| Business Ctx | `/api/v1/business-context` | SSVC, context uploads |
| Marketplace | `/api/v1/marketplace` | Plugin marketplace |
| Integrations | `/api/v1/integrations` | SIEM, ticketing, SCM |
| Webhooks | `/api/v1/webhooks` | Event webhooks |
| IaC | `/api/v1/iac` | Infrastructure-as-code |
| IDE | `/api/v1/ide` | IDE plugin support |
| OSS Tools | `/api/v1/oss` | Trivy, Grype, OPA |
| MCP | `/api/v1/mcp` | Model Context Protocol |
| Analytics | `/api/v1/analytics` | Metrics, dashboards |
| Auth | `/api/v1/auth` | Authentication, tokens |

> **Explore all endpoints:** Visit `http://localhost:8000/docs` for the Swagger UI, or `http://localhost:8000/redoc` for ReDoc.

---

## 18. Known Limitations & Integrations Required

| Feature | Status | Required Integration |
|---------|--------|---------------------|
| EPSS/KEV threat intel | ✅ **Working** | Built-in (FIRST.org + CISA feeds) |
| CVSS scoring | ✅ **Working** | Built-in (`cvss` library) |
| Compliance assessment | ✅ **Working** | Built-in (ComplianceEngine) |
| Decision engine | ✅ **Working** | Built-in |
| Reporting | ✅ **Working** | Built-in |
| Business context | ✅ **Working** | Built-in |
| AI fix generation | ⏳ Integration required | LLM API key (OpenAI/Claude/Gemini) |
| PR creation | ⏳ Integration required | Git provider token (GitHub/GitLab) |
| Dependency updates | ⏳ Integration required | Package manager access |
| Playbook generation | ⏳ Integration required | Knowledge base + LLM API key |
| Attack simulation | ⏳ Integration required | MPTE service |
| Micro-pentest | ⏳ Integration required | MPTE service |
| SIEM integration | ⏳ Integration required | Splunk/QRadar credentials |
| Cloud analysis | ⏳ Integration required | AWS/Azure/GCP SDK + credentials |
| Evidence Lake | ⏳ Integration required | Database (PostgreSQL) |

> **All `integration_required` endpoints return a clear JSON message** explaining what's needed. This is by design — the platform is modular and extensible.

---

## Quick Reference Card

```bash
# Generate enterprise credentials
export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export API="http://localhost:8000"
export KEY="$FIXOPS_API_TOKEN"

# Health check
curl -s "$API/health"

# Threat intel
curl -s -H "X-API-Key: $KEY" "$API/api/v1/copilot/agents/analyst/cve/CVE-2024-3094"
curl -s -H "X-API-Key: $KEY" "$API/api/v1/copilot/agents/analyst/trending"

# Compliance
curl -s -H "X-API-Key: $KEY" "$API/api/v1/copilot/agents/compliance/dashboard"

# Decision engine
curl -s -H "X-API-Key: $KEY" "$API/api/v1/decisions/core-components"

# Agent orchestration
curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  "$API/api/v1/copilot/agents/orchestrate" \
  -d '{"objective":"Full security assessment","cve_ids":["CVE-2024-3094"]}'

# Reports
curl -s -H "X-API-Key: $KEY" "$API/api/v1/reports"

# Interactive enterprise testing (full CTEM loop)
bash scripts/fixops-enterprise-test.sh

# Swagger UI
open "$API/docs"
```

