# ALdeci CTEM+ API Reference

> **Version**: 2.0 — Enterprise Demo Edition
> **Last updated**: 2026-03-01
> **Base URL**: `http://localhost:8000`
> **Total endpoints**: 704 across 64 routers + inline definitions
> **Authentication**: API Key (`X-API-Key` header) or JWT Bearer token
> **OpenAPI Spec**: `GET /openapi.json`
> **Pillar**: [V3] Decision Intelligence · [V5] MPTE Verification · [V7] MCP-Native · [V10] CTEM Full Loop

---

## Quickstart — Up and Running in 3 Steps

### Step 1: Start the API Server

```bash
# Clone and install
git clone https://github.com/DevOpsMadDog/Fixops.git && cd Fixops
pip install -r requirements.txt

# Start the server
python -m uvicorn apps.api.app:create_app --factory --port 8000
```

### Step 2: Authenticate

```bash
# Set your API key (use demo token for testing)
export FIXOPS_API_TOKEN="demo-token-12345"

# Verify the server is running
curl -s http://localhost:8000/health | python3 -m json.tool
# → {"status": "healthy", "service": "aldeci-api"}

# Authenticate and get a JWT token (enterprise mode)
curl -s -X POST http://localhost:8000/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}' | python3 -m json.tool
```

### Step 3: Run Your First Scan

```bash
# Upload a scanner report (e.g., ZAP, Burp, Nessus, Checkmarx)
curl -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@zap-report.json" \
  -F "scanner_type=zap"

# Or run a native SAST scan
curl -X POST http://localhost:8000/api/v1/sast/scan/code \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "import os; os.system(input())", "language": "python"}'

# Check the triage dashboard
curl -s http://localhost:8000/api/v1/analytics/dashboard/overview \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | python3 -m json.tool
```

You now have ALdeci CTEM+ running with full API access. Read on for the complete endpoint reference organized by the CTEM lifecycle.

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [CTEM Lifecycle Overview](#2-ctem-lifecycle-overview)
3. [Discover — Scanners, Feeds & Ingestion](#3-discover--scanners-feeds--ingestion)
4. [Validate — MPTE, Pentest & Verification](#4-validate--mpte-pentest--verification)
5. [Remediate — AutoFix, Workflows & Actions](#5-remediate--autofix-workflows--actions)
6. [Comply — Evidence, Compliance & Audit](#6-comply--evidence-compliance--audit)
7. [Intelligence — Brain Pipeline, Analytics & AI](#7-intelligence--brain-pipeline-analytics--ai)
8. [Platform — Admin, Users, Teams & System](#8-platform--admin-users-teams--system)
9. [Error Codes](#9-error-codes)
10. [Rate Limits](#10-rate-limits)

---

## 1. Authentication

All endpoints except `/health` and `/api/v1/health` require authentication.

### API Key Authentication (recommended for scripts)

```bash
# Header method (preferred)
curl -H "X-API-Key: YOUR_TOKEN" http://localhost:8000/api/v1/analytics/findings

# Query parameter method
curl "http://localhost:8000/api/v1/analytics/findings?api_key=YOUR_TOKEN"
```

### JWT Authentication (enterprise mode)

```bash
# 1. Login to get a token
curl -X POST http://localhost:8000/api/v1/users/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}'
# → {"access_token": "eyJ...", "token_type": "bearer", "expires_in": 7200}

# 2. Use the Bearer token
curl -H "Authorization: Bearer eyJ..." http://localhost:8000/api/v1/analytics/findings
```

JWT tokens expire after `FIXOPS_JWT_EXP_MINUTES` (default: 120 minutes).

### Scopes

| Scope | Required For |
|-------|-------------|
| `admin:all` | User/team management, system config |
| `write:findings` | Creating/updating findings, policies |
| `attack:execute` | Scanner execution, MPTE, pentest |
| `read:evidence` | Evidence bundles, compliance, risk |
| `write:integrations` | Integration management, webhooks |

---

## 2. CTEM Lifecycle Overview

ALdeci organizes its 704 endpoints around the **Continuous Threat Exposure Management (CTEM)** lifecycle:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  DISCOVER   │───▶│  VALIDATE   │───▶│  REMEDIATE  │───▶│   COMPLY    │
│             │    │             │    │             │    │             │
│ 8 Scanners  │    │ MPTE 19-ph  │    │ AutoFix 10  │    │ Evidence    │
│ 25 Parsers  │    │ Sandbox PoC │    │ Workflows   │    │ Compliance  │
│ 6 Feeds     │    │ FAIL Engine │    │ Connectors  │    │ Audit Trail │
│ ~180 endpts │    │ ~120 endpts │    │ ~100 endpts │    │ ~80 endpts  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
        │                │                  │                   │
        └────────────────┴──────────────────┴───────────────────┘
                              ▲
                    ┌─────────┴──────────┐
                    │   INTELLIGENCE     │
                    │ Brain Pipeline     │
                    │ Knowledge Graph    │
                    │ AI Copilot         │
                    │ ~224 endpoints     │
                    └────────────────────┘
```

---

## 3. Discover — Scanners, Feeds & Ingestion

> **CTEM Phase**: Find every risk in your environment.
> **Pillar**: [V3] [V7] [V9]

### 3.1 Native Scanners (8 Built-in)

ALdeci ships with 8 native scanners that work air-gapped — no external tools required.

#### 3.1.1 SAST — Static Application Security Testing

**Prefix**: `/api/v1/sast` · **Source**: `suite-attack/api/sast_router.py` · **Engine**: `suite-core/core/sast_engine.py` (465 LOC)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/sast/scan/code` | Scan source code for vulnerabilities |
| `POST` | `/api/v1/sast/scan/files` | Scan uploaded files |
| `GET` | `/api/v1/sast/rules` | List detection rules |
| `GET` | `/api/v1/sast/status` | Engine status |
| `GET` | `/api/v1/sast/health` | Health check |

**Example — Scan Python code for injection flaws:**

```bash
curl -X POST http://localhost:8000/api/v1/sast/scan/code \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import subprocess\nsubprocess.call(user_input, shell=True)",
    "language": "python",
    "scan_type": "full"
  }'
```

```json
{
  "findings": [
    {
      "id": "SAST-001",
      "title": "Command Injection via subprocess.call with shell=True",
      "severity": "CRITICAL",
      "cwe": "CWE-78",
      "line": 2,
      "confidence": 0.95
    }
  ],
  "scan_duration_ms": 45,
  "rules_matched": 1
}
```

#### 3.1.2 DAST — Dynamic Application Security Testing

**Prefix**: `/api/v1/dast` · **Source**: `suite-attack/api/dast_router.py` · **Engine**: `suite-core/core/dast_engine.py` (533 LOC)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/dast/scan` | Run dynamic scan against a target URL |
| `GET` | `/api/v1/dast/status` | Engine status |
| `GET` | `/api/v1/dast/health` | Health check |

**Example — Scan a web application:**

```bash
curl -X POST http://localhost:8000/api/v1/dast/scan \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://testapp.example.com",
    "scan_type": "full",
    "auth": {"type": "bearer", "token": "app-token"}
  }'
```

#### 3.1.3 Secrets Scanner

**Prefix**: `/api/v1/secrets` · **Source**: `suite-attack/api/secrets_router.py` · **Engine**: `suite-core/core/secrets_scanner.py` (775 LOC)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/secrets` | List detected secret findings (paginated) |
| `POST` | `/api/v1/secrets` | Create a secret finding |
| `GET` | `/api/v1/secrets/{id}` | Get secret finding details |
| `POST` | `/api/v1/secrets/{id}/resolve` | Resolve/rotate a secret |
| `POST` | `/api/v1/secrets/scan/content` | Scan content for secrets |
| `GET` | `/api/v1/secrets/scanners/status` | Scanner detector status |
| `GET` | `/api/v1/secrets/status` | Engine status |
| `GET` | `/api/v1/secrets/health` | Health check |

**Example — Scan code for leaked credentials:**

```bash
curl -X POST http://localhost:8000/api/v1/secrets/scan/content \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "aws_secret_key = \"AKIAIOSFODNN7EXAMPLE\"",
    "filename": "config.py"
  }'
```

#### 3.1.4 Container Scanner

**Prefix**: `/api/v1/container` · **Source**: `suite-attack/api/container_router.py` · **Engine**: `suite-core/core/container_scanner.py` (410 LOC)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/container/scan/dockerfile` | Scan a Dockerfile for misconfigurations |
| `POST` | `/api/v1/container/scan/image` | Scan a container image for CVEs |
| `GET` | `/api/v1/container/status` | Engine status |
| `GET` | `/api/v1/container/health` | Health check |

#### 3.1.5 CSPM / IaC Scanner

**Prefix**: `/api/v1/cspm` · **Source**: `suite-attack/api/cspm_router.py` · **Engine**: `suite-core/core/cspm_engine.py` (586 LOC)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/cspm/scan/terraform` | Scan Terraform files for misconfigurations |
| `POST` | `/api/v1/cspm/scan/cloudformation` | Scan CloudFormation templates |
| `GET` | `/api/v1/cspm/rules` | List CIS benchmark rules |
| `GET` | `/api/v1/cspm/status` | Engine status |
| `GET` | `/api/v1/cspm/health` | Health check |

#### 3.1.6 API Fuzzer

**Prefix**: `/api/v1/api-fuzzer` · **Source**: `suite-attack/api/api_fuzzer_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/api-fuzzer/discover` | Discover API endpoints |
| `POST` | `/api/v1/api-fuzzer/fuzz` | Fuzz API endpoints for vulnerabilities |
| `GET` | `/api/v1/api-fuzzer/status` | Engine status |

#### 3.1.7 Malware Detector

**Prefix**: `/api/v1/malware` · **Source**: `suite-attack/api/malware_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/malware/scan/content` | Scan file content for malware |
| `POST` | `/api/v1/malware/scan/files` | Scan multiple files |
| `GET` | `/api/v1/malware/signatures` | List malware signatures |
| `GET` | `/api/v1/malware/status` | Engine status |

#### 3.1.8 LLM Monitor

**Prefix**: `/api/v1/llm-monitor` · **Source**: `suite-core/api/llm_monitor_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/llm-monitor/analyze` | Analyze prompt for injection/jailbreak |
| `POST` | `/api/v1/llm-monitor/scan/prompt` | Scan a specific prompt |
| `GET` | `/api/v1/llm-monitor/patterns` | List detection patterns |
| `GET` | `/api/v1/llm-monitor/status` | Engine status |

---

### 3.2 Scanner Ingest — 25+ Third-Party Parsers [V7]

**Prefix**: `/api/v1/scanner-ingest` · **Source**: `suite-api/apps/api/scanner_ingest_router.py`
**Parser Engine**: `suite-core/core/scanner_parsers.py` (700 LOC, 15 normalizers)

Import reports from any third-party scanner. ALdeci normalizes all findings into its Universal Finding Format (UFF).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scanner-ingest/upload` | Upload a scanner report file (JSON, XML, SARIF) |
| `POST` | `/api/v1/scanner-ingest/webhook/{scanner_type}` | Receive webhook from a scanner |
| `POST` | `/api/v1/scanner-ingest/detect` | Auto-detect scanner format |
| `GET` | `/api/v1/scanner-ingest/supported` | List supported scanner formats |
| `GET` | `/api/v1/scanner-ingest/stats` | Ingestion statistics |
| `GET` | `/api/v1/scanner-ingest/health` | Health check |
| `GET` | `/api/v1/scanner-ingest/status` | Status |

**Supported scanners**: ZAP, Burp Suite, Nessus, Qualys, Checkmarx, Fortify, Veracode, Snyk, SonarQube, Semgrep, Trivy, Grype, Dependabot, Bandit, ESLint Security, Anchore, Aqua, Prisma Cloud, AWS Inspector, Nuclei, GitLeaks, TruffleHog, Hadolint, Tfsec, Checkov.

**Example — Upload a ZAP report:**

```bash
curl -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@zap-baseline-report.json" \
  -F "scanner_type=zap" \
  -F "app_id=myapp-001"
```

```json
{
  "status": "ingested",
  "scanner": "zap",
  "findings_parsed": 47,
  "findings_deduplicated": 31,
  "app_id": "myapp-001",
  "ingest_id": "ing-a1b2c3"
}
```

---

### 3.3 Threat Intelligence Feeds [V3]

**Prefix**: `/api/v1/feeds` · **Source**: `suite-feeds/api/feeds_router.py` · **31 endpoints**

Real-time vulnerability intelligence from 6 authoritative sources.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/feeds/epss` | Get EPSS exploitation probability scores |
| `POST` | `/api/v1/feeds/epss/refresh` | Refresh EPSS feed from FIRST.org |
| `GET` | `/api/v1/feeds/kev` | Get CISA Known Exploited Vulnerabilities |
| `POST` | `/api/v1/feeds/kev/refresh` | Refresh KEV feed from CISA |
| `POST` | `/api/v1/feeds/nvd/refresh` | Refresh NVD vulnerability database |
| `GET` | `/api/v1/feeds/nvd/recent` | Get recent NVD CVEs |
| `GET` | `/api/v1/feeds/nvd/{cve_id}` | Lookup specific CVE in NVD |
| `POST` | `/api/v1/feeds/exploitdb/refresh` | Refresh ExploitDB feed |
| `POST` | `/api/v1/feeds/osv/refresh` | Refresh OSV (open-source vuln) feed |
| `POST` | `/api/v1/feeds/github/refresh` | Refresh GitHub Security Advisories |
| `GET` | `/api/v1/feeds/exploits` | List all known exploits |
| `GET` | `/api/v1/feeds/exploits/{cve_id}` | Get exploits for a specific CVE |
| `POST` | `/api/v1/feeds/exploits` | Add exploit intelligence |
| `GET` | `/api/v1/feeds/threat-actors` | List threat actor mappings |
| `GET` | `/api/v1/feeds/threat-actors/{cve_id}` | Get threat actors for a CVE |
| `GET` | `/api/v1/feeds/threat-actors/by-actor/{actor}` | Get CVEs by threat actor |
| `POST` | `/api/v1/feeds/threat-actors` | Add threat actor mapping |
| `GET` | `/api/v1/feeds/supply-chain` | List supply chain vulnerabilities |
| `GET` | `/api/v1/feeds/supply-chain/{package}` | Get vulns for a package |
| `POST` | `/api/v1/feeds/supply-chain` | Add supply chain vulnerability |
| `GET` | `/api/v1/feeds/exploit-confidence/{cve_id}` | Get exploit confidence score |
| `GET` | `/api/v1/feeds/geo-risk/{cve_id}` | Get geo-weighted risk assessment |
| `POST` | `/api/v1/feeds/enrich` | Enrich findings with all feed sources |
| `GET` | `/api/v1/feeds/stats` | Feed statistics |
| `GET` | `/api/v1/feeds/categories` | List feed categories |
| `GET` | `/api/v1/feeds/sources` | List feed sources |
| `GET` | `/api/v1/feeds/health` | Feed health status |
| `GET` | `/api/v1/feeds/status` | Feed status |
| `GET` | `/api/v1/feeds/scheduler/status` | Feed scheduler status |
| `POST` | `/api/v1/feeds/refresh` | Trigger feed refresh |
| `POST` | `/api/v1/feeds/refresh/all` | Refresh all feeds simultaneously |

**Example — Enrich findings with threat intelligence:**

```bash
curl -X POST http://localhost:8000/api/v1/feeds/enrich \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_ids": ["CVE-2024-3094", "CVE-2023-44487"],
    "sources": ["nvd", "epss", "kev", "exploitdb"]
  }'
```

```json
{
  "enrichments": [
    {
      "cve_id": "CVE-2024-3094",
      "cvss": 10.0,
      "epss": 0.971,
      "in_kev": true,
      "exploits_available": 3,
      "threat_actors": ["state-sponsored"],
      "recommendation": "PATCH_IMMEDIATELY"
    }
  ]
}
```

---

### 3.4 Knowledge Graph [V3]

**Prefix**: `/api/v1/knowledge-graph` · **Source**: `suite-core/api/knowledge_graph_router.py` · **10 endpoints**

Build and query a security knowledge graph connecting assets, findings, CVEs, and attack paths.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/knowledge-graph/ingest` | Ingest data into the knowledge graph |
| `POST` | `/api/v1/knowledge-graph/dependency` | Add dependency relationship |
| `POST` | `/api/v1/knowledge-graph/attack-paths` | Compute attack paths |
| `POST` | `/api/v1/knowledge-graph/blast-radius` | Calculate blast radius |
| `GET` | `/api/v1/knowledge-graph/analytics` | Graph analytics and metrics |
| `GET` | `/api/v1/knowledge-graph/export` | Export graph data |
| `GET` | `/api/v1/knowledge-graph/node-types` | List node types |
| `POST` | `/api/v1/knowledge-graph/seed-demo` | Seed demo data |
| `GET` | `/api/v1/knowledge-graph/status` | Graph status |
| `GET` | `/api/v1/knowledge-graph/health` | Health check |

---

### 3.5 Asset Inventory [V1]

**Prefix**: `/api/v1/inventory` · **Source**: `suite-api/apps/api/inventory_router.py`

APP_ID-centric asset management — every finding traces to an application.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/inventory/applications` | List all applications |
| `POST` | `/api/v1/inventory/applications` | Register a new application |
| `GET` | `/api/v1/inventory/applications/{app_id}` | Get application details |
| `PUT` | `/api/v1/inventory/applications/{app_id}` | Update application |
| `DELETE` | `/api/v1/inventory/applications/{app_id}` | Delete application |
| `GET` | `/api/v1/inventory/sbom` | Generate SBOM (CycloneDX/SPDX) |
| `GET` | `/api/v1/inventory/license-compliance` | License compliance check |

---

### 3.6 OSS Tools Integration [V7]

**Prefix**: `/api/v1/oss` · **Source**: `suite-integrations/api/oss_tools.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/oss/scan/comprehensive` | Run comprehensive OSS scan |
| `POST` | `/api/v1/oss/scan/trivy` | Run Trivy vulnerability scan |
| `POST` | `/api/v1/oss/scan/grype` | Run Grype SBOM scan |
| `GET` | `/api/v1/oss/status` | OSS tools status |

---

## 4. Validate — MPTE, Pentest & Verification

> **CTEM Phase**: Prove what's actually exploitable — don't just detect, verify.
> **Pillar**: [V5] MPTE Verification

### 4.1 MPTE — Micro Pen-Test Engine [V5]

**Prefix**: `/api/v1/mpte` · **Source**: `suite-attack/api/mpte_router.py` · **23 endpoints**

19-phase deterministic exploit verification engine. Proves exploitability with evidence.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/mpte/verify` | Verify exploitability of a finding |
| `POST` | `/api/v1/mpte/scan/comprehensive` | Run comprehensive MPTE scan |
| `POST` | `/api/v1/mpte/monitoring` | Set up continuous monitoring |
| `GET` | `/api/v1/mpte/requests` | List verification requests |
| `POST` | `/api/v1/mpte/requests` | Create verification request |
| `GET` | `/api/v1/mpte/requests/{request_id}` | Get request details |
| `PUT` | `/api/v1/mpte/requests/{request_id}` | Update request |
| `POST` | `/api/v1/mpte/requests/{request_id}/start` | Start verification |
| `POST` | `/api/v1/mpte/requests/{request_id}/cancel` | Cancel verification |
| `GET` | `/api/v1/mpte/results` | List all results |
| `POST` | `/api/v1/mpte/results` | Create result record |
| `GET` | `/api/v1/mpte/results/by-request/{request_id}` | Get results by request |
| `GET` | `/api/v1/mpte/configs` | List MPTE configurations |
| `POST` | `/api/v1/mpte/configs` | Create MPTE configuration |
| `GET` | `/api/v1/mpte/configs/{config_id}` | Get configuration details |
| `PUT` | `/api/v1/mpte/configs/{config_id}` | Update configuration |
| `DELETE` | `/api/v1/mpte/configs/{config_id}` | Delete configuration |
| `GET` | `/api/v1/mpte/findings/{finding_id}/exploitability` | Get exploitability assessment |
| `GET` | `/api/v1/mpte/verifications` | List all verifications |
| `GET` | `/api/v1/mpte/verifications/{verification_id}` | Get verification detail |
| `GET` | `/api/v1/mpte/stats` | MPTE statistics |
| `GET` | `/api/v1/mpte/health` | Health check |
| `GET` | `/api/v1/mpte/status` | Status |

**Example — Verify a CVE is exploitable:**

```bash
curl -X POST http://localhost:8000/api/v1/mpte/verify \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "finding-abc123",
    "cve_id": "CVE-2024-3094",
    "target": "https://app.example.com",
    "safe_mode": true
  }'
```

```json
{
  "verification_id": "ver-x1y2z3",
  "status": "completed",
  "exploitable": true,
  "confidence": 0.94,
  "phases_completed": 19,
  "evidence": {
    "proof_of_concept": "...",
    "attack_chain": ["recon", "enum", "exploit", "verify"],
    "impact": "Remote Code Execution"
  },
  "signed_evidence_hash": "sha256:a1b2c3..."
}
```

---

### 4.2 Micro-Pentest Runner [V5]

**Prefix**: `/api/v1/micro-pentest` · **Source**: `suite-attack/api/micro_pentest_router.py` · **19 endpoints**

Run micro-pentests with enterprise controls, reporting, and compliance frameworks.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/micro-pentest/run` | Run a micro-pentest |
| `POST` | `/api/v1/micro-pentest/run-async` | Run async micro-pentest |
| `POST` | `/api/v1/micro-pentest/batch` | Run batch pentests |
| `GET` | `/api/v1/micro-pentest/status/{flow_id}` | Get pentest status |
| `GET` | `/api/v1/micro-pentest/enterprise/scans` | List enterprise scans |
| `GET` | `/api/v1/micro-pentest/enterprise/scan/{scan_id}` | Get scan details |
| `POST` | `/api/v1/micro-pentest/enterprise/scan/{scan_id}/cancel` | Cancel a scan |
| `GET` | `/api/v1/micro-pentest/enterprise/audit-logs` | Pentest audit logs |
| `GET` | `/api/v1/micro-pentest/enterprise/health` | Enterprise health |
| `GET` | `/api/v1/micro-pentest/enterprise/attack-vectors` | List attack vectors |
| `GET` | `/api/v1/micro-pentest/enterprise/threat-categories` | Threat categories |
| `GET` | `/api/v1/micro-pentest/enterprise/compliance-frameworks` | Compliance frameworks |
| `GET` | `/api/v1/micro-pentest/enterprise/scan-modes` | Available scan modes |
| `POST` | `/api/v1/micro-pentest/report/generate` | Generate pentest report |
| `GET` | `/api/v1/micro-pentest/report/download` | Download report |
| `GET` | `/api/v1/micro-pentest/report/view` | View report in browser |
| `GET` | `/api/v1/micro-pentest/report/data` | Get raw report data |
| `GET` | `/api/v1/micro-pentest/health` | Health check |
| `GET` | `/api/v1/micro-pentest/status` | Status |

**Example — Run a micro-pentest against a target:**

```bash
curl -X POST http://localhost:8000/api/v1/micro-pentest/run \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://testapp.example.com",
    "scan_type": "owasp_top_10",
    "safe_mode": true,
    "max_duration_seconds": 300
  }'
```

---

### 4.3 Sandbox PoC Verifier [V5]

**Prefix**: `/api/v1/sandbox` · **Source**: `suite-core/core/sandbox_verifier.py` (500 LOC)

Docker-isolated exploit verification with self-correction.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/sandbox/verify` | Verify exploit in sandboxed Docker container |
| `POST` | `/api/v1/sandbox/verify-finding` | Verify a specific finding |
| `GET` | `/api/v1/sandbox/results` | List verification results |
| `GET` | `/api/v1/sandbox/stats` | Sandbox statistics |
| `GET` | `/api/v1/sandbox/health` | Health check |

**Isolation Model**: Memory-limited (512MB), CPU-limited (1 core), network-controlled, read-only filesystem. Self-corrects `ModuleNotFoundError`, `ConnectionRefused`, and `PermissionDenied`.

---

### 4.4 FAIL Engine — Fault & Attack Injection Layer [V3]

**Prefix**: `/api/v1/fail` · **Source**: `suite-api/apps/api/fail_router.py`

Chaos engineering for AppSec — inject faults, grade team response, generate labeled training data.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/fail/scenarios` | Create a FAIL scenario |
| `GET` | `/api/v1/fail/scenarios` | List FAIL scenarios |
| `GET` | `/api/v1/fail/scenarios/{id}` | Get scenario details |
| `POST` | `/api/v1/fail/scenarios/{id}/execute` | Execute FAIL scenario |
| `GET` | `/api/v1/fail/results` | List FAIL results |
| `GET` | `/api/v1/fail/stats` | FAIL statistics |
| `GET` | `/api/v1/fail/health` | Health check |

---

### 4.5 Attack Simulation [V5]

**Prefix**: `/api/v1/attack-sim` · **Source**: `suite-attack/api/attack_sim_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/attack-sim/scenarios` | Create attack simulation |
| `GET` | `/api/v1/attack-sim/scenarios` | List simulations |
| `POST` | `/api/v1/attack-sim/scenarios/{id}/run` | Execute simulation |
| `GET` | `/api/v1/attack-sim/results` | Get simulation results |
| `GET` | `/api/v1/attack-sim/status` | Status |

---

### 4.6 Vulnerability Discovery [V5]

**Prefix**: `/api/v1/vulns` · **Source**: `suite-attack/api/vuln_discovery_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/vulns` | List discovered vulnerabilities |
| `POST` | `/api/v1/vulns` | Create vulnerability record |
| `GET` | `/api/v1/vulns/{id}` | Get vulnerability details |
| `PUT` | `/api/v1/vulns/{id}` | Update vulnerability |
| `GET` | `/api/v1/vulns/status` | Status |

---

## 5. Remediate — AutoFix, Workflows & Actions

> **CTEM Phase**: Fix it, track it, close it.
> **Pillar**: [V3] Decision Intelligence

### 5.1 AutoFix Engine [V3]

**Prefix**: `/api/v1/autofix` · **Source**: `suite-core/api/autofix_router.py` · **Engine**: `suite-core/core/autofix_engine.py` (1,260 LOC) · **13 endpoints**

AI-powered automated remediation with 10 fix types and confidence-based auto-apply.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/autofix/generate` | Generate a fix for a finding |
| `POST` | `/api/v1/autofix/generate/bulk` | Generate fixes for multiple findings |
| `POST` | `/api/v1/autofix/apply` | Apply fix and create PR |
| `POST` | `/api/v1/autofix/validate` | Validate a generated fix |
| `POST` | `/api/v1/autofix/rollback` | Rollback an applied fix |
| `GET` | `/api/v1/autofix/fixes/{fix_id}` | Get fix details |
| `GET` | `/api/v1/autofix/suggestions/{finding_id}` | Get fix suggestions for a finding |
| `GET` | `/api/v1/autofix/history` | Fix action history |
| `GET` | `/api/v1/autofix/stats` | AutoFix statistics |
| `GET` | `/api/v1/autofix/health` | Health check |
| `GET` | `/api/v1/autofix/status` | Status |
| `GET` | `/api/v1/autofix/fix-types` | List 10 supported fix types |
| `GET` | `/api/v1/autofix/confidence-levels` | Confidence level definitions |

**10 Fix Types**: `CODE_PATCH`, `DEPENDENCY_UPDATE`, `CONFIG_HARDENING`, `IAC_FIX`, `SECRET_ROTATION`, `PERMISSION_FIX`, `INPUT_VALIDATION`, `OUTPUT_ENCODING`, `WAF_RULE`, `CONTAINER_FIX`

**Confidence Levels**: HIGH (>85%, auto-apply) · MEDIUM (60-85%, PR for review) · LOW (<60%, suggestion only)

**Example — Generate an automated fix:**

```bash
curl -X POST http://localhost:8000/api/v1/autofix/generate \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "finding-abc123",
    "fix_type": "CODE_PATCH",
    "auto_apply": false
  }'
```

```json
{
  "fix_id": "fix-xyz789",
  "finding_id": "finding-abc123",
  "fix_type": "CODE_PATCH",
  "confidence": 0.92,
  "confidence_level": "HIGH",
  "patch": {
    "file": "src/auth/login.py",
    "diff": "--- a/src/auth/login.py\n+++ b/src/auth/login.py\n@@ -42,3 +42,5 @@\n-    query = f\"SELECT * FROM users WHERE name='{username}'\"\n+    query = \"SELECT * FROM users WHERE name=?\"\n+    cursor.execute(query, (username,))"
  },
  "status": "ready_to_apply",
  "pr_url": null
}
```

**Example — Apply a fix and create a PR:**

```bash
curl -X POST http://localhost:8000/api/v1/autofix/apply \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fix_id": "fix-xyz789", "create_pr": true, "repo": "org/myapp"}'
```

---

### 5.2 Remediation Tasks [V3]

**Prefix**: `/api/v1/remediation` · **Source**: `suite-api/apps/api/remediation_router.py` · **15 endpoints**

Track remediation from detection to closure with SLA enforcement.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/remediation/tasks` | Create remediation task |
| `GET` | `/api/v1/remediation/tasks` | List remediation tasks |
| `GET` | `/api/v1/remediation/tasks/{task_id}` | Get task details |
| `PUT` | `/api/v1/remediation/tasks/{task_id}/status` | Update task status |
| `PUT` | `/api/v1/remediation/tasks/{task_id}/assign` | Assign task to developer |
| `POST` | `/api/v1/remediation/tasks/{task_id}/verification` | Mark task as verified |
| `PUT` | `/api/v1/remediation/tasks/{task_id}/ticket` | Link external ticket |
| `POST` | `/api/v1/remediation/tasks/{task_id}/autofix` | Trigger AutoFix for task |
| `GET` | `/api/v1/remediation/tasks/{task_id}/autofix/suggestions` | Get autofix suggestions |
| `PUT` | `/api/v1/remediation/tasks/{task_id}/transition` | Transition task state |
| `POST` | `/api/v1/remediation/tasks/{task_id}/verify` | Re-verify after fix |
| `POST` | `/api/v1/remediation/sla/check` | Check SLA compliance |
| `GET` | `/api/v1/remediation/metrics/{org_id}` | Org remediation metrics |
| `GET` | `/api/v1/remediation/metrics` | Global remediation metrics |
| `GET` | `/api/v1/remediation/statuses` | List possible statuses |

**Example — Create a remediation task and assign it:**

```bash
curl -X POST http://localhost:8000/api/v1/remediation/tasks \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "finding-abc123",
    "title": "Fix SQL injection in login endpoint",
    "severity": "CRITICAL",
    "assignee": "dev@company.com",
    "sla_hours": 24
  }'
```

---

### 5.3 Workflows & Automation [V3]

**Prefix**: `/api/v1/workflows` · **Source**: `suite-api/apps/api/workflows_router.py` · **13 endpoints**

Orchestrate multi-step remediation workflows with SLA tracking.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/workflows` | List workflows (paginated) |
| `POST` | `/api/v1/workflows` | Create workflow |
| `GET` | `/api/v1/workflows/{id}` | Get workflow details |
| `PUT` | `/api/v1/workflows/{id}` | Update workflow |
| `DELETE` | `/api/v1/workflows/{id}` | Delete workflow |
| `POST` | `/api/v1/workflows/{id}/execute` | Execute workflow |
| `GET` | `/api/v1/workflows/{id}/history` | Execution history |
| `GET` | `/api/v1/workflows/rules` | List automation rules |
| `PUT` | `/api/v1/workflows/{id}/sla` | Set SLA for workflow |
| `GET` | `/api/v1/workflows/{id}/sla` | Get SLA status |
| `POST` | `/api/v1/workflows/executions/{exec_id}/pause` | Pause execution |
| `POST` | `/api/v1/workflows/executions/{exec_id}/resume` | Resume execution |
| `GET` | `/api/v1/workflows/executions/{exec_id}/timeline` | Execution timeline |

---

### 5.4 Connectors — Jira, GitHub, Slack [V1]

**Prefix**: `/api/v1/connectors` · **Source**: `suite-api/apps/api/connectors_router.py`

Fan-out remediation actions to external tools.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/connectors/jira/create-issue` | Create Jira ticket for finding |
| `POST` | `/api/v1/connectors/github/create-issue` | Create GitHub issue |
| `POST` | `/api/v1/connectors/slack/notify` | Send Slack notification |
| `GET` | `/api/v1/connectors/status` | Connector health status |

---

### 5.5 Integrations Management [V7]

**Prefix**: `/api/v1/integrations` · **Source**: `suite-integrations/api/integrations_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/integrations` | List integrations (paginated, filterable) |
| `POST` | `/api/v1/integrations` | Create integration |
| `GET` | `/api/v1/integrations/{id}` | Get integration details |
| `PUT` | `/api/v1/integrations/{id}` | Update integration |
| `DELETE` | `/api/v1/integrations/{id}` | Delete integration |
| `POST` | `/api/v1/integrations/{id}/sync` | Sync integration |
| `POST` | `/api/v1/integrations/{id}/test` | Test connection |

---

## 6. Comply — Evidence, Compliance & Audit

> **CTEM Phase**: Prove you're secure to auditors — cryptographically.
> **Pillar**: [V10] CTEM Full Loop with Crypto

### 6.1 Evidence Engine [V10]

**Prefix**: `/api/v1/evidence` · **Source**: `suite-evidence-risk/api/evidence_router.py` · **13 endpoints**

Generate, sign, and verify compliance evidence bundles with RSA-SHA256 cryptographic signatures.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/evidence/` | List evidence records |
| `GET` | `/api/v1/evidence/{release}` | Get evidence for a release |
| `GET` | `/api/v1/evidence/stats` | Evidence statistics |
| `GET` | `/api/v1/evidence/bundles` | List evidence bundles |
| `POST` | `/api/v1/evidence/bundles/generate` | Generate evidence bundle |
| `GET` | `/api/v1/evidence/bundles/{bundle_id}/download` | Download evidence bundle |
| `POST` | `/api/v1/evidence/verify` | Verify evidence cryptographic signature |
| `GET` | `/api/v1/evidence/compliance-status` | Overall compliance status |
| `POST` | `/api/v1/evidence/{bundle_id}/collect` | Collect evidence for bundle |
| `POST` | `/api/v1/evidence/export` | Export evidence (PDF/CSV/JSON) |
| `POST` | `/api/v1/evidence/export/verify` | Verify exported evidence integrity |
| `GET` | `/api/v1/evidence/export/status` | Export job status |
| `POST` | `/api/v1/evidence/sign` | Sign evidence with RSA-SHA256 |

**Example — Generate a signed evidence bundle for SOC2:**

```bash
curl -X POST http://localhost:8000/api/v1/evidence/bundles/generate \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "framework": "SOC2",
    "app_id": "myapp-001",
    "period": "2026-Q1",
    "sign": true
  }'
```

```json
{
  "bundle_id": "bun-a1b2c3",
  "framework": "SOC2",
  "controls_mapped": 42,
  "evidence_items": 156,
  "signature": "RSA-SHA256:a1b2c3d4...",
  "signed_at": "2026-03-01T12:00:00Z",
  "download_url": "/api/v1/evidence/bundles/bun-a1b2c3/download"
}
```

**Example — Verify evidence integrity:**

```bash
curl -X POST http://localhost:8000/api/v1/evidence/verify \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "bundle_id": "bun-a1b2c3",
    "signature": "RSA-SHA256:a1b2c3d4..."
  }'
```

---

### 6.2 Compliance Engine [V10]

**Prefix**: `/api/v1/compliance-engine` · **Source**: `suite-evidence-risk/api/compliance_engine_router.py` · **9 endpoints**

Map findings to compliance frameworks (SOC2, PCI-DSS, HIPAA, GDPR, ISO 27001).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/compliance-engine/status` | Compliance engine status |
| `GET` | `/api/v1/compliance-engine/frameworks` | List supported frameworks |
| `POST` | `/api/v1/compliance-engine/map-findings` | Map findings to framework controls |
| `POST` | `/api/v1/compliance-engine/assess` | Assess compliance for a framework |
| `POST` | `/api/v1/compliance-engine/assess-all` | Assess all frameworks |
| `GET` | `/api/v1/compliance-engine/gaps` | List compliance gaps |
| `GET` | `/api/v1/compliance-engine/audit-bundle` | Generate audit-ready bundle |
| `GET` | `/api/v1/compliance-engine/cwe-mapping/{cwe_id}` | Map CWE to framework controls |
| `GET` | `/api/v1/compliance-engine/control/{control_id}` | Get control details |

**Example — Assess compliance against SOC2:**

```bash
curl -X POST http://localhost:8000/api/v1/compliance-engine/assess \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"framework": "SOC2", "app_id": "myapp-001"}'
```

```json
{
  "framework": "SOC2",
  "overall_score": 0.87,
  "controls_total": 64,
  "controls_met": 56,
  "controls_partial": 5,
  "controls_failed": 3,
  "gaps": [
    {"control": "CC6.1", "status": "failed", "finding_count": 2}
  ]
}
```

---

### 6.3 Risk Scoring [V3]

**Prefix**: `/api/v1/risk` · **Source**: `suite-evidence-risk/api/risk_router.py`

Multi-factor risk scoring combining CVSS, EPSS, business context, and exploitability.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/risk/calculate` | Calculate risk score for a finding |
| `POST` | `/api/v1/risk/calculate/bulk` | Bulk risk calculation |
| `GET` | `/api/v1/risk/trends` | Risk trend analysis |
| `GET` | `/api/v1/risk/summary` | Risk summary dashboard |
| `GET` | `/api/v1/risk/status` | Status |

---

### 6.4 Audit Trail [V10]

**Prefix**: `/api/v1/audit` · **Source**: `suite-api/apps/api/audit_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/audit/logs` | Query audit logs |
| `GET` | `/api/v1/audit/logs/{id}` | Get audit log entry |
| `POST` | `/api/v1/audit/export` | Export audit logs |
| `GET` | `/api/v1/audit/stats` | Audit statistics |

---

### 6.5 Provenance Tracking [V10]

**Prefix**: `/api/v1/provenance` · **Source**: `suite-evidence-risk/api/provenance_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/provenance/record` | Record provenance event |
| `GET` | `/api/v1/provenance/chain/{artifact_id}` | Get provenance chain |
| `GET` | `/api/v1/provenance/verify/{artifact_id}` | Verify provenance integrity |
| `GET` | `/api/v1/provenance/status` | Status |

---

## 7. Intelligence — Brain Pipeline, Analytics & AI

> **CTEM Phase**: The brain that powers all decisions.
> **Pillar**: [V3] Decision Intelligence · [V7] MCP-Native

### 7.1 Brain Pipeline — 12-Step CTEM Engine [V3]

**Prefix**: `/api/v1/brain` · **Source**: `suite-core/api/brain_router.py` + `pipeline_router.py` · **Engine**: `suite-core/core/brain_pipeline.py` (1,000 LOC) · **30 endpoints**

The core decision engine — 12 steps from ingestion to evidence.

#### Knowledge Graph Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/brain/nodes` | Create/update node in knowledge graph |
| `GET` | `/api/v1/brain/nodes` | Query nodes with filters |
| `GET` | `/api/v1/brain/nodes/{node_id}` | Get specific node |
| `DELETE` | `/api/v1/brain/nodes/{node_id}` | Delete node |
| `POST` | `/api/v1/brain/edges` | Create/update edge relationship |
| `GET` | `/api/v1/brain/all-edges` | List all edges |
| `GET` | `/api/v1/brain/edges/{node_id}` | Get edges for a node |
| `DELETE` | `/api/v1/brain/edges` | Delete edge |
| `GET` | `/api/v1/brain/neighbors/{node_id}` | Get neighbors (N-hop traversal) |
| `GET` | `/api/v1/brain/paths` | Find paths between nodes |
| `GET` | `/api/v1/brain/most-connected` | Highest-degree nodes |
| `GET` | `/api/v1/brain/risk/{node_id}` | Calculate node risk score |

#### Ingestion

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/brain/ingest/cve` | Ingest CVE into knowledge graph |
| `POST` | `/api/v1/brain/ingest/finding` | Ingest finding |
| `POST` | `/api/v1/brain/ingest/scan` | Ingest scan result |
| `POST` | `/api/v1/brain/ingest/asset` | Ingest asset |
| `POST` | `/api/v1/brain/ingest/remediation` | Ingest remediation task |

#### Pipeline Execution

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/brain/pipeline/run` | Execute full 12-step pipeline |
| `POST` | `/api/v1/brain/pipeline/run-async` | Execute pipeline asynchronously |
| `GET` | `/api/v1/brain/pipeline/runs` | List past pipeline runs |
| `GET` | `/api/v1/brain/pipeline/runs/{id}` | Get run details |
| `POST` | `/api/v1/brain/evidence/generate` | Generate evidence pack |
| `GET` | `/api/v1/brain/evidence/packs` | List evidence packs |
| `GET` | `/api/v1/brain/evidence/packs/{id}` | Get evidence pack |

#### Metadata & Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/brain/meta/entity-types` | List entity types |
| `GET` | `/api/v1/brain/meta/edge-types` | List edge types |
| `GET` | `/api/v1/brain/events` | Recent events |
| `GET` | `/api/v1/brain/stats` | Graph statistics |
| `GET` | `/api/v1/brain/health` | Health check |
| `GET` | `/api/v1/brain/status` | Status |

**Example — Execute the full 12-step brain pipeline:**

```bash
curl -X POST http://localhost:8000/api/v1/brain/pipeline/run \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_id": "myapp-001",
    "steps": ["connect","normalize","resolve_identity","deduplicate",
              "build_graph","enrich_threats","score_risk","apply_policy",
              "llm_consensus","micro_pentest","run_playbooks","generate_evidence"]
  }'
```

```json
{
  "run_id": "run-abc123",
  "status": "completed",
  "steps_completed": 12,
  "duration_ms": 4200,
  "results": {
    "findings_ingested": 1200,
    "deduplicated_to": 340,
    "exploitable_confirmed": 12,
    "auto_fixed": 8,
    "evidence_bundle_id": "bun-xyz789"
  }
}
```

---

### 7.2 Analytics & Dashboard [V3]

**Prefix**: `/api/v1/analytics` · **Source**: `suite-api/apps/api/analytics_router.py` · **23 endpoints**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/analytics/dashboard/overview` | Dashboard overview metrics |
| `GET` | `/api/v1/analytics/dashboard/trends` | Trend data over time |
| `GET` | `/api/v1/analytics/dashboard/top-risks` | Top risk findings |
| `GET` | `/api/v1/analytics/dashboard/compliance-status` | Compliance dashboard |
| `GET` | `/api/v1/analytics/findings` | List all findings (paginated) |
| `POST` | `/api/v1/analytics/findings` | Create finding |
| `GET` | `/api/v1/analytics/findings/{id}` | Get finding details |
| `PUT` | `/api/v1/analytics/findings/{id}` | Update finding |
| `GET` | `/api/v1/analytics/decisions` | List decisions |
| `POST` | `/api/v1/analytics/decisions` | Create decision |
| `GET` | `/api/v1/analytics/mttr` | Mean time to remediate |
| `GET` | `/api/v1/analytics/coverage` | Security coverage metrics |
| `GET` | `/api/v1/analytics/roi` | ROI calculations |
| `GET` | `/api/v1/analytics/noise-reduction` | Noise reduction metrics |
| `POST` | `/api/v1/analytics/custom-query` | Run custom analytics query |
| `GET` | `/api/v1/analytics/export` | Export analytics data |
| `GET` | `/api/v1/analytics/stats` | Overall statistics |
| `GET` | `/api/v1/analytics/summary` | Summary dashboard |
| `GET` | `/api/v1/analytics/trends/severity-over-time` | Severity trends |
| `GET` | `/api/v1/analytics/trends/anomalies` | Anomaly detection |
| `GET` | `/api/v1/analytics/compare` | Compare time periods |
| `GET` | `/api/v1/analytics/triage-funnel` | Triage funnel metrics |
| `GET` | `/api/v1/analytics/risk-velocity` | Risk velocity tracking |

**Example — Get dashboard overview:**

```bash
curl -s http://localhost:8000/api/v1/analytics/dashboard/overview \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | python3 -m json.tool
```

```json
{
  "total_findings": 11300,
  "actionable_findings": 340,
  "noise_reduction_pct": 97.0,
  "critical_count": 12,
  "high_count": 45,
  "mttr_hours": 14.5,
  "coverage_pct": 87.3,
  "last_scan": "2026-03-01T11:30:00Z"
}
```

---

### 7.3 MCP Gateway — AI Agent Platform [V7]

**Prefix**: `/api/v1/mcp` · **Source**: `suite-api/apps/api/mcp_router.py` · **7 endpoints**

Model Context Protocol — makes ALdeci the first AppSec platform AI agents can programmatically use.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/mcp/tools` | List all MCP-available tools (auto-discovered) |
| `GET` | `/api/v1/mcp/tools/{tool_name}` | Get tool schema definition |
| `POST` | `/api/v1/mcp/execute` | Execute an MCP tool |
| `GET` | `/api/v1/mcp/schemas` | OpenAPI schemas for all tools |
| `GET` | `/api/v1/mcp/health` | MCP gateway health |
| `GET` | `/api/v1/mcp/stats` | MCP usage statistics |
| `POST` | `/api/v1/mcp/refresh` | Refresh tool catalog |

**Example — List available MCP tools:**

```bash
curl -s http://localhost:8000/api/v1/mcp/tools \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | python3 -m json.tool
```

**Example — Execute an MCP tool:**

```bash
curl -X POST http://localhost:8000/api/v1/mcp/execute \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "analytics_get_findings",
    "parameters": {"severity": "CRITICAL", "limit": 10}
  }'
```

---

### 7.4 MCP Protocol Server [V7]

**Prefix**: `/api/v1/mcp-protocol` · **Source**: `suite-core/api/mcp_protocol_router.py` · **8 endpoints**

Low-level MCP protocol implementation for agent-to-agent communication.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/mcp-protocol/status` | Protocol server status |
| `POST` | `/api/v1/mcp-protocol/initialize` | Initialize MCP session |
| `POST` | `/api/v1/mcp-protocol/tools/list` | List available tools |
| `POST` | `/api/v1/mcp-protocol/tools/call` | Call a tool |
| `POST` | `/api/v1/mcp-protocol/resources/list` | List resources |
| `POST` | `/api/v1/mcp-protocol/resources/read` | Read a resource |
| `POST` | `/api/v1/mcp-protocol/prompts/list` | List prompts |
| `GET` | `/api/v1/mcp-protocol/health` | Health check |

---

### 7.5 AI Copilot Agents [V3]

**Prefix**: `/api/v1/copilot/agents` · **Source**: `suite-core/api/agents_router.py` · **32 endpoints**

Specialized AI agents for security analysis, triage, and remediation.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/copilot/agents/analyst/analyze` | AI-powered vulnerability analysis |
| `POST` | `/api/v1/copilot/agents/analyst/threat-intel` | Threat intelligence assessment |
| `POST` | `/api/v1/copilot/agents/analyst/prioritize` | AI-driven prioritization |
| `POST` | `/api/v1/copilot/agents/analyst/attack-path` | Attack path analysis |
| `POST` | `/api/v1/copilot/agents/compliance/check` | Compliance check |
| `POST` | `/api/v1/copilot/agents/pentest/plan` | Generate pentest plan |
| `POST` | `/api/v1/copilot/agents/remediation/suggest` | Suggest remediation |
| `GET` | `/api/v1/copilot/agents/status` | Agent pool status |

---

### 7.6 Exposure Cases [V3]

**Prefix**: `/api/v1/cases` · **Source**: `suite-core/api/exposure_case_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/cases` | List exposure cases |
| `POST` | `/api/v1/cases` | Create exposure case |
| `GET` | `/api/v1/cases/{id}` | Get case details |
| `PUT` | `/api/v1/cases/{id}` | Update case |
| `DELETE` | `/api/v1/cases/{id}` | Close case |

---

### 7.7 Deduplication Engine [V3]

**Prefix**: `/api/v1/deduplication` · **Source**: `suite-core/api/deduplication_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/deduplication/run` | Run deduplication on findings |
| `GET` | `/api/v1/deduplication/stats` | Deduplication statistics |
| `GET` | `/api/v1/deduplication/clusters` | View finding clusters |
| `GET` | `/api/v1/deduplication/status` | Status |

---

### 7.8 Predictions & ML [V3]

**Prefix**: `/api/v1/predictions` · **Source**: `suite-core/api/predictions_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/predictions/risk` | Predict risk for finding |
| `POST` | `/api/v1/predictions/exploitability` | Predict exploitability |
| `GET` | `/api/v1/predictions/models` | List ML models |
| `GET` | `/api/v1/predictions/status` | Status |

---

### 7.9 Additional Intelligence Endpoints

#### Algorithmic Scoring

**Prefix**: `/api/v1/algorithms` · **Source**: `suite-core/api/algorithmic_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/algorithms/ssvc` | SSVC decision tree scoring |
| `POST` | `/api/v1/algorithms/epss` | EPSS-based scoring |
| `GET` | `/api/v1/algorithms/status` | Status |

#### LLM Provider Management

**Prefix**: `/api/v1/llm` · **Source**: `suite-core/api/llm_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/llm/providers` | List configured LLM providers |
| `POST` | `/api/v1/llm/analyze` | Send analysis request to LLM |
| `GET` | `/api/v1/llm/status` | LLM service status |

#### Streaming / SSE

**Prefix**: `/api/v1/stream` · **Source**: `suite-core/api/streaming_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/stream/events` | Server-Sent Events stream |
| `GET` | `/api/v1/stream/findings` | Real-time findings stream |
| `GET` | `/api/v1/stream/status` | Status |

---

## 8. Platform — Admin, Users, Teams & System

> **Cross-cutting**: Platform management, health, and configuration.

### 8.1 Health & Status

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Legacy health check (Docker/K8s) |
| `GET` | `/api/v1/health` | No | Health check with version info |
| `GET` | `/api/v1/status` | Yes | Authenticated status |
| `GET` | `/api/v1/search` | Yes | Global search across all entities |

### 8.2 User Management

**Prefix**: `/api/v1/users` · **Scope**: `admin:all`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/users` | List users |
| `POST` | `/api/v1/users` | Create user |
| `GET` | `/api/v1/users/{id}` | Get user details |
| `PUT` | `/api/v1/users/{id}` | Update user |
| `DELETE` | `/api/v1/users/{id}` | Delete user |
| `POST` | `/api/v1/users/login` | Login (returns JWT) |

### 8.3 Team Management

**Prefix**: `/api/v1/teams` · **Scope**: `admin:all`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/teams` | List teams |
| `POST` | `/api/v1/teams` | Create team |
| `GET` | `/api/v1/teams/{id}` | Get team details |
| `PUT` | `/api/v1/teams/{id}` | Update team |
| `DELETE` | `/api/v1/teams/{id}` | Delete team |

### 8.4 Admin

**Prefix**: `/api/v1/admin` · **Scope**: `admin:all`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/admin/users` | Admin user listing (paginated) |
| `POST` | `/api/v1/admin/users` | Admin create user |
| `GET` | `/api/v1/admin/users/{user_id}` | Admin get user |
| `PUT` | `/api/v1/admin/users/{user_id}` | Admin update user |
| `DELETE` | `/api/v1/admin/users/{user_id}` | Admin delete user |
| `GET` | `/api/v1/admin/teams` | Admin team listing |
| `POST` | `/api/v1/admin/teams` | Admin create team |
| `GET` | `/api/v1/admin/teams/{team_id}` | Admin get team |
| `PUT` | `/api/v1/admin/teams/{team_id}` | Admin update team |
| `DELETE` | `/api/v1/admin/teams/{team_id}` | Admin delete team |

### 8.5 System Configuration

**Prefix**: `/api/v1/system` · **Scope**: `admin:all`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/system/info` | System information |
| `GET` | `/api/v1/system/config` | Get system configuration |
| `PUT` | `/api/v1/system/config` | Update system configuration |
| `GET` | `/api/v1/system/health` | Detailed system health |

### 8.6 Auth / SSO

**Prefix**: `/api/v1/auth` · **Scope**: `admin:all`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/auth/sso` | List SSO configurations |
| `POST` | `/api/v1/auth/sso` | Create SSO configuration |
| `GET` | `/api/v1/auth/sso/{id}` | Get SSO config |
| `PUT` | `/api/v1/auth/sso/{id}` | Update SSO config |

### 8.7 Reports

**Prefix**: `/api/v1/reports`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/reports` | List reports |
| `POST` | `/api/v1/reports` | Generate report |
| `GET` | `/api/v1/reports/{id}` | Get report |
| `GET` | `/api/v1/reports/{id}/download` | Download report |

### 8.8 Policies

**Prefix**: `/api/v1/policies` · **Scope**: `write:findings`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/policies` | List security policies |
| `POST` | `/api/v1/policies` | Create policy |
| `GET` | `/api/v1/policies/{id}` | Get policy |
| `PUT` | `/api/v1/policies/{id}` | Update policy |
| `DELETE` | `/api/v1/policies/{id}` | Delete policy |

### 8.9 Webhooks

**Prefix**: `/api/v1/webhooks` · **Source**: `suite-integrations/api/webhooks_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/webhooks` | List webhook subscriptions |
| `POST` | `/api/v1/webhooks` | Create webhook |
| `PUT` | `/api/v1/webhooks/{id}` | Update webhook |
| `DELETE` | `/api/v1/webhooks/{id}` | Delete webhook |
| `POST` | `/api/v1/webhooks/{id}/test` | Test webhook delivery |

### 8.10 Bulk Operations

**Prefix**: `/api/v1/bulk` · **Scope**: `write:findings`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/bulk/import` | Bulk import findings |
| `POST` | `/api/v1/bulk/export` | Bulk export |
| `POST` | `/api/v1/bulk/analyze` | Bulk analysis |

### 8.11 Collaboration

**Prefix**: `/api/v1/collaboration`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/collaboration/comments` | Add comment |
| `GET` | `/api/v1/collaboration/comments` | List comments |
| `POST` | `/api/v1/collaboration/mentions` | Create mention |

### 8.12 Validation

**Prefix**: `/api/v1/validate` · **Source**: `suite-api/apps/api/validation_router.py` (or `suite-core/api/validation_router.py`, 492 LOC)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/validate/sarif` | Validate SARIF format |
| `POST` | `/api/v1/validate/sbom` | Validate SBOM format |
| `POST` | `/api/v1/validate/cve` | Validate CVE format |
| `POST` | `/api/v1/validate/vex` | Validate VEX format |

### 8.13 Marketplace

**Prefix**: `/api/v1/marketplace`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/marketplace/browse` | Browse marketplace |
| `GET` | `/api/v1/marketplace/recommendations` | Get recommendations |
| `GET` | `/api/v1/marketplace/items/{item_id}` | Get marketplace item |
| `GET` | `/api/v1/marketplace/packs/{framework}/{control}` | Get remediation pack |

---

## 9. Error Codes

All error responses follow this structure:

```json
{
  "detail": "Human-readable error message",
  "status_code": 400,
  "error_code": "VALIDATION_ERROR"
}
```

| HTTP Code | Error Code | Description |
|-----------|-----------|-------------|
| `400` | `VALIDATION_ERROR` | Invalid request body or parameters |
| `401` | `UNAUTHORIZED` | Missing or invalid API key / JWT |
| `403` | `FORBIDDEN` | Insufficient scope for operation |
| `404` | `NOT_FOUND` | Resource not found |
| `409` | `CONFLICT` | Duplicate resource or state conflict |
| `422` | `UNPROCESSABLE_ENTITY` | Semantic validation failure |
| `429` | `RATE_LIMITED` | Rate limit exceeded |
| `500` | `INTERNAL_ERROR` | Server error |
| `503` | `SERVICE_UNAVAILABLE` | Dependent service unavailable |

---

## 10. Rate Limits

| Tier | Rate Limit | Burst |
|------|-----------|-------|
| Community | 100 req/min | 20 req/s |
| Professional | 1,000 req/min | 50 req/s |
| Enterprise | 10,000 req/min | 200 req/s |
| Air-Gapped | Unlimited | Unlimited |

Rate limit headers are included in every response:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 998
X-RateLimit-Reset: 1709300000
```

Disable rate limiting for development:
```bash
export FIXOPS_DISABLE_RATE_LIMIT=1
```

---

## Appendix A: Endpoint Count by CTEM Phase

| Phase | Category | Endpoints |
|-------|----------|-----------|
| **Discover** | 8 Native Scanners | ~36 |
| **Discover** | Scanner Ingest (25 parsers) | 7 |
| **Discover** | Threat Intelligence Feeds | 31 |
| **Discover** | Knowledge Graph | 10 |
| **Discover** | Asset Inventory | 7 |
| **Discover** | OSS Tools | 4 |
| **Validate** | MPTE Engine | 23 |
| **Validate** | Micro-Pentest | 19 |
| **Validate** | Sandbox PoC | 5 |
| **Validate** | FAIL Engine | 7 |
| **Validate** | Attack Simulation | 5 |
| **Validate** | Vulnerability Discovery | 5 |
| **Remediate** | AutoFix Engine | 13 |
| **Remediate** | Remediation Tasks | 15 |
| **Remediate** | Workflows | 13 |
| **Remediate** | Connectors | 4 |
| **Remediate** | Integrations | 7 |
| **Comply** | Evidence Engine | 13 |
| **Comply** | Compliance Engine | 9 |
| **Comply** | Risk Scoring | 5 |
| **Comply** | Audit Trail | 4 |
| **Comply** | Provenance | 4 |
| **Intelligence** | Brain Pipeline | 30 |
| **Intelligence** | Analytics | 23 |
| **Intelligence** | MCP Gateway | 7 |
| **Intelligence** | MCP Protocol | 8 |
| **Intelligence** | AI Copilot | 32 |
| **Intelligence** | Exposure Cases | 5 |
| **Intelligence** | Deduplication | 4 |
| **Intelligence** | Predictions | 4 |
| **Intelligence** | Algorithms, LLM, SSE | ~10 |
| **Platform** | Users, Teams, Admin | ~25 |
| **Platform** | Auth, System, Health | ~12 |
| **Platform** | Reports, Policies, Webhooks | ~15 |
| **Platform** | Bulk, Collab, Validation, Marketplace | ~15 |
| **Platform** | Additional routers | ~50+ |
| | **Total** | **~704** |

---

## Appendix B: Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_MODE` | `enterprise` | Operating mode |
| `FIXOPS_API_TOKEN` | — | API authentication key |
| `FIXOPS_JWT_SECRET` | auto-generated | JWT signing secret |
| `FIXOPS_JWT_EXP_MINUTES` | `120` | JWT token expiry (minutes) |
| `FIXOPS_DATA_DIR` | `.fixops_data` | Data storage directory |
| `FIXOPS_DISABLE_RATE_LIMIT` | `0` | Set to `1` to disable rate limiting |
| `FIXOPS_ALLOWED_ORIGINS` | — | CORS allowed origins |
| `MPTE_BASE_URL` | `https://localhost:8443` | MPTE service URL |
| `OPENAI_API_KEY` | — | OpenAI LLM provider key |
| `ANTHROPIC_API_KEY` | — | Anthropic LLM provider key |
| `GOOGLE_API_KEY` | — | Google Gemini LLM provider key |

---

## Appendix C: Supported Scanner Formats

| Scanner | Format | Ingest Endpoint |
|---------|--------|-----------------|
| OWASP ZAP | JSON, XML | `/api/v1/scanner-ingest/upload` |
| Burp Suite | XML, JSON | `/api/v1/scanner-ingest/upload` |
| Nessus | `.nessus` XML | `/api/v1/scanner-ingest/upload` |
| Qualys | XML | `/api/v1/scanner-ingest/upload` |
| Checkmarx | XML, SARIF | `/api/v1/scanner-ingest/upload` |
| Fortify | FPR, XML | `/api/v1/scanner-ingest/upload` |
| Veracode | XML, JSON | `/api/v1/scanner-ingest/upload` |
| Snyk | JSON | `/api/v1/scanner-ingest/webhook/snyk` |
| SonarQube | JSON | `/api/v1/scanner-ingest/webhook/sonarqube` |
| Semgrep | JSON, SARIF | `/api/v1/scanner-ingest/upload` |
| Trivy | JSON | `/api/v1/scanner-ingest/upload` |
| Grype | JSON | `/api/v1/scanner-ingest/upload` |
| Dependabot | JSON | `/api/v1/scanner-ingest/webhook/dependabot` |
| Bandit | JSON | `/api/v1/scanner-ingest/upload` |
| ESLint Security | JSON | `/api/v1/scanner-ingest/upload` |
| Anchore | JSON | `/api/v1/scanner-ingest/upload` |
| Aqua | JSON | `/api/v1/scanner-ingest/upload` |
| Prisma Cloud | JSON | `/api/v1/scanner-ingest/webhook/prisma` |
| AWS Inspector | JSON | `/api/v1/scanner-ingest/upload` |
| Nuclei | JSONL | `/api/v1/scanner-ingest/upload` |
| GitLeaks | JSON | `/api/v1/scanner-ingest/upload` |
| TruffleHog | JSON | `/api/v1/scanner-ingest/upload` |
| Hadolint | JSON | `/api/v1/scanner-ingest/upload` |
| Tfsec | JSON | `/api/v1/scanner-ingest/upload` |
| Checkov | JSON | `/api/v1/scanner-ingest/upload` |

---

*Generated by ALdeci Technical Writer Agent · 2026-03-01 · Pillar [V3][V5][V7][V10]*
*Source of truth: `suite-api/apps/api/app.py` (2,737 LOC, 34 router mounts) + 64 router files across 6 suites*
