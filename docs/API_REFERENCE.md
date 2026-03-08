# ALdeci CTEM+ API Reference

> **Version**: 5.0 — Post-Demo Hardened Edition (Sprint 2, Day 4+)
> **Last updated**: 2026-03-07
> **Base URL**: `http://localhost:8000`
> **Total endpoints**: 784 across 72 router files + 2 dynamic routers + 25 inline @app (verified via grep 2026-03-07)
> **Total routes mounted**: 784 routes, 77+ unique prefixes
> **Suites**: suite-api (238) · suite-core (256) · suite-attack (106) · suite-feeds (31) · suite-evidence-risk (56) · suite-integrations (59) · sandbox (8) · logs (5) · inline @app (25)
> **Authentication**: API Key (`X-API-Key` header) or JWT Bearer token
> **OpenAPI Spec**: `GET /openapi.json` (verified 200 OK)
> **Pillar**: [V3] Decision Intelligence · [V5] MPTE Verification · [V7] MCP-Native · [V10] CTEM Full Loop
> **Security**: All endpoints hardened — Pydantic v2 validation, path traversal prevention, size limits, injection guards (Sprint 2)
> **CTEM+ Identity**: ALdeci is a complete CTEM+ platform with 8 built-in scanners, 25 third-party parsers, a 12-step Brain Pipeline, and AI-powered AutoFix — see [CTEM+ Identity](CTEM_PLUS_IDENTITY.md)
> **v5.0 changes**: Post-demo endpoint audit (verified 784 via code grep 2026-03-07). +3 new endpoints: Brain `/trends`, MCP Protocol `/stats`, Self-Learning `/stats`. Suite-core 253→256. Validation section corrected. 41+ curl examples. Appendix A reconciled.

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
# Set your API key
export FIXOPS_API_TOKEN="your-enterprise-api-key-here"

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
9. [Vision Engines — Advanced Capabilities](#9-vision-engines--advanced-capabilities)
10. [Error Codes](#10-error-codes)
11. [Rate Limits](#11-rate-limits)

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

ALdeci organizes its 784 endpoints around the **Continuous Threat Exposure Management (CTEM)** lifecycle:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  DISCOVER   │───▶│  VALIDATE   │───▶│  REMEDIATE  │───▶│   COMPLY    │
│             │    │             │    │             │    │             │
│ 8 Scanners  │    │ MPTE 19-ph  │    │ AutoFix 10  │    │ Evidence    │
│ 25 Parsers  │    │ Sandbox PoC │    │ Workflows   │    │ Compliance  │
│ 6 Feeds     │    │ FAIL Engine │    │ Connectors  │    │ Audit Trail │
│ 134 endpts  │    │ 97 endpts   │    │ 78 endpts   │    │ 57 endpts   │

└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
        │                │                  │                   │
        └────────────────┴──────────────────┴───────────────────┘
                              ▲
                    ┌─────────┴──────────┐
                    │   INTELLIGENCE     │
                    │ Brain Pipeline     │
                    │ Knowledge Graph    │
                    │ AI Copilot / MCP   │
                    │ 237 endpoints      │
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

**Prefix**: `/api/v1/inventory` · **Source**: `suite-api/apps/api/inventory_router.py` · **19 endpoints**

APP_ID-centric asset management — every finding traces to an application, component, service, or API.

#### Applications

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/inventory/applications` | List all applications (paginated) |
| `POST` | `/api/v1/inventory/applications` | Register a new application |
| `GET` | `/api/v1/inventory/applications/{id}` | Get application details |
| `PUT` | `/api/v1/inventory/applications/{id}` | Update application |
| `DELETE` | `/api/v1/inventory/applications/{id}` | Delete application |
| `GET` | `/api/v1/inventory/applications/{id}/components` | List application components |
| `GET` | `/api/v1/inventory/applications/{id}/apis` | List application APIs |
| `POST` | `/api/v1/inventory/applications/{id}/dependencies` | Add dependency |
| `GET` | `/api/v1/inventory/applications/{id}/dependencies` | List dependencies |
| `GET` | `/api/v1/inventory/applications/{id}/license-compliance` | License compliance check |
| `GET` | `/api/v1/inventory/applications/{id}/sbom` | Generate SBOM (CycloneDX/SPDX) |

#### Assets, Services & APIs

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/inventory/assets` | List all assets (paginated) |
| `GET` | `/api/v1/inventory/services` | List all services |
| `POST` | `/api/v1/inventory/services` | Register a service |
| `GET` | `/api/v1/inventory/services/{id}` | Get service details |
| `GET` | `/api/v1/inventory/apis` | List all APIs |
| `POST` | `/api/v1/inventory/apis` | Register an API |
| `GET` | `/api/v1/inventory/apis/{id}/security` | Get API security assessment |
| `GET` | `/api/v1/inventory/search` | Search across all inventory |

**Example — Register an application and generate SBOM:**

```bash
# Register an application
curl -X POST http://localhost:8000/api/v1/inventory/applications \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "payment-service", "team": "platform", "criticality": "high"}'

# Generate CycloneDX SBOM for the application
curl -s http://localhost:8000/api/v1/inventory/applications/payment-service/sbom \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | python3 -m json.tool
```

---

### 3.6 OSS Tools Integration [V7]

**Prefix**: `/api/v1/oss` · **Source**: `suite-integrations/api/oss_tools.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/oss/scan/comprehensive` | Run comprehensive OSS scan |
| `POST` | `/api/v1/oss/scan/trivy` | Run Trivy vulnerability scan |
| `POST` | `/api/v1/oss/scan/grype` | Run Grype SBOM scan |
| `GET` | `/api/v1/oss/status` | OSS tools status |

### 3.7 IaC Security Scanner [V9]

**Prefix**: `/api/v1/iac` · **Source**: `suite-integrations/api/iac_router.py` · **7 endpoints**

Scan Infrastructure-as-Code templates for security misconfigurations.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/iac/scan` | Scan IaC template (Terraform, CloudFormation, K8s) |
| `POST` | `/api/v1/iac/scan/terraform` | Scan Terraform files |
| `POST` | `/api/v1/iac/scan/cloudformation` | Scan CloudFormation templates |
| `POST` | `/api/v1/iac/scan/kubernetes` | Scan Kubernetes YAML |
| `GET` | `/api/v1/iac/rules` | List IaC scanning rules |
| `GET` | `/api/v1/iac/health` | Health check |
| `GET` | `/api/v1/iac/status` | Status |

---

### 3.8 IDE Integration [V7]

**Prefix**: `/api/v1/ide` · **Source**: `suite-integrations/api/ide_router.py` · **5 endpoints**

Real-time security feedback in VS Code, JetBrains, and other IDEs.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/ide/scan` | Scan code from IDE context |
| `GET` | `/api/v1/ide/findings/{file_path}` | Get findings for a file |
| `POST` | `/api/v1/ide/fix-suggestion` | Get fix suggestion inline |
| `GET` | `/api/v1/ide/health` | Health check |
| `GET` | `/api/v1/ide/status` | Status |

---

### 3.9 Fuzzy Identity Resolution [V1]

**Prefix**: `/api/v1/identity` · **Source**: `suite-core/api/fuzzy_identity_router.py` · **9 endpoints**

Map findings to APP_ID → Component → Feature using fuzzy matching, string similarity, and ML.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/identity/resolve` | Resolve entity identity |
| `POST` | `/api/v1/identity/match` | Match entities across sources |
| `POST` | `/api/v1/identity/merge` | Merge duplicate identities |
| `GET` | `/api/v1/identity/entities` | List resolved entities |
| `GET` | `/api/v1/identity/entities/{id}` | Get entity details |
| `GET` | `/api/v1/identity/clusters` | View identity clusters |
| `GET` | `/api/v1/identity/stats` | Identity resolution stats |
| `GET` | `/api/v1/identity/health` | Health check |
| `GET` | `/api/v1/identity/status` | Status |

---

### 3.10 Code-to-Cloud Mapping [V1]

**Prefix**: `/api/v1/code-to-cloud` · **Source**: `suite-core/api/code_to_cloud_router.py` · **2 endpoints**

Trace code changes through build → deploy → runtime with full lineage.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/code-to-cloud/map` | Map code artifact to cloud deployment |
| `GET` | `/api/v1/code-to-cloud/status` | Status |

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

**Prefix**: `/api/v1/sandbox` · **Source**: `suite-core/core/sandbox_verifier.py` (500 LOC, dynamic router) · **8 endpoints**

Docker-isolated exploit verification with self-correction and reachability analysis.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/sandbox/verify` | Verify exploit in sandboxed Docker container |
| `POST` | `/api/v1/sandbox/verify-finding` | Verify a specific finding |
| `GET` | `/api/v1/sandbox/results` | List verification results |
| `GET` | `/api/v1/sandbox/stats` | Sandbox statistics |
| `POST` | `/api/v1/sandbox/reachability` | Analyze reachability of a vulnerability path |
| `POST` | `/api/v1/sandbox/reachability/single` | Single-finding reachability check |
| `GET` | `/api/v1/sandbox/health` | Health check |
| `GET` | `/api/v1/sandbox/status` | Status |

**Isolation Model**: Memory-limited (512MB), CPU-limited (1 core), network-controlled, read-only filesystem. Self-corrects `ModuleNotFoundError`, `ConnectionRefused`, and `PermissionDenied`.

**Example — Verify an exploit in a sandboxed container:**

```bash
curl -X POST http://localhost:8000/api/v1/sandbox/verify \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "poc_code": "import requests\nrequests.get(\"http://target/admin\")",
    "language": "python",
    "timeout_seconds": 30,
    "network_access": false
  }'
```

```json
{
  "verification_id": "sandbox-v1x2y3",
  "status": "completed",
  "exploitable": true,
  "exit_code": 0,
  "output": "HTTP 200 — admin panel accessible without auth",
  "execution_time_ms": 1200,
  "isolation": {"memory_mb": 512, "cpu_cores": 1, "network": false}
}
```

---

### 4.4 FAIL Engine — Fault & Attack Injection Layer [V3]

**Prefix**: `/api/v1/fail` · **Source**: `suite-api/apps/api/fail_router.py` · **10 endpoints**

FAIL (Fault & Attack Injection Layer) scoring — chaos engineering for AppSec. Score findings using the FAIL methodology (Feasibility, Attack-surface, Impact, Likelihood), grade team response, generate labeled training data.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/fail/score` | Score a single finding using FAIL methodology |
| `POST` | `/api/v1/fail/score/batch` | Score multiple findings in batch |
| `GET` | `/api/v1/fail/score/{score_id}` | Get a stored FAIL score by ID |
| `GET` | `/api/v1/fail/scores` | List all FAIL scores (paginated) |
| `GET` | `/api/v1/fail/top-risks` | Top risks ranked by FAIL score |
| `GET` | `/api/v1/fail/stats` | FAIL score statistics |
| `GET` | `/api/v1/fail/cve/{cve_id}` | Get FAIL scores for a specific CVE |
| `DELETE` | `/api/v1/fail/score/{score_id}` | Delete a FAIL score |
| `GET` | `/api/v1/fail/health` | FAIL engine health |
| `GET` | `/api/v1/fail/status` | FAIL engine status |

**Example — Score a finding with FAIL methodology:**

```bash
curl -X POST http://localhost:8000/api/v1/fail/score \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "finding-abc123",
    "cve_id": "CVE-2024-3094",
    "context": {"environment": "production", "exposure": "internet-facing"}
  }'
```

```json
{
  "score_id": "fail-x1y2z3",
  "finding_id": "finding-abc123",
  "feasibility": 0.85,
  "attack_surface": 0.92,
  "impact": 0.95,
  "likelihood": 0.88,
  "composite_score": 9.2,
  "risk_level": "CRITICAL"
}
```

---

### 4.5 Attack Simulation [V5]

**Prefix**: `/api/v1/attack-sim` · **Source**: `suite-attack/api/attack_sim_router.py` · **13 endpoints**

Full attack campaign simulation with MITRE ATT&CK mapping, breach impact analysis, and automated recommendations.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/attack-sim/scenarios` | Create attack scenario |
| `POST` | `/api/v1/attack-sim/scenarios/generate` | AI-generate attack scenario |
| `GET` | `/api/v1/attack-sim/scenarios` | List scenarios |
| `GET` | `/api/v1/attack-sim/scenarios/{scenario_id}` | Get scenario details |
| `POST` | `/api/v1/attack-sim/campaigns/run` | Execute attack campaign |
| `GET` | `/api/v1/attack-sim/campaigns` | List campaigns |
| `GET` | `/api/v1/attack-sim/campaigns/{campaign_id}` | Get campaign details |
| `GET` | `/api/v1/attack-sim/campaigns/{campaign_id}/attack-paths` | Get campaign attack paths |
| `GET` | `/api/v1/attack-sim/campaigns/{campaign_id}/breach-impact` | Get breach impact analysis |
| `GET` | `/api/v1/attack-sim/campaigns/{campaign_id}/recommendations` | Get remediation recommendations |
| `GET` | `/api/v1/attack-sim/mitre/heatmap` | MITRE ATT&CK coverage heatmap |
| `GET` | `/api/v1/attack-sim/mitre/techniques` | List MITRE techniques with coverage |
| `GET` | `/api/v1/attack-sim/health` | Health check |

**Example — Run an attack simulation campaign:**

```bash
curl -X POST http://localhost:8000/api/v1/attack-sim/campaigns/run \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scenario_id": "scenario-001",
    "target_app_id": "myapp-001",
    "attack_types": ["sqli", "xss", "ssrf"],
    "safe_mode": true
  }'
```

---

### 4.6 Vulnerability Discovery [V5]

**Prefix**: `/api/v1/vulns` · **Source**: `suite-attack/api/vuln_discovery_router.py` · **11 endpoints**

Zero-day discovery, community contribution, and ML-based vulnerability classification.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/vulns/discovered` | List discovered vulnerabilities (paginated) |
| `POST` | `/api/v1/vulns/discovered` | Report a discovered vulnerability |
| `POST` | `/api/v1/vulns/contribute` | Contribute vulnerability to community DB |
| `GET` | `/api/v1/vulns/internal` | List internal vulnerability assessments |
| `GET` | `/api/v1/vulns/internal/{vuln_id}` | Get internal vuln details |
| `PATCH` | `/api/v1/vulns/internal/{vuln_id}` | Update internal vuln assessment |
| `POST` | `/api/v1/vulns/train` | Trigger ML model retraining |
| `GET` | `/api/v1/vulns/train/{job_id}` | Get training job status |
| `GET` | `/api/v1/vulns/stats` | Discovery statistics |
| `GET` | `/api/v1/vulns/contributions` | List community contributions |
| `GET` | `/api/v1/vulns/health` | Health check |

### 4.7 MPTE Orchestrator — Unified Pentest & Decision API [V5] [V3]

**Prefix**: `/api/v1/mpte-orchestrator` · **Source**: `suite-attack/api/mpte_orchestrator_router.py` · **8 endpoints**

Bridges CLI-side `advanced-pentest` capabilities to the HTTP API surface — threat intelligence, business impact analysis, attack simulation, and remediation guidance for external integrations.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/mpte-orchestrator/threat-intel` | Get threat intelligence for a target/CVE |
| `POST` | `/api/v1/mpte-orchestrator/business-impact` | Analyze business impact of a vulnerability |
| `POST` | `/api/v1/mpte-orchestrator/simulate` | Run attack simulation |
| `POST` | `/api/v1/mpte-orchestrator/remediation` | Get remediation guidance for a finding |
| `POST` | `/api/v1/mpte-orchestrator/run` | Run a full orchestrated pentest |
| `GET` | `/api/v1/mpte-orchestrator/status/{test_id}` | Get orchestrated test status |
| `GET` | `/api/v1/mpte-orchestrator/capabilities` | List orchestrator capabilities |
| `GET` | `/api/v1/mpte-orchestrator/health` | Health check |

**Example — Run an orchestrated pentest with full analysis:**

```bash
curl -X POST http://localhost:8000/api/v1/mpte-orchestrator/run \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://testapp.example.com",
    "cve_id": "CVE-2024-3094",
    "include_threat_intel": true,
    "include_business_impact": true,
    "include_remediation": true
  }'
```

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

**Prefix**: `/api/v1/connectors` · **Source**: `suite-api/apps/api/connectors_router.py` · **8 endpoints**

Fan-out remediation actions to external tools. Register, test, and manage 7 integration connectors.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/connectors/types` | List supported connector types |
| `GET` | `/api/v1/connectors` | List registered connectors |
| `POST` | `/api/v1/connectors/register` | Register a new connector |
| `POST` | `/api/v1/connectors/test` | Test all connectors |
| `POST` | `/api/v1/connectors/create-ticket` | Create ticket from finding (Jira/GitHub/ServiceNow) |
| `POST` | `/api/v1/connectors/{name}/test` | Test a specific connector |
| `DELETE` | `/api/v1/connectors/{name}` | Remove a connector |
| `GET` | `/api/v1/connectors/health` | Connectors health |

**Supported connectors**: Jira, GitHub, GitLab, Slack, ServiceNow, Azure DevOps, Confluence.

**Example — Register a Jira connector and create a ticket:**

```bash
# Register the connector
curl -X POST http://localhost:8000/api/v1/connectors/register \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "jira",
    "config": {"url": "https://company.atlassian.net", "project": "SEC"}
  }'

# Create a ticket from a finding
curl -X POST http://localhost:8000/api/v1/connectors/create-ticket \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"finding_id": "finding-abc123", "connector": "jira", "priority": "high"}'
```

---

### 5.5 Integrations Management [V7]

**Prefix**: `/api/v1/integrations` · **Source**: `suite-integrations/api/integrations_router.py` · **8 endpoints**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/integrations` | List integrations (paginated, filterable) |
| `POST` | `/api/v1/integrations` | Create integration |
| `GET` | `/api/v1/integrations/{id}` | Get integration details |
| `PUT` | `/api/v1/integrations/{id}` | Update integration |
| `DELETE` | `/api/v1/integrations/{id}` | Delete integration |
| `POST` | `/api/v1/integrations/{id}/sync` | Sync integration |
| `GET` | `/api/v1/integrations/{id}/sync-status` | Get sync status |
| `POST` | `/api/v1/integrations/{id}/test` | Test connection |

### 5.6 Webhooks — Bidirectional Sync [V7]

**Prefix**: `/api/v1/webhooks` · **Source**: `suite-integrations/api/webhooks_router.py` · **21 endpoints**

Full webhook lifecycle management with bidirectional sync — both outgoing notifications and incoming scanner webhooks.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/webhooks` | List webhook subscriptions |
| `POST` | `/api/v1/webhooks` | Create webhook subscription |
| `GET` | `/api/v1/webhooks/{id}` | Get webhook details |
| `PUT` | `/api/v1/webhooks/{id}` | Update webhook |
| `DELETE` | `/api/v1/webhooks/{id}` | Delete webhook |
| `POST` | `/api/v1/webhooks/{id}/test` | Test webhook delivery |
| `GET` | `/api/v1/webhooks/{id}/deliveries` | View delivery history |
| `POST` | `/api/v1/webhooks/{id}/retry` | Retry failed delivery |
| `POST` | `/api/v1/webhooks/receive/github` | Receive GitHub webhook |
| `POST` | `/api/v1/webhooks/receive/gitlab` | Receive GitLab webhook |
| `POST` | `/api/v1/webhooks/receive/jira` | Receive Jira webhook |
| `POST` | `/api/v1/webhooks/receive/snyk` | Receive Snyk webhook |
| `POST` | `/api/v1/webhooks/receive/sonarqube` | Receive SonarQube webhook |
| `POST` | `/api/v1/webhooks/receive/generic` | Receive generic webhook |
| `GET` | `/api/v1/webhooks/events` | List supported event types |
| `GET` | `/api/v1/webhooks/stats` | Webhook statistics |
| `GET` | `/api/v1/webhooks/health` | Health check |
| `GET` | `/api/v1/webhooks/status` | Status |

---

## 6. Comply — Evidence, Compliance & Audit

> **CTEM Phase**: Prove you're secure to auditors — cryptographically.
> **Pillar**: [V10] CTEM Full Loop with Crypto

### 6.1 Evidence Engine [V10]

**Prefix**: `/api/v1/evidence` · **Source**: `suite-evidence-risk/api/evidence_router.py` · **15 endpoints**

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
| `GET` | `/api/v1/evidence/health` | Health check |
| `GET` | `/api/v1/evidence/status` | Status |

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

**Prefix**: `/api/v1/compliance-engine` · **Source**: `suite-evidence-risk/api/compliance_engine_router.py` · **10 endpoints**

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
| `GET` | `/api/v1/compliance-engine/health` | Health check |

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

**Prefix**: `/api/v1/audit` · **Source**: `suite-api/apps/api/audit_router.py` · **14 endpoints**

Full audit trail with compliance framework mapping, cryptographic chain verification, and decision tracking.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/audit/logs` | Query audit logs (paginated, filterable) |
| `GET` | `/api/v1/audit/logs/export` | Export audit logs (CSV/JSON) |
| `GET` | `/api/v1/audit/logs/{id}` | Get specific audit log entry |
| `GET` | `/api/v1/audit/user-activity` | User activity timeline |
| `GET` | `/api/v1/audit/policy-changes` | Policy change history |
| `GET` | `/api/v1/audit/decision-trail` | AI decision audit trail |
| `GET` | `/api/v1/audit/compliance/frameworks` | List compliance frameworks |
| `GET` | `/api/v1/audit/compliance/frameworks/{id}/status` | Framework compliance status |
| `GET` | `/api/v1/audit/compliance/frameworks/{id}/gaps` | Framework compliance gaps |
| `POST` | `/api/v1/audit/compliance/frameworks/{id}/report` | Generate compliance report |
| `GET` | `/api/v1/audit/compliance/controls` | List all compliance controls |
| `POST` | `/api/v1/audit/logs/chain` | Create cryptographic audit chain entry |
| `GET` | `/api/v1/audit/chain/verify` | Verify audit chain integrity |
| `GET` | `/api/v1/audit/retention` | Audit log retention policy |

**Example — Verify audit chain integrity:**

```bash
curl -s http://localhost:8000/api/v1/audit/chain/verify \
  -H "X-API-Key: $FIXOPS_API_TOKEN" | python3 -m json.tool
```

```json
{
  "chain_valid": true,
  "total_entries": 1247,
  "last_verified": "2026-03-02T14:00:00Z",
  "hash_algorithm": "SHA-256",
  "gaps_detected": 0
}
```

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

**Prefix**: `/api/v1/brain` · **Source**: `suite-core/api/brain_router.py` (24) + `pipeline_router.py` (8) · **Engine**: `suite-core/core/brain_pipeline.py` (1,878 LOC) · **32 endpoints**

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
| `GET` | `/api/v1/brain/trends` | Finding and risk trends over time |
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

**Prefix**: `/api/v1/mcp` · **Source**: `suite-api/apps/api/mcp_router.py` · **8 endpoints**

Model Context Protocol — makes ALdeci the first AppSec platform AI agents can programmatically use.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/mcp/tools` | List all MCP-available tools (auto-discovered from 784 routes) |
| `GET` | `/api/v1/mcp/tools/{tool_name}` | Get tool schema definition |
| `POST` | `/api/v1/mcp/execute` | Execute an MCP tool |
| `GET` | `/api/v1/mcp/schemas` | OpenAPI schemas for all tools |
| `GET` | `/api/v1/mcp/health` | MCP gateway health |
| `GET` | `/api/v1/mcp/status` | MCP gateway status |
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

**Prefix**: `/api/v1/mcp-protocol` · **Source**: `suite-core/api/mcp_protocol_router.py` · **10 endpoints**

Low-level MCP protocol implementation for agent-to-agent communication via JSON-RPC and SSE.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/mcp-protocol/status` | Protocol server status |
| `POST` | `/api/v1/mcp-protocol/jsonrpc` | JSON-RPC 2.0 message handler |
| `POST` | `/api/v1/mcp-protocol/raw` | Raw MCP message passthrough |
| `GET` | `/api/v1/mcp-protocol/sse` | Server-Sent Events stream for real-time updates |
| `GET` | `/api/v1/mcp-protocol/tools` | List available MCP tools |
| `GET` | `/api/v1/mcp-protocol/resources` | List available resources |
| `GET` | `/api/v1/mcp-protocol/prompts` | List available prompts |
| `POST` | `/api/v1/mcp-protocol/discover` | Auto-discover tools from FastAPI routes |
| `GET` | `/api/v1/mcp-protocol/stats` | MCP protocol usage statistics |
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

**Prefix**: `/api/v1/cases` · **Source**: `suite-core/api/exposure_case_router.py` · **10 endpoints**

Track exposure cases through their lifecycle — from discovery to closure with full state machine transitions.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/cases/stats/summary` | Case summary statistics |
| `POST` | `/api/v1/cases` | Create exposure case |
| `GET` | `/api/v1/cases` | List exposure cases |
| `GET` | `/api/v1/cases/{case_id}` | Get case details |
| `PATCH` | `/api/v1/cases/{case_id}` | Update case |
| `POST` | `/api/v1/cases/{case_id}/transition` | Transition case state |
| `POST` | `/api/v1/cases/{case_id}/clusters` | Link finding clusters to case |
| `GET` | `/api/v1/cases/{case_id}/transitions` | Get case transition history |
| `GET` | `/api/v1/cases/health` | Health check |
| `GET` | `/api/v1/cases/status` | Status |

---

### 7.7 Deduplication Engine [V3]

**Prefix**: `/api/v1/deduplication` · **Source**: `suite-core/api/deduplication_router.py` · **20 endpoints**

Cross-scanner deduplication with cluster management, correlation analysis, and baseline comparison.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/deduplication/process` | Process findings for deduplication |
| `POST` | `/api/v1/deduplication/process/batch` | Batch deduplication processing |
| `GET` | `/api/v1/deduplication/clusters` | List dedup clusters |
| `GET` | `/api/v1/deduplication/clusters/{cluster_id}` | Get cluster details |
| `PUT` | `/api/v1/deduplication/clusters/{cluster_id}/status` | Update cluster status |
| `PUT` | `/api/v1/deduplication/clusters/{cluster_id}/assign` | Assign cluster to team |
| `PUT` | `/api/v1/deduplication/clusters/{cluster_id}/ticket` | Link external ticket |
| `GET` | `/api/v1/deduplication/clusters/{cluster_id}/related` | Get related clusters |
| `GET` | `/api/v1/deduplication/correlations` | List finding correlations |
| `POST` | `/api/v1/deduplication/correlations` | Create correlation rule |
| `GET` | `/api/v1/deduplication/stats` | Deduplication statistics |
| `GET` | `/api/v1/deduplication/stats/{org_id}` | Org-specific dedup stats |
| `POST` | `/api/v1/deduplication/correlate/cross-stage` | Cross-stage correlation |
| `GET` | `/api/v1/deduplication/graph` | Dedup cluster graph |
| `POST` | `/api/v1/deduplication/feedback` | Submit dedup feedback |
| `POST` | `/api/v1/deduplication/baseline/compare` | Compare against baseline |
| `POST` | `/api/v1/deduplication/clusters/merge` | Merge duplicate clusters |
| `POST` | `/api/v1/deduplication/clusters/{cluster_id}/split` | Split mismatched cluster |
| `GET` | `/api/v1/deduplication/health` | Health check |
| `GET` | `/api/v1/deduplication/status` | Status |

**Example — Deduplicate findings from multiple scanners:**

```bash
curl -X POST http://localhost:8000/api/v1/deduplication/process \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_id": "myapp-001",
    "finding_ids": ["f-001", "f-002", "f-003"],
    "strategy": "cross_scanner"
  }'
```

---

### 7.8 Predictions & ML [V3]

**Prefix**: `/api/v1/predictions` · **Source**: `suite-core/api/predictions_router.py` · **10 endpoints**

Advanced predictive analytics with Markov chains, Bayesian networks, and combined risk assessment.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/predictions/attack-chain` | Predict attack chain probability |
| `POST` | `/api/v1/predictions/risk-trajectory` | Predict risk trajectory over time |
| `POST` | `/api/v1/predictions/simulate-attack` | Monte Carlo attack simulation |
| `GET` | `/api/v1/predictions/markov/states` | Get Markov model states |
| `GET` | `/api/v1/predictions/markov/transitions` | Get state transition matrix |
| `POST` | `/api/v1/predictions/bayesian/update` | Update Bayesian belief network |
| `POST` | `/api/v1/predictions/bayesian/risk-assessment` | Bayesian risk assessment |
| `POST` | `/api/v1/predictions/combined-analysis` | Combined multi-model analysis |
| `GET` | `/api/v1/predictions/health` | Health check |
| `GET` | `/api/v1/predictions/status` | Status |

---

### 7.9 Additional Intelligence Endpoints

#### Algorithmic Scoring

**Prefix**: `/api/v1/algorithms` · **Source**: `suite-core/api/algorithmic_router.py` · **11 endpoints**

Advanced risk quantification using Monte Carlo simulation, causal inference, and Graph Neural Networks.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/algorithms/monte-carlo/quantify` | Monte Carlo risk quantification |
| `POST` | `/api/v1/algorithms/monte-carlo/cve` | CVE-specific Monte Carlo analysis |
| `POST` | `/api/v1/algorithms/monte-carlo/portfolio` | Portfolio risk Monte Carlo |
| `POST` | `/api/v1/algorithms/causal/analyze` | Causal analysis of vulnerability factors |
| `POST` | `/api/v1/algorithms/causal/counterfactual` | Counterfactual "what-if" analysis |
| `POST` | `/api/v1/algorithms/causal/treatment-effect` | Remediation treatment effect |
| `POST` | `/api/v1/algorithms/gnn/attack-surface` | GNN attack surface analysis |
| `POST` | `/api/v1/algorithms/gnn/critical-nodes` | GNN critical node identification |
| `POST` | `/api/v1/algorithms/gnn/risk-propagation` | GNN risk propagation modeling |
| `GET` | `/api/v1/algorithms/status` | Status |
| `GET` | `/api/v1/algorithms/capabilities` | List available algorithms |

**Example — Run Monte Carlo risk quantification:**

```bash
curl -X POST http://localhost:8000/api/v1/algorithms/monte-carlo/quantify \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_ids": ["f-001", "f-002"],
    "simulations": 10000,
    "time_horizon_days": 365
  }'
```

#### LLM Provider Management

**Prefix**: `/api/v1/llm` · **Source**: `suite-core/api/llm_router.py` · **6 endpoints**

Multi-LLM consensus configuration — manage providers, test connections, and tune settings.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/llm/status` | LLM configuration and provider status |
| `POST` | `/api/v1/llm/test` | Test LLM provider connection |
| `GET` | `/api/v1/llm/settings` | Get LLM consensus settings |
| `PATCH` | `/api/v1/llm/settings` | Update LLM consensus settings |
| `GET` | `/api/v1/llm/providers` | List configured LLM providers |
| `GET` | `/api/v1/llm/health` | Health check |

#### Nerve Center — Central Health Hub [V3]

**Prefix**: `/api/v1/nerve-center` · **Source**: `suite-core/api/nerve_center.py` · **9 endpoints**

Real-time operational health monitoring — the "central nervous system" of the platform.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/nerve-center/status` | Overall platform health status |
| `GET` | `/api/v1/nerve-center/engines` | Engine health dashboard |
| `GET` | `/api/v1/nerve-center/scanners` | Scanner health status |
| `GET` | `/api/v1/nerve-center/feeds` | Feed health status |
| `GET` | `/api/v1/nerve-center/pipelines` | Pipeline health status |
| `GET` | `/api/v1/nerve-center/alerts` | Active operational alerts |
| `POST` | `/api/v1/nerve-center/alerts/acknowledge` | Acknowledge an alert |
| `GET` | `/api/v1/nerve-center/metrics` | Platform operational metrics |
| `GET` | `/api/v1/nerve-center/health` | Health check |

#### Decision Records [V3]

**Prefix**: `/api/v1/decisions` · **Source**: `suite-core/api/decisions.py` · **6 endpoints**

Track AI-powered decisions with full audit trail — who decided what, when, and why.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/decisions` | List decision records |
| `POST` | `/api/v1/decisions` | Create decision record |
| `GET` | `/api/v1/decisions/{id}` | Get decision details |
| `PUT` | `/api/v1/decisions/{id}` | Update decision |
| `GET` | `/api/v1/decisions/stats` | Decision statistics |
| `GET` | `/api/v1/decisions/status` | Status |

#### MindsDB ML Models [V3]

**Prefix**: `/api/v1/ml` · **Source**: `suite-core/api/mindsdb_router.py` · **14 endpoints**

ML model serving for vulnerability prioritization, exploit prediction, and risk scoring.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/ml/models` | List available ML models |
| `POST` | `/api/v1/ml/models` | Register a new model |
| `GET` | `/api/v1/ml/models/{id}` | Get model details |
| `DELETE` | `/api/v1/ml/models/{id}` | Delete model |
| `POST` | `/api/v1/ml/predict` | Run prediction |
| `POST` | `/api/v1/ml/predict/batch` | Batch prediction |
| `POST` | `/api/v1/ml/train` | Train a model |
| `GET` | `/api/v1/ml/train/{job_id}` | Get training job status |
| `GET` | `/api/v1/ml/features` | List feature definitions |
| `POST` | `/api/v1/ml/features/importance` | Calculate feature importance |
| `GET` | `/api/v1/ml/experiments` | List experiments |
| `GET` | `/api/v1/ml/stats` | ML service statistics |
| `GET` | `/api/v1/ml/health` | Health check |
| `GET` | `/api/v1/ml/status` | Status |

#### Copilot — AI Security Assistant [V3]

**Prefix**: `/api/v1/copilot` · **Source**: `suite-core/api/copilot_router.py` · **14 endpoints**

Interactive AI copilot for security analysis, natural language queries, and recommendations.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/copilot/ask` | Ask the AI copilot a security question |
| `POST` | `/api/v1/copilot/analyze` | Analyze findings with AI |
| `POST` | `/api/v1/copilot/recommend` | Get AI recommendations |
| `POST` | `/api/v1/copilot/explain` | Explain a vulnerability in plain English |
| `POST` | `/api/v1/copilot/summarize` | Summarize security posture |
| `GET` | `/api/v1/copilot/history` | Conversation history |
| `POST` | `/api/v1/copilot/report` | Generate AI-powered security report |
| `GET` | `/api/v1/copilot/suggestions` | Get proactive suggestions |
| `POST` | `/api/v1/copilot/triage` | AI-assisted triage |
| `GET` | `/api/v1/copilot/models` | List available AI models |
| `GET` | `/api/v1/copilot/stats` | Copilot usage statistics |
| `GET` | `/api/v1/copilot/health` | Health check |
| `GET` | `/api/v1/copilot/status` | Status |

#### Business Context [V1]

**Prefix**: `/api/v1/business-context` · **Source**: `suite-evidence-risk/api/business_context.py` + `business_context_enhanced.py` · **9 endpoints**

Enrich findings with business context — asset criticality, data sensitivity, regulatory scope.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/business-context/enrich` | Enrich findings with business context |
| `GET` | `/api/v1/business-context/assets` | List business assets |
| `POST` | `/api/v1/business-context/assets` | Register business asset |
| `GET` | `/api/v1/business-context/assets/{id}` | Get asset business context |
| `PUT` | `/api/v1/business-context/assets/{id}` | Update asset context |
| `POST` | `/api/v1/business-context/impact` | Calculate business impact |
| `GET` | `/api/v1/business-context/data-flows` | List data flow mappings |
| `GET` | `/api/v1/business-context/health` | Health check |
| `GET` | `/api/v1/business-context/status` | Status |

#### Graph Risk Analysis [V3]

**Prefix**: `/api/v1/graph` · **Source**: `suite-evidence-risk/api/graph_router.py` · **6 endpoints**

Graph-based risk analysis with attack path computation and blast radius estimation.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/graph/query` | Execute graph query |
| `POST` | `/api/v1/graph/attack-paths` | Compute attack paths |
| `POST` | `/api/v1/graph/blast-radius` | Calculate blast radius |
| `GET` | `/api/v1/graph/stats` | Graph statistics |
| `GET` | `/api/v1/graph/health` | Health check |
| `GET` | `/api/v1/graph/status` | Status |

#### Reachability Analysis [V3]

**Prefix**: `/api/v1/reachability` · **Source**: `suite-evidence-risk/risk/reachability/api.py` · **7 endpoints**

Analyze whether vulnerable code paths are actually reachable in production — reduces false positives by proving exploitability through static call-graph analysis.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/reachability/analyze` | Analyze reachability of a vulnerability |
| `POST` | `/api/v1/reachability/analyze/bulk` | Bulk reachability analysis |
| `GET` | `/api/v1/reachability/job/{job_id}` | Get analysis job status |
| `GET` | `/api/v1/reachability/results/{cve_id}` | Get reachability results for a CVE |
| `DELETE` | `/api/v1/reachability/results/{cve_id}` | Delete reachability results |
| `GET` | `/api/v1/reachability/health` | Health check |
| `GET` | `/api/v1/reachability/metrics` | Reachability analysis metrics |

**Example — Check if a CVE is reachable in your application:**

```bash
curl -X POST http://localhost:8000/api/v1/reachability/analyze \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-3094",
    "app_id": "myapp-001",
    "entry_points": ["src/main.py", "src/api/routes.py"]
  }'
```

---

#### Enhanced Decision Analysis [V3]

**Prefix**: `/api/v1/enhanced` · **Source**: `suite-api/apps/api/routes/enhanced.py` · **4 endpoints**

Advanced multi-LLM comparison and signal analysis for decision intelligence.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/enhanced/analysis` | Run enhanced decision analysis |
| `POST` | `/api/v1/enhanced/compare-llms` | Compare LLM provider responses side-by-side |
| `GET` | `/api/v1/enhanced/capabilities` | List enhanced analysis capabilities |
| `GET` | `/api/v1/enhanced/signals` | Get decision signal definitions |

---

#### Streaming / SSE

**Prefix**: `/api/v1/stream` · **Source**: `suite-core/api/streaming_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/stream/events` | Server-Sent Events stream |
| `GET` | `/api/v1/stream/findings` | Real-time findings stream |
| `GET` | `/api/v1/stream/status` | Status |

#### MCP Server — External Agent Gateway [V7]

**Prefix**: `/api/v1/mcp` · **Source**: `suite-integrations/api/mcp_router.py` (468 LOC) · **10 endpoints**

Low-level MCP server management — client connections, tool registry, and server configuration for external AI agents.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/mcp/status` | MCP server status |
| `GET` | `/api/v1/mcp/clients` | List connected MCP clients |
| `GET` | `/api/v1/mcp/tools` | List registered MCP tools |
| `GET` | `/api/v1/mcp/resources` | List available resources |
| `GET` | `/api/v1/mcp/prompts` | List available prompts |
| `GET` | `/api/v1/mcp/config` | Get server configuration |
| `POST` | `/api/v1/mcp/configure` | Update MCP server configuration |
| `POST` | `/api/v1/mcp/clients/{client_id}/disconnect` | Disconnect a client |
| `DELETE` | `/api/v1/mcp/clients/{client_id}` | Remove a client |
| `GET` | `/api/v1/mcp/manifest` | Get full MCP manifest |

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

**Prefix**: `/api/v1/teams` · **Scope**: `admin:all` · **8 endpoints**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/teams` | List teams |
| `POST` | `/api/v1/teams` | Create team |
| `GET` | `/api/v1/teams/{id}` | Get team details |
| `PUT` | `/api/v1/teams/{id}` | Update team |
| `DELETE` | `/api/v1/teams/{id}` | Delete team |
| `GET` | `/api/v1/teams/{id}/members` | List team members |
| `POST` | `/api/v1/teams/{id}/members` | Add member to team |
| `DELETE` | `/api/v1/teams/{id}/members/{user_id}` | Remove member from team |

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

**Prefix**: `/api/v1/system` · **Source**: `suite-api/apps/api/system_router.py` · **Scope**: `admin:all` · **5 endpoints**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/system/health` | Detailed system health |
| `GET` | `/api/v1/system/info` | System information |
| `GET` | `/api/v1/system/config` | Get system configuration |
| `GET` | `/api/v1/system/metrics` | Platform operational metrics |
| `GET` | `/api/v1/system/status` | System status |

### 8.6 Auth / SSO

**Prefix**: `/api/v1/auth` · **Scope**: `admin:all`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/auth/sso` | List SSO configurations |
| `POST` | `/api/v1/auth/sso` | Create SSO configuration |
| `GET` | `/api/v1/auth/sso/{id}` | Get SSO config |
| `PUT` | `/api/v1/auth/sso/{id}` | Update SSO config |

### 8.7 Reports [V10]

**Prefix**: `/api/v1/reports` · **Source**: `suite-api/apps/api/reports_router.py` · **14 endpoints**

Report generation, scheduling, and export in multiple formats (PDF, SARIF, CSV, JSON).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/reports` | List reports (paginated) |
| `POST` | `/api/v1/reports` | Create report metadata |
| `POST` | `/api/v1/reports/generate` | Generate a full report |
| `GET` | `/api/v1/reports/stats` | Report statistics |
| `GET` | `/api/v1/reports/{id}` | Get report details |
| `GET` | `/api/v1/reports/{id}/download` | Download report file |
| `GET` | `/api/v1/reports/{id}/file` | Get report file content |
| `POST` | `/api/v1/reports/schedule` | Schedule recurring report |
| `GET` | `/api/v1/reports/schedules/list` | List report schedules |
| `GET` | `/api/v1/reports/templates/list` | List report templates |
| `POST` | `/api/v1/reports/export/sarif` | Export findings as SARIF |
| `POST` | `/api/v1/reports/export/csv` | Export findings as CSV |
| `GET` | `/api/v1/reports/export/csv/{export_id}/download` | Download CSV export |
| `GET` | `/api/v1/reports/export/json` | Export findings as JSON |

**Example — Generate a security report:**

```bash
curl -X POST http://localhost:8000/api/v1/reports/generate \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "executive_summary",
    "app_id": "myapp-001",
    "format": "pdf",
    "period": "last_30_days"
  }'
```

### 8.8 Policies [V3]

**Prefix**: `/api/v1/policies` · **Source**: `suite-api/apps/api/policies_router.py` · **Scope**: `write:findings` · **11 endpoints**

Security policy lifecycle — create, validate, test, enforce, and simulate policies with conflict detection.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/policies` | List security policies (paginated) |
| `POST` | `/api/v1/policies` | Create policy |
| `GET` | `/api/v1/policies/{id}` | Get policy details |
| `PUT` | `/api/v1/policies/{id}` | Update policy |
| `DELETE` | `/api/v1/policies/{id}` | Delete policy |
| `POST` | `/api/v1/policies/{id}/validate` | Validate policy rules |
| `POST` | `/api/v1/policies/{id}/test` | Test policy against sample data |
| `GET` | `/api/v1/policies/{id}/violations` | List policy violations |
| `POST` | `/api/v1/policies/{id}/enforce` | Enforce policy on findings |
| `POST` | `/api/v1/policies/simulate` | Simulate policy impact before applying |
| `GET` | `/api/v1/policies/conflicts` | Detect conflicting policies |

### 8.9 Webhooks

**Prefix**: `/api/v1/webhooks` · **Source**: `suite-integrations/api/webhooks_router.py`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/webhooks` | List webhook subscriptions |
| `POST` | `/api/v1/webhooks` | Create webhook |
| `PUT` | `/api/v1/webhooks/{id}` | Update webhook |
| `DELETE` | `/api/v1/webhooks/{id}` | Delete webhook |
| `POST` | `/api/v1/webhooks/{id}/test` | Test webhook delivery |

### 8.10 Bulk Operations [V3]

**Prefix**: `/api/v1/bulk` · **Source**: `suite-api/apps/api/bulk_router.py` · **Scope**: `write:findings` · **13 endpoints**

Asynchronous bulk operations for findings, clusters, policies, and exports with job tracking.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/bulk/clusters/status` | Bulk update cluster statuses |
| `POST` | `/api/v1/bulk/clusters/assign` | Bulk assign clusters to teams |
| `POST` | `/api/v1/bulk/clusters/accept-risk` | Bulk accept risk for clusters |
| `POST` | `/api/v1/bulk/clusters/create-tickets` | Bulk create tickets from clusters |
| `POST` | `/api/v1/bulk/export` | Bulk export findings (async) |
| `GET` | `/api/v1/bulk/exports/{filename}` | Download bulk export file |
| `GET` | `/api/v1/bulk/jobs/{job_id}` | Get bulk job status |
| `GET` | `/api/v1/bulk/jobs` | List all bulk jobs |
| `DELETE` | `/api/v1/bulk/jobs/{job_id}` | Cancel/delete a bulk job |
| `POST` | `/api/v1/bulk/findings/update` | Bulk update findings |
| `POST` | `/api/v1/bulk/findings/delete` | Bulk delete findings |
| `POST` | `/api/v1/bulk/findings/assign` | Bulk assign findings |
| `POST` | `/api/v1/bulk/policies/apply` | Bulk apply policies to findings |

### 8.11 Collaboration [V3]

**Prefix**: `/api/v1/collaboration` · **Source**: `suite-api/apps/api/collaboration_router.py` · **23 endpoints**

Full collaboration suite — comments, watchers, activity feeds, mentions, and notification delivery.

#### Comments & Watchers

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/collaboration/comments` | Add comment to an entity |
| `GET` | `/api/v1/collaboration/comments` | List comments (filterable by entity) |
| `PUT` | `/api/v1/collaboration/comments/{comment_id}/promote` | Promote comment to decision |
| `POST` | `/api/v1/collaboration/watchers` | Subscribe to entity updates |
| `DELETE` | `/api/v1/collaboration/watchers` | Unsubscribe from entity |
| `GET` | `/api/v1/collaboration/watchers` | List watchers for entity |
| `GET` | `/api/v1/collaboration/watchers/user/{user_id}` | List entities watched by user |

#### Activity Feed & Mentions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/collaboration/activities` | Log an activity event |
| `GET` | `/api/v1/collaboration/activities` | Get activity feed (paginated) |
| `GET` | `/api/v1/collaboration/mentions/{user_id}` | List mentions for a user |
| `PUT` | `/api/v1/collaboration/mentions/{mention_id}/acknowledge` | Acknowledge a mention |
| `GET` | `/api/v1/collaboration/entity-types` | List supported entity types |
| `GET` | `/api/v1/collaboration/activity-types` | List supported activity types |

#### Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/collaboration/notifications/queue` | Queue a notification |
| `POST` | `/api/v1/collaboration/notifications/notify-watchers` | Notify all watchers of an entity |
| `GET` | `/api/v1/collaboration/notifications/pending` | List pending notifications |
| `PUT` | `/api/v1/collaboration/notifications/{notification_id}/sent` | Mark notification as sent |
| `GET` | `/api/v1/collaboration/notifications/preferences/{user_id}` | Get notification preferences |
| `PUT` | `/api/v1/collaboration/notifications/preferences/{user_id}` | Update notification preferences |
| `POST` | `/api/v1/collaboration/notifications/{notification_id}/deliver` | Deliver via configured channel |
| `POST` | `/api/v1/collaboration/notifications/process` | Process pending notification queue |

#### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/collaboration/health` | Health check |
| `GET` | `/api/v1/collaboration/status` | Status |

### 8.12 Validation — Security Tool Output Compatibility

**Prefix**: `/api/v1/validate` · **Source**: `suite-api/apps/api/validation_router.py` · **5 endpoints**

Validate and check compatibility of security tool outputs before ingestion.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/validate/input` | Validate security tool output for compatibility |
| `POST` | `/api/v1/validate/batch` | Batch validate multiple tool outputs, generate compatibility report |
| `GET` | `/api/v1/validate/supported-formats` | List supported validation formats |
| `GET` | `/api/v1/validate/health` | Health check |
| `GET` | `/api/v1/validate/status` | Status |

**Example — Validate a scanner report before ingestion:**

```bash
curl -X POST http://localhost:8000/api/v1/validate/input \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "sarif",
    "content": "{\"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\"}",
    "strict": true
  }'
```

### 8.13 Marketplace [V7]

**Prefix**: `/api/v1/marketplace` · **Source**: `suite-api/apps/api/marketplace_router.py` · **14 endpoints**

Enterprise remediation pack marketplace — browse, contribute, purchase, and download compliance-ready remediation content.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/marketplace/browse` | Browse marketplace (filterable, paginated) |
| `GET` | `/api/v1/marketplace/recommendations` | Get personalized recommendations |
| `GET` | `/api/v1/marketplace/items/{item_id}` | Get marketplace item details |
| `GET` | `/api/v1/marketplace/packs/{framework}/{control}` | Get remediation pack by framework/control |
| `POST` | `/api/v1/marketplace/contribute` | Contribute a remediation pack |
| `PUT` | `/api/v1/marketplace/items/{item_id}` | Update marketplace item |
| `POST` | `/api/v1/marketplace/items/{item_id}/rate` | Rate a marketplace item |
| `POST` | `/api/v1/marketplace/purchase/{item_id}` | Purchase a marketplace item |
| `GET` | `/api/v1/marketplace/download/{token}` | Download purchased item |
| `GET` | `/api/v1/marketplace/contributors` | List marketplace contributors |
| `GET` | `/api/v1/marketplace/compliance-content/{stage}` | Get compliance content by CTEM stage |
| `GET` | `/api/v1/marketplace/stats` | Marketplace statistics |
| `GET` | `/api/v1/marketplace/health` | Health check |
| `GET` | `/api/v1/marketplace/status` | Status |

### 8.14 Detailed Logs

**Prefix**: `/api/v1/logs` · **Source**: `suite-api/apps/api/detailed_logging.py` · **5 endpoints**

Full request/response payload logging with streaming support for real-time debugging.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/logs` | Query captured logs (paginated, filterable) |
| `GET` | `/api/v1/logs/stats` | Log capture statistics |
| `GET` | `/api/v1/logs/recent` | Most recent logs (quick view) |
| `DELETE` | `/api/v1/logs` | Clear captured logs |
| `GET` | `/api/v1/logs/stream` | Server-Sent Events stream of live logs |

---

## 9. Vision Engines — Advanced Capabilities

> **Cross-cutting**: Advanced AI, cryptography, data lifecycle, and feedback loop engines.
> **Note**: These engines implement vision pillars V4, V6, V8, V9 — active and operational but not the primary demo focus for Sprint 2.

### 9.1 Self-Learning Engine [V8]

**Prefix**: `/api/v1/self-learning` · **Source**: `suite-core/api/self_learning_router.py` · **Engine**: `suite-core/core/self_learning.py` (832 LOC) · **20 endpoints**

Five feedback loops that continuously improve ALdeci's decision quality over time.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/self-learning/health` | Health check |
| `GET` | `/api/v1/self-learning/status` | Engine status and loop health |
| `GET` | `/api/v1/self-learning/stats` | Self-learning usage and loop statistics |
| `POST` | `/api/v1/self-learning/feedback/decision` | Record decision feedback (was the AI right?) |
| `POST` | `/api/v1/self-learning/feedback/mpte` | Record MPTE verification feedback |
| `POST` | `/api/v1/self-learning/feedback/false-positive` | Report false positive for model retraining |
| `POST` | `/api/v1/self-learning/feedback/remediation` | Record remediation outcome feedback |
| `POST` | `/api/v1/self-learning/feedback/policy` | Record policy effectiveness feedback |
| `GET` | `/api/v1/self-learning/analyze` | Analyze all feedback loops (configurable window) |
| `GET` | `/api/v1/self-learning/insights` | Get actionable learning insights |
| `GET` | `/api/v1/self-learning/analyze/{loop}` | Analyze a specific feedback loop |
| `GET` | `/api/v1/self-learning/suppressed-rules` | Get auto-suppressed detection rules |
| `POST` | `/api/v1/self-learning/score-with-learning` | Score finding with learned adjustments |
| `POST` | `/api/v1/self-learning/compute-adjustments` | Recompute scoring model adjustments |
| `GET` | `/api/v1/self-learning/weights` | Get current scoring weight configuration |
| `PUT` | `/api/v1/self-learning/weights/{key}` | Update a specific scoring weight |
| `GET` | `/api/v1/self-learning/metrics/trends` | Feedback metrics over time |
| `POST` | `/api/v1/self-learning/demo/seed` | Seed demo feedback data |
| `POST` | `/api/v1/self-learning/demo/reset` | Reset demo data |
| `GET` | `/api/v1/self-learning/demo/full-loop` | Run full demo loop |

**5 Feedback Loops**: Decision accuracy · MPTE verification · False positive reduction · Remediation effectiveness · Policy tuning

**Example — Record false positive feedback:**

```bash
curl -X POST http://localhost:8000/api/v1/self-learning/feedback/false-positive \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "finding-abc123",
    "confirmed_fp": true,
    "reason": "Test code, not production",
    "reporter": "security-analyst@company.com"
  }'
```

---

### 9.2 Quantum-Secure Cryptography [V6]

**Prefix**: `/api/v1/quantum-crypto` · **Source**: `suite-core/api/quantum_crypto_router.py` · **Engine**: `suite-core/core/quantum_crypto.py` (666 LOC) · **6 endpoints**

Hybrid RSA-SHA256 + ML-DSA (FIPS 204) evidence signing for post-quantum security.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/quantum-crypto/health` | Health check |
| `GET` | `/api/v1/quantum-crypto/status` | Cryptographic engine status |
| `POST` | `/api/v1/quantum-crypto/sign` | Sign content with hybrid quantum-safe signature |
| `POST` | `/api/v1/quantum-crypto/verify` | Verify hybrid signature |
| `GET` | `/api/v1/quantum-crypto/keys` | Get key information (algorithm, size, rotation) |
| `POST` | `/api/v1/quantum-crypto/keys/rotate` | Rotate signing keys |

**Example — Sign evidence with quantum-safe signature:**

```bash
curl -X POST http://localhost:8000/api/v1/quantum-crypto/sign \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "evidence-bundle-hash:sha256:a1b2c3d4...",
    "algorithm": "hybrid"
  }'
```

---

### 9.3 Zero-Gravity Data Lifecycle [V9]

**Prefix**: `/api/v1/zero-gravity` · **Source**: `suite-core/api/zero_gravity_router.py` · **Engine**: `suite-core/core/zero_gravity.py` (857 LOC) · **7 endpoints**

Intelligent data lifecycle management — 95% storage reduction (20 GB → 1 GB/year) via ZSTD compression, coreset selection, and MinHash deduplication.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/zero-gravity/health` | Health check |
| `GET` | `/api/v1/zero-gravity/status` | Data lifecycle engine status |
| `POST` | `/api/v1/zero-gravity/ingest` | Ingest data with compression |
| `GET` | `/api/v1/zero-gravity/retrieve/{data_id}` | Retrieve compressed data |
| `POST` | `/api/v1/zero-gravity/migrate` | Run data migration/compaction |
| `GET` | `/api/v1/zero-gravity/forecast` | Storage forecast (configurable horizon) |
| `GET` | `/api/v1/zero-gravity/tiers` | Storage tier information |

---

### 9.4 Self-Hosted AI Agent [V4]

**Prefix**: `/api/v1/ai-agent` · **Source**: `suite-core/api/single_agent_router.py` · **Engine**: `suite-core/core/single_agent.py` (819 LOC) · **7 endpoints**

Self-hosted LLM that assumes 4 expert roles sequentially — $0 API tokens vs $6,000/mo multi-vendor.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/ai-agent/health` | Health check |
| `GET` | `/api/v1/ai-agent/status` | Agent engine status and model info |
| `POST` | `/api/v1/ai-agent/decide` | Send decision request to self-hosted agent |
| `POST` | `/api/v1/ai-agent/batch-decide` | Batch decision processing |
| `GET` | `/api/v1/ai-agent/experts` | List expert roles (analyst, pentester, remediator, auditor) |
| `GET` | `/api/v1/ai-agent/backends` | List available LLM backends |
| `DELETE` | `/api/v1/ai-agent/cache` | Clear inference cache |

---

## 10. Error Codes

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

## 11. Rate Limits

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

> Verified via `grep -r '@router\.\(get\|post\|put\|delete\|patch\)'` across all suites on 2026-03-07.

| Phase | Category | Endpoints | Routers |
|-------|----------|-----------|---------|
| **Discover** | 8 Native Scanners (SAST, DAST, Secrets, Container, CSPM, API Fuzzer, Malware, LLM Monitor) | 36 | 8 |
| **Discover** | Scanner Ingest (25 third-party parsers) | 7 | 1 |
| **Discover** | Threat Intelligence Feeds (NVD, KEV, EPSS, OSV, ExploitDB, GitHub) | 31 | 1 |
| **Discover** | Knowledge Graph | 10 | 1 |
| **Discover** | Asset Inventory & SBOM | 19 | 1 |
| **Discover** | OSS Tools (Trivy, Grype, Sigstore, OPA) | 8 | 1 |
| **Discover** | IaC Security Scanner | 7 | 1 |
| **Discover** | IDE Integration | 5 | 1 |
| **Discover** | Fuzzy Identity Resolution | 9 | 1 |
| **Discover** | Code-to-Cloud Mapping | 2 | 1 |
| | **Discover Subtotal** | **134** | **17** |
| **Validate** | MPTE Engine (19-phase verification) | 23 | 1 |
| **Validate** | Micro-Pentest Runner | 19 | 1 |
| **Validate** | MPTE Orchestrator | 8 | 1 |
| **Validate** | Sandbox PoC Verifier (dynamic router) | 8 | 1 |
| **Validate** | FAIL Engine (chaos for AppSec) | 10 | 1 |
| **Validate** | Attack Simulation | 13 | 1 |
| **Validate** | Vulnerability Discovery | 11 | 1 |
| **Validate** | Validation (Compatibility Check) | 5 | 1 |
| | **Validate Subtotal** | **97** | **8** |
| **Remediate** | AutoFix Engine (10 fix types) | 13 | 1 |
| **Remediate** | Remediation Tasks & SLAs | 15 | 1 |
| **Remediate** | Workflows & Automation | 13 | 1 |
| **Remediate** | Connectors (Jira, GitHub, Slack, ServiceNow) | 8 | 1 |
| **Remediate** | Integrations Management | 8 | 1 |
| **Remediate** | Webhooks (bidirectional) | 21 | 1 |
| | **Remediate Subtotal** | **78** | **6** |
| **Comply** | Evidence Engine (RSA-SHA256 signing) | 15 | 1 |
| **Comply** | Compliance Engine (SOC2, PCI-DSS, HIPAA) | 10 | 1 |
| **Comply** | Risk Scoring (multi-factor) | 5 | 1 |
| **Comply** | Audit Trail | 14 | 1 |
| **Comply** | Provenance Tracking | 4 | 1 |
| **Comply** | Business Context | 9 | 2 |
| | **Comply Subtotal** | **57** | **7** |
| **Intelligence** | Brain Pipeline (12-step CTEM) | 32 | 2 |
| **Intelligence** | Analytics & Dashboard | 23 | 1 |
| **Intelligence** | MCP Gateway (AI agent platform) | 8 | 1 |
| **Intelligence** | MCP Protocol (JSON-RPC, SSE) | 10 | 1 |
| **Intelligence** | MCP Server Integration | 10 | 1 |
| **Intelligence** | AI Copilot & Agents | 46 | 2 |
| **Intelligence** | Exposure Cases | 10 | 1 |
| **Intelligence** | Deduplication Engine | 20 | 1 |
| **Intelligence** | Predictions & ML | 10 | 1 |
| **Intelligence** | MindsDB ML Models | 14 | 1 |
| **Intelligence** | Nerve Center | 9 | 1 |
| **Intelligence** | Decision Records | 6 | 1 |
| **Intelligence** | Algorithms | 11 | 1 |
| **Intelligence** | LLM Provider | 6 | 1 |
| **Intelligence** | Graph Risk Analysis | 6 | 1 |
| **Intelligence** | Reachability Analysis | 7 | 1 |
| **Intelligence** | Enhanced Decision Analysis | 4 | 1 |
| **Intelligence** | Streaming / SSE | 4 | 1 |
| | **Intelligence Subtotal** | **236** | **20** |
| **Platform** | Users | 6 | 1 |
| **Platform** | Teams | 8 | 1 |
| **Platform** | Admin | 10 | 1 |
| **Platform** | Auth / SSO | 4 | 1 |
| **Platform** | System Configuration | 5 | 1 |
| **Platform** | Health (root-level) | 4 | 1 |
| **Platform** | Reports | 14 | 1 |
| **Platform** | Policies | 11 | 1 |
| **Platform** | Bulk Operations | 13 | 1 |
| **Platform** | Collaboration | 23 | 1 |
| **Platform** | Marketplace | 14 | 1 |
| **Platform** | Detailed Logs | 5 | 1 |
| **Platform** | Direct @app endpoints | 25 | — |
| | **Platform Subtotal** | **142** | **14+** |
| **Vision** | Self-Learning (V8) | 20 | 1 |
| **Vision** | Zero-Gravity Data (V9) | 7 | 1 |
| **Vision** | Quantum Crypto (V6) | 6 | 1 |
| **Vision** | Self-Hosted AI Agent (V4) | 7 | 1 |
| | **Vision Subtotal** | **40** | **4** |
| | | | |
| | **GRAND TOTAL** | **784** | **72 routers + 2 dynamic + inline** |

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

## Appendix D: Sprint 2 Security Hardening (2026-03-02)

The following hardening was applied to all endpoints by the Backend Hardener agent:

| Category | Change | Scope |
|----------|--------|-------|
| **Input Validation** | Pydantic v2 models on all POST/PUT endpoints | All 784 endpoints |
| **Path Traversal** | File path sanitization on upload endpoints | Scanner Ingest, Evidence, Reports |
| **Size Limits** | Request body size limits (10MB default, 50MB uploads) | All POST endpoints |
| **Injection Prevention** | SQL parameter binding, shell command escaping | Brain Pipeline, Scanner Parsers |
| **XXE Prevention** | XML external entity parsing disabled | Scanner Ingest (XML formats) |
| **SSRF Guard** | URL validation on target parameters | DAST, MPTE, Micro-Pentest |
| **Secrets Leakage** | Response sanitization — no credentials in error messages | All error responses |
| **Thread Safety** | Brain Pipeline made thread-safe with proper locking | Brain Pipeline (12 steps) |
| **Crash Resilience** | Scanner parsers handle malformed input gracefully | All 25 parsers |
| **Health Endpoints** | Every router now has both `/health` and `/status` | 68 routers |

---

*Generated by ALdeci Technical Writer Agent · v5.0 · 2026-03-07 · Sprint 2 Day 4+ Post-Demo · Pillar [V3][V5][V7][V10]*
*Source of truth: `suite-api/apps/api/app.py` (2,893 LOC, 34 router mounts) + 72 router files + 2 dynamic routers across 6 suites*
*Suites: suite-api (238) · suite-core (256) · suite-attack (106) · suite-feeds (31) · suite-evidence-risk (56) · suite-integrations (59) · sandbox (8) · logs (5) · inline @app (25)*
*Verified: grep-audited 2026-03-07, 784 routes mounted, 77+ unique prefixes*
*v5.0 changes: +3 new endpoints: Brain `/trends`, MCP Protocol `/stats`, Self-Learning `/stats`. Suite-core 253→256. Validation section corrected to match actual router (was documenting stale endpoints). 41+ curl examples.*
*v4.0 changes: Full grep audit of all endpoints. Corrected: Inventory (7→19), Sandbox (5→8), Connectors (4→8), Evidence (13→15), Compliance (9→10), MCP Gateway (7→8), MCP Protocol (8→9), Brain (30→31), Vision engines (+4 health endpoints). Appendix A reconciled. 36+ curl examples.*
*v3.2 changes: CTEM+ identity header, suite-level breakdown, deduplicated MPTE Orchestrator section, 34+ curl examples*
*v3.1 changes: +73 previously undocumented endpoints: FAIL Engine (7→10), MPTE Orchestrator (new, 8ep), Audit Trail (4→14), Reports (4→14), Policies (5→11), Collaboration (3→23), Bulk Ops (3→13), Marketplace (4→14), Teams (5→8)*
*v3.0 changes: +11 new sections (Reachability, Enhanced Analysis, Attack Sim, Vuln Discovery, Dedup, Predictions, Algorithms), 30+ curl examples*
