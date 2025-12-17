# FixOps API Documentation

This document provides comprehensive documentation for all FixOps APIs, CLI commands, and Pentagi (Penetration Testing AI) features.

## Quick Start

```bash
# Run the container
docker run -it -p 8000:8000 devopsaico/fixops:latest /bin/bash

# Start the API server
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000 &

# Test health endpoint
curl -H "X-API-Key: demo-token" http://localhost:8000/health | jq
```

## Authentication

All API endpoints require authentication via the `X-API-Key` header:

```bash
curl -H "X-API-Key: demo-token" http://localhost:8000/api/v1/...
```

Default token: `demo-token`

---

## API Endpoints (165+ Main Endpoints)

### 1. Health & Status (4 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| GET | `/version` | API version |
| GET | `/api/v1/status` | Detailed status |

**Example:**
```bash
curl -H "X-API-Key: demo-token" http://localhost:8000/health | jq
```

---

### 2. Enhanced API - CVE Analysis (5 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/enhanced/capabilities` | List capabilities |
| POST | `/api/v1/enhanced/analysis` | Analyze security findings |
| POST | `/api/v1/enhanced/compare-llms` | Compare LLM responses |
| GET | `/api/v1/enhanced/signals` | Get risk signals |
| POST | `/api/v1/enhanced/triage` | Auto-triage findings |

**Example - Analyze CVE-2021-44228 (Log4Shell):**
```bash
curl -X POST http://localhost:8000/api/v1/enhanced/analysis \
  -H "X-API-Key: demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "payment-service",
    "security_findings": [{
      "rule_id": "CVE-2021-44228",
      "severity": "critical",
      "description": "Apache Log4j2 RCE vulnerability (Log4Shell)"
    }],
    "business_context": {
      "environment": "production",
      "criticality": "high"
    }
  }' | jq
```

---

### 3. Pipeline & Inputs (5 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/pipeline/run` | Execute pipeline |
| POST | `/inputs/sbom` | Upload SBOM |
| POST | `/inputs/cve` | Upload CVE data |
| POST | `/inputs/sarif` | Upload SARIF scan |
| POST | `/inputs/design` | Upload design doc |
| POST | `/inputs/context` | Upload context |

**Example - Upload SBOM:**
```bash
curl -X POST http://localhost:8000/inputs/sbom \
  -H "X-API-Key: demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [{
      "type": "library",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    }]
  }' | jq
```

---

### 4. Analytics & Dashboard (14 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/analytics/dashboard/overview` | Dashboard overview |
| GET | `/api/v1/analytics/dashboard/trends` | Trend data |
| GET | `/api/v1/analytics/dashboard/top-risks` | Top risks |
| GET | `/api/v1/analytics/dashboard/compliance-status` | Compliance status |
| GET | `/api/v1/analytics/mttr` | Mean time to remediate |
| GET | `/api/v1/analytics/coverage` | Coverage metrics |
| GET | `/api/v1/analytics/roi` | ROI metrics |
| GET | `/api/v1/analytics/noise-reduction` | Noise reduction stats |
| GET | `/api/v1/analytics/findings` | List findings |
| POST | `/api/v1/analytics/findings` | Create finding |
| GET | `/api/v1/analytics/decisions` | List decisions |
| GET | `/api/v1/analytics/export` | Export data |

---

### 5. Triage & Graph (3 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/triage` | Get triage data |
| GET | `/api/v1/triage/export` | Export triage |
| GET | `/api/v1/graph` | Risk graph |

---

### 6. Workflows (7 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/workflows` | List workflows |
| POST | `/api/v1/workflows` | Create workflow |
| GET | `/api/v1/workflows/{id}` | Get workflow |
| PUT | `/api/v1/workflows/{id}` | Update workflow |
| DELETE | `/api/v1/workflows/{id}` | Delete workflow |
| POST | `/api/v1/workflows/{id}/execute` | Execute workflow |
| GET | `/api/v1/workflows/{id}/history` | Workflow history |

**Example - Create Workflow:**
```bash
curl -X POST http://localhost:8000/api/v1/workflows \
  -H "X-API-Key: demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CVE Response",
    "description": "Auto triage critical CVEs",
    "steps": [{"name": "scan", "action": "run_scan"}]
  }' | jq
```

---

### 7. Pentagi - Penetration Testing AI (12 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/pentagi/requests` | List pentest requests |
| POST | `/api/v1/pentagi/requests` | Create pentest request |
| GET | `/api/v1/pentagi/requests/{id}` | Get request details |
| POST | `/api/v1/pentagi/requests/{id}/start` | Start pentest |
| GET | `/api/v1/pentagi/results` | List results |
| GET | `/api/v1/pentagi/results/{id}` | Get result details |
| GET | `/api/v1/pentagi/stats` | Pentest statistics |
| POST | `/api/v1/pentagi/scan/comprehensive` | Comprehensive scan |
| POST | `/api/v1/pentagi/verify` | Verify finding |
| GET | `/api/v1/pentagi/configs` | List configs |
| POST | `/api/v1/pentagi/configs` | Create config |

**Example - Create Pentest Request:**
```bash
curl -X POST http://localhost:8000/api/v1/pentagi/requests \
  -H "X-API-Key: demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "scope": ["auth", "injection"],
    "cves_to_test": ["CVE-2021-44228"]
  }' | jq
```

---

### 8. Users & Teams (10 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/users/login` | User login |
| GET | `/api/v1/users` | List users |
| POST | `/api/v1/users` | Create user |
| GET | `/api/v1/users/{id}` | Get user |
| PUT | `/api/v1/users/{id}` | Update user |
| DELETE | `/api/v1/users/{id}` | Delete user |
| GET | `/api/v1/teams` | List teams |
| POST | `/api/v1/teams` | Create team |
| GET | `/api/v1/teams/{id}` | Get team |
| PUT | `/api/v1/teams/{id}` | Update team |

---

### 9. Policies (7 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/policies` | List policies |
| POST | `/api/v1/policies` | Create policy |
| GET | `/api/v1/policies/{id}` | Get policy |
| PUT | `/api/v1/policies/{id}` | Update policy |
| DELETE | `/api/v1/policies/{id}` | Delete policy |
| POST | `/api/v1/policies/{id}/validate` | Validate policy |
| POST | `/api/v1/policies/{id}/test` | Test policy |

---

### 10. Reports (8 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reports` | List reports |
| POST | `/api/v1/reports` | Create report |
| GET | `/api/v1/reports/{id}` | Get report |
| GET | `/api/v1/reports/{id}/download` | Download report |
| POST | `/api/v1/reports/schedule` | Schedule report |
| POST | `/api/v1/reports/export/sarif` | Export as SARIF |
| POST | `/api/v1/reports/export/csv` | Export as CSV |
| POST | `/api/v1/reports/export/pdf` | Export as PDF |

---

### 11. Integrations (7 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/integrations` | List integrations |
| POST | `/api/v1/integrations` | Create integration |
| GET | `/api/v1/integrations/{id}` | Get integration |
| PUT | `/api/v1/integrations/{id}` | Update integration |
| DELETE | `/api/v1/integrations/{id}` | Delete integration |
| POST | `/api/v1/integrations/{id}/test` | Test integration |
| POST | `/api/v1/integrations/{id}/sync` | Sync integration |

**Supported Integrations:** Jira, Slack, Teams, GitHub, GitLab, ServiceNow, PagerDuty

---

### 12. Inventory (10 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/inventory/applications` | List applications |
| POST | `/api/v1/inventory/applications` | Create application |
| GET | `/api/v1/inventory/applications/{id}` | Get application |
| GET | `/api/v1/inventory/applications/{id}/components` | Get components |
| GET | `/api/v1/inventory/applications/{id}/dependencies` | Get dependencies |
| GET | `/api/v1/inventory/services` | List services |
| POST | `/api/v1/inventory/services` | Create service |
| GET | `/api/v1/inventory/search` | Search inventory |
| GET | `/api/v1/inventory/stats` | Inventory stats |
| POST | `/api/v1/inventory/import` | Import inventory |

---

### 13. Secrets Detection (4 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/secrets` | List secret findings |
| POST | `/api/v1/secrets` | Create finding |
| POST | `/api/v1/secrets/{id}/resolve` | Resolve finding |
| POST | `/api/v1/secrets/scan` | Scan for secrets |

---

### 14. IaC Security (4 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/iac` | List IaC findings |
| POST | `/api/v1/iac` | Create finding |
| POST | `/api/v1/iac/{id}/resolve` | Resolve finding |
| POST | `/api/v1/iac/scan` | Scan IaC |

---

### 15. IDE Integration (3 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/ide/config` | Get IDE config |
| POST | `/api/v1/ide/analyze` | Analyze code |
| GET | `/api/v1/ide/suggestions` | Get suggestions |

---

### 16. Audit & Compliance (10 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/audit/logs` | Audit logs |
| GET | `/api/v1/audit/user-activity` | User activity |
| GET | `/api/v1/audit/policy-changes` | Policy changes |
| GET | `/api/v1/audit/decision-trail` | Decision trail |
| GET | `/api/v1/audit/compliance/frameworks` | List frameworks |
| GET | `/api/v1/audit/compliance/frameworks/{id}/status` | Framework status |
| GET | `/api/v1/audit/compliance/frameworks/{id}/gaps` | Framework gaps |
| POST | `/api/v1/audit/compliance/assess` | Run assessment |
| GET | `/api/v1/audit/compliance/reports` | Compliance reports |
| POST | `/api/v1/audit/export` | Export audit data |

---

### 17. Bulk Operations (5 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/bulk/findings/update` | Bulk update |
| POST | `/api/v1/bulk/findings/delete` | Bulk delete |
| POST | `/api/v1/bulk/findings/assign` | Bulk assign |
| POST | `/api/v1/bulk/export` | Bulk export |
| POST | `/api/v1/bulk/import` | Bulk import |

---

### 18. SSO & Auth (4 endpoints)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/auth/sso` | List SSO configs |
| POST | `/api/v1/auth/sso` | Create SSO config |
| GET | `/api/v1/auth/sso/{id}` | Get SSO config |
| DELETE | `/api/v1/auth/sso/{id}` | Delete SSO config |

---

### 19. Feedback (1 endpoint)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/feedback` | Submit feedback |

---

## CLI Commands

### Demo Mode
```bash
python -m core.cli demo --mode demo --output out/pipeline-demo.json --pretty
```

### Enterprise Mode
```bash
python -m core.cli demo --mode enterprise --output out/pipeline-enterprise.json --pretty
```

### Run Pipeline
```bash
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --enable policy_automation --enable compliance \
  --design artefacts/design.csv --sbom artefacts/sbom.json \
  --sarif artefacts/scan.sarif --cve artefacts/cve.json \
  --output out/pipeline.json
```

### Show Overlay
```bash
python -m core.cli show-overlay --overlay config/fixops.overlay.yml
```

---

## Micropentest CLI

### Run Demo
```bash
python scripts/micropentest_sidecar.py demo
```

### Attack Chain Simulation
```bash
python scripts/micropentest_sidecar.py attack-chain --cve-source live
```

### Scan Target
```bash
python scripts/micropentest_sidecar.py scan --target https://api.example.com
```

---

## Real CVE Test Cases

### CVE-2021-44228 (Log4Shell) - CVSS 10.0
```bash
curl -X POST http://localhost:8000/api/v1/enhanced/analysis \
  -H "X-API-Key: demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "payment-service",
    "security_findings": [{
      "rule_id": "CVE-2021-44228",
      "severity": "critical",
      "description": "Apache Log4j2 RCE vulnerability - allows remote code execution via JNDI lookup"
    }],
    "business_context": {"environment": "production", "criticality": "high"}
  }' | jq
```

### CVE-2023-44487 (HTTP/2 Rapid Reset) - CVSS 7.5
```bash
curl -X POST http://localhost:8000/api/v1/enhanced/analysis \
  -H "X-API-Key: demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "api-gateway",
    "security_findings": [{
      "rule_id": "CVE-2023-44487",
      "severity": "high",
      "description": "HTTP/2 Rapid Reset Attack - DoS vulnerability affecting HTTP/2 implementations"
    }],
    "business_context": {"environment": "production", "criticality": "high"}
  }' | jq
```

### CVE-2024-3094 (XZ Utils Backdoor) - CVSS 10.0
```bash
curl -X POST http://localhost:8000/api/v1/enhanced/analysis \
  -H "X-API-Key: demo-token" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "linux-server",
    "security_findings": [{
      "rule_id": "CVE-2024-3094",
      "severity": "critical",
      "description": "XZ Utils backdoor - supply chain attack with malicious code in liblzma"
    }],
    "business_context": {"environment": "production", "criticality": "critical"}
  }' | jq
```

---

## Postman Collection

The Postman collection is available at `/app/postman/FixOps-Complete-API-Collection.json`

To export:
```bash
cat /app/postman/FixOps-Complete-API-Collection.json > /tmp/fixops-postman.json
```

Import into Postman desktop app for interactive testing.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_API_TOKEN` | `demo-token` | API authentication token |
| `FIXOPS_MODE` | `demo` | Mode (demo/enterprise) |
| `FIXOPS_DATA_DIR` | `/app/.fixops_data` | Data directory |
| `FIXOPS_DISABLE_TELEMETRY` | `1` | Disable telemetry |

---

## Support

For issues or questions, see the main repository: https://github.com/DevOpsMadDog/Fixops
