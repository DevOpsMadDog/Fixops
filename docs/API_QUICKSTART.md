# ALDECI CTEM+ Platform — API Quick Start

> Version: 1.0 | Base URL: `http://localhost:8000` (or your configured domain)
> Last updated: 2026-04-12

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [First API Call](#2-first-api-call)
3. [Common Workflows](#3-common-workflows)
4. [Webhook Setup](#4-webhook-setup)
5. [SDK Examples](#5-sdk-examples)

---

## 1. Authentication

ALDECI uses API key authentication. Pass your key in one of two ways:

### Header (recommended)

```
X-API-Key: fixops_sk_your_token_here
```

### Query Parameter (avoid in production — key appears in server logs)

```
?api_key=fixops_sk_your_token_here
```

### Generating an API Key

```bash
# Generate a cryptographically secure token
python3 -c "import secrets; print(f'fixops_sk_{secrets.token_urlsafe(32)}')"
```

Set `FIXOPS_API_TOKEN` in your `.env` file to this value, then restart the stack.

### Verifying Your Key

```bash
export ALDECI_URL=http://localhost:8000
export API_TOKEN=fixops_sk_your_token_here

curl -s -H "X-API-Key: $API_TOKEN" "$ALDECI_URL/health"
# {"status": "healthy", "version": "..."}
```

---

## 2. First API Call

### Interactive API Docs

The full OpenAPI specification is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

### Platform Overview

```bash
curl -s -H "X-API-Key: $API_TOKEN" "$ALDECI_URL/api/v1/overview" \
  | python3 -m json.tool
```

Example response:
```json
{
  "findings_total": 1247,
  "critical_open": 12,
  "high_open": 89,
  "scanners_active": 4,
  "compliance_score": 78,
  "last_scan": "2026-04-12T08:30:00Z"
}
```

---

## 3. Common Workflows

### 3.1 Trigger a Scan

```bash
# Trigger a container image scan
curl -X POST "$ALDECI_URL/api/v1/scans" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "container",
    "target": "nginx:1.27",
    "scanner": "trivy",
    "severity_threshold": "MEDIUM",
    "notify_on_complete": true
  }'
# Returns: {"scan_id": "sc_abc123", "status": "queued"}
```

### 3.2 Poll Scan Status

```bash
SCAN_ID=sc_abc123

curl -s -H "X-API-Key: $API_TOKEN" \
  "$ALDECI_URL/api/v1/scans/$SCAN_ID" \
  | python3 -m json.tool
```

### 3.3 List Findings

```bash
# All critical/high open findings
curl -s -H "X-API-Key: $API_TOKEN" \
  "$ALDECI_URL/api/v1/findings?severity=CRITICAL,HIGH&status=open&limit=50" \
  | python3 -m json.tool
```

#### Filtering Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | Comma-separated |
| `status` | `open`, `in_progress`, `resolved`, `accepted` | Finding status |
| `scanner` | `trivy`, `snyk`, `semgrep`, `github`, `aws` | Source scanner |
| `limit` | 1–1000 | Results per page (default 100) |
| `offset` | integer | Pagination offset |
| `sort` | `severity`, `cvss`, `epss`, `created_at` | Sort field |

### 3.4 Get a Specific Finding

```bash
curl -s -H "X-API-Key: $API_TOKEN" \
  "$ALDECI_URL/api/v1/findings/finding-uuid-here" \
  | python3 -m json.tool
```

### 3.5 Update Finding Status

```bash
# Accept a risk / mark as false positive
curl -X PATCH "$ALDECI_URL/api/v1/findings/finding-uuid-here" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "accepted",
    "reason": "Compensating control in place — network segmentation applied",
    "accepted_by": "jane.smith@acme.com",
    "review_date": "2026-07-12"
  }'
```

### 3.6 Run the Brain Pipeline

The 12-step Brain Pipeline processes raw findings through enrichment, deduplication, risk scoring, and LLM Council analysis:

```bash
curl -X POST "$ALDECI_URL/api/v1/pipeline/run" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "full",
    "enable_council": true,
    "finding_ids": ["finding-uuid-1", "finding-uuid-2"]
  }'
```

### 3.7 Compliance Status

```bash
# Get compliance posture for all active frameworks
curl -s -H "X-API-Key: $API_TOKEN" \
  "$ALDECI_URL/api/v1/compliance/summary" \
  | python3 -m json.tool

# Get control-level detail for a specific framework
curl -s -H "X-API-Key: $API_TOKEN" \
  "$ALDECI_URL/api/v1/compliance/frameworks/soc2/controls" \
  | python3 -m json.tool
```

### 3.8 Export a Report

```bash
# Generate PDF report (async — returns job_id)
curl -X POST "$ALDECI_URL/api/v1/reports/generate" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "executive_summary",
    "format": "pdf",
    "date_range": {"start": "2026-01-01", "end": "2026-04-12"},
    "frameworks": ["soc2", "nist_csf"]
  }'

# Download when ready
curl -H "X-API-Key: $API_TOKEN" \
  "$ALDECI_URL/api/v1/reports/{job_id}/download" \
  -o report.pdf
```

### 3.9 Submit Raw Scanner Output

Send SARIF or vendor JSON directly for normalization:

```bash
# Submit Trivy SARIF output
curl -X POST "$ALDECI_URL/api/v1/intake/sarif" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @trivy-results.sarif.json

# Submit Snyk JSON output
curl -X POST "$ALDECI_URL/api/v1/intake/snyk" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @snyk-results.json
```

---

## 4. Webhook Setup

### 4.1 Register a Webhook

```bash
curl -X POST "$ALDECI_URL/api/v1/webhooks" \
  -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-cd-gate",
    "url": "https://your-ci-system.com/aldeci/events",
    "secret": "your-webhook-signing-secret",
    "events": [
      "finding.created",
      "finding.severity_changed",
      "scan.completed",
      "sla.breached"
    ],
    "severity_filter": ["CRITICAL", "HIGH"]
  }'
```

### 4.2 Webhook Payload

All events follow this envelope:

```json
{
  "event": "finding.created",
  "timestamp": "2026-04-12T10:30:00Z",
  "webhook_id": "wh_abc123",
  "signature": "sha256=...",
  "data": {
    "finding_id": "...",
    "severity": "CRITICAL",
    "title": "...",
    "cve": "CVE-2024-XXXX",
    "cvss": 9.8,
    "epss": 0.94
  }
}
```

### 4.3 Verify Webhook Signature

```python
import hmac, hashlib

def verify_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)
```

### 4.4 Available Event Types

| Event | Triggered When |
|-------|---------------|
| `finding.created` | New finding ingested |
| `finding.resolved` | Finding marked resolved |
| `finding.severity_changed` | Severity upgraded or downgraded |
| `scan.completed` | Scanner run finished |
| `sla.warning` | Finding at 75% of SLA window |
| `sla.breached` | Finding exceeded SLA |
| `compliance.control_failed` | Compliance control dropped to failing |
| `pipeline.completed` | Brain Pipeline run finished |

---

## 5. SDK Examples

### 5.1 Python — Basic Client

```python
import httpx
from typing import Any

class ALDECIClient:
    def __init__(self, base_url: str, api_key: str):
        self.client = httpx.Client(
            base_url=base_url,
            headers={"X-API-Key": api_key},
            timeout=30.0,
        )

    def get_findings(self, severity: list[str] = None, status: str = "open") -> list[dict]:
        params = {"status": status}
        if severity:
            params["severity"] = ",".join(severity)
        r = self.client.get("/api/v1/findings", params=params)
        r.raise_for_status()
        return r.json()["items"]

    def trigger_scan(self, target: str, scanner: str = "trivy") -> dict:
        r = self.client.post("/api/v1/scans", json={"target": target, "scanner": scanner})
        r.raise_for_status()
        return r.json()

    def close(self):
        self.client.close()


# Usage
client = ALDECIClient("http://localhost:8000", "fixops_sk_your_token")
findings = client.get_findings(severity=["CRITICAL", "HIGH"])
print(f"Open critical/high findings: {len(findings)}")

scan = client.trigger_scan("nginx:1.27")
print(f"Scan queued: {scan['scan_id']}")
client.close()
```

### 5.2 Python — CI/CD Quality Gate

```python
#!/usr/bin/env python3
"""Fail CI if critical vulnerabilities found in a container image."""

import sys
import time
import httpx

ALDECI_URL = "http://localhost:8000"
API_TOKEN = "fixops_sk_your_token"
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "myapp:latest"

client = httpx.Client(base_url=ALDECI_URL, headers={"X-API-Key": API_TOKEN})

# Trigger scan
scan = client.post("/api/v1/scans", json={"type": "container", "target": IMAGE, "scanner": "trivy"}).json()
scan_id = scan["scan_id"]
print(f"Scan started: {scan_id}")

# Poll until complete (max 5 minutes)
for _ in range(60):
    status = client.get(f"/api/v1/scans/{scan_id}").json()
    if status["state"] == "completed":
        break
    time.sleep(5)

# Check results
findings = client.get("/api/v1/findings", params={
    "scan_id": scan_id, "severity": "CRITICAL", "status": "open"
}).json()

critical_count = findings["total"]
if critical_count > 0:
    print(f"FAIL: {critical_count} critical vulnerabilities found in {IMAGE}")
    sys.exit(1)

print(f"PASS: No critical vulnerabilities in {IMAGE}")
sys.exit(0)
```

### 5.3 curl — Quick Reference

```bash
# Set once in your shell
export ALDECI_URL=http://localhost:8000
export API_KEY=fixops_sk_your_token
alias aldeci='curl -s -H "X-API-Key: $API_KEY" -H "Content-Type: application/json"'

# Health
aldeci $ALDECI_URL/health | jq .

# List critical findings
aldeci "$ALDECI_URL/api/v1/findings?severity=CRITICAL&status=open" | jq '.items[].title'

# Trigger scan
aldeci -X POST $ALDECI_URL/api/v1/scans -d '{"target":"nginx:latest","scanner":"trivy"}' | jq .

# Get compliance summary
aldeci $ALDECI_URL/api/v1/compliance/summary | jq .

# List active scanners
aldeci $ALDECI_URL/api/v1/scanners | jq '.[] | {name,status,last_run}'
```

---

*Full API reference is auto-generated at `/docs`. For authentication options see `docs/ADMIN_GUIDE.md`. For security controls see `docs/SECURITY_WHITEPAPER.md`.*
