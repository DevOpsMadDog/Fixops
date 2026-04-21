# ALDECI API Reference v2

> **Version:** 2.0 | **Base URL:** `https://<your-instance>/` | **Updated:** 2026-04-22
>
> ALDECI exposes 568+ REST endpoints across 334 security engines. This document covers the **top 50 most critical endpoints** grouped by domain, suitable for enterprise evaluation and integration planning.

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Alert Triage](#2-alert-triage)
3. [Incident Management](#3-incident-management)
4. [Vulnerability Management](#4-vulnerability-management)
5. [Compliance](#5-compliance)
6. [CSPM / Cloud Security](#6-cspm--cloud-security)
7. [ASPM / Application Security](#7-aspm--application-security)
8. [Threat Intelligence](#8-threat-intelligence)
9. [Attack Path Analysis](#9-attack-path-analysis)
10. [Risk Management](#10-risk-management)
11. [Brain / Knowledge Graph](#11-brain--knowledge-graph)
12. [SIEM Integration](#12-siem-integration)
13. [Prowler CSPM](#13-prowler-cspm)
14. [ServiceNow Integration](#14-servicenow-integration)
15. [CI/CD Integration](#15-cicd-integration)

---

## Authentication

All API requests (except SSO login flow endpoints) require authentication via one of:

| Method | Header | Description |
|--------|--------|-------------|
| **API Key** | `X-API-Key: aldeci_...` | Primary method. Keys are created via `/api/v1/auth/keys`. |
| **Bearer Token (SSO)** | `Authorization: Bearer <jwt>` | Issued after SAML 2.0 / OIDC login flow. |
| **Query Parameter** | `?api_key=aldeci_...` | Convenience fallback for tools that cannot set headers. |

All endpoints are **multi-tenant**. The `org_id` query parameter (default: `"default"`) scopes all data to the caller's organization. RBAC roles: `admin`, `analyst`, `security_engineer`, `auditor`, `responder`, `readonly`.

### Rate Limiting

Sliding-window rate limiter: 60 requests/minute per API key (configurable per key). Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header.

---

## 1. Authentication

**Prefix:** `/api/v1/auth/`

Manage API keys and enterprise SSO (SAML 2.0 / OIDC).

### API Key Management (`/api/v1/auth/keys`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/keys` | Create a new API key. Plaintext returned **once**. |
| `GET` | `/api/v1/auth/keys?org_id=` | List all API keys for an org (no secrets exposed). |
| `GET` | `/api/v1/auth/keys/{key_id}` | Get a single API key by ID. |
| `PUT` | `/api/v1/auth/keys/{key_id}` | Update key metadata (name, scopes, rate_limit). |
| `POST` | `/api/v1/auth/keys/{key_id}/rotate` | Rotate a key. Old key deactivated, new plaintext returned once. |
| `POST` | `/api/v1/auth/keys/{key_id}/revoke` | Revoke a key immediately. |
| `GET` | `/api/v1/auth/keys/{key_id}/usage` | Get usage statistics for a key. |

**Create Key Request:**
```json
{
  "name": "CI Pipeline Key",
  "org_id": "acme-corp",
  "role": "analyst",
  "scopes": ["read:findings", "write:scans"],
  "expires_at": "2027-01-01T00:00:00Z",
  "rate_limit": 120,
  "description": "Used by GitHub Actions pipeline"
}
```

**Create Key Response (plaintext shown once):**
```json
{
  "id": "key_abc123",
  "name": "CI Pipeline Key",
  "prefix": "aldeci_ci_",
  "raw_key": "aldeci_ci_sk_live_a1b2c3d4e5f6...",
  "org_id": "acme-corp",
  "role": "analyst",
  "scopes": ["read:findings", "write:scans"],
  "is_active": true,
  "created_at": "2026-04-22T10:00:00Z"
}
```

### SSO (`/api/v1/auth/sso`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/auth/sso/providers` | List configured SSO providers (Okta, Azure AD, etc.). |
| `GET` | `/api/v1/auth/sso/{provider}/login` | Initiate SSO flow -- redirects to IdP. |
| `POST` | `/api/v1/auth/sso/{provider}/callback` | IdP callback. Issues ALDECI JWT on success. |
| `GET` | `/api/v1/auth/sso/session` | Return current SSO session info from Bearer token. |
| `POST` | `/api/v1/auth/sso/logout` | Single logout -- invalidates SSO session. |

**SSO Callback Response:**
```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "email": "alice@acme.com",
  "name": "Alice Chen",
  "roles": ["admin", "security_engineer"],
  "groups": ["soc-team", "vuln-mgmt"],
  "provider": "okta"
}
```

---

## 2. Alert Triage

**Prefix:** `/api/v1/alert-triage/` | **Auth:** API Key + RBAC (analyst+) | **Engine:** `AlertTriageEngine`

Centralized alert ingestion and triage workflow across SIEM, EDR, NDR, Cloud, WAF, IDS, and Firewall sources. Priority is auto-assigned from severity.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/alert-triage/alerts` | Ingest a new alert. Priority auto-assigned from severity. |
| `GET` | `/api/v1/alert-triage/alerts` | List alerts with filters (source_system, severity, status, priority). |
| `GET` | `/api/v1/alert-triage/alerts/{alert_id}` | Retrieve a single alert by ID. |
| `PATCH` | `/api/v1/alert-triage/alerts/{alert_id}/triage` | Update triage status, assignee, and notes. |
| `POST` | `/api/v1/alert-triage/bulk-triage` | Apply the same action to multiple alerts at once. |
| `GET` | `/api/v1/alert-triage/queue` | Prioritized triage queue (new + triaging, P1 first). |
| `GET` | `/api/v1/alert-triage/stats` | Aggregate triage statistics. |
| `GET` | `/api/v1/alert-triage/alerts/{alert_id}/context` | TrustGraph cross-domain context for an alert. |
| `POST` | `/api/v1/alert-triage/investigate/{alert_id}` | Full SOC investigation: correlate across all domains. |

**Ingest Alert Request:**
```json
{
  "title": "Suspicious outbound connection to C2 domain",
  "source_system": "edr",
  "severity": "critical",
  "raw_alert_json": {
    "host": "ws-042.internal",
    "dst_ip": "185.220.101.42",
    "process": "powershell.exe"
  }
}
```

**Triage Alert Request:**
```json
{
  "triage_status": "investigating",
  "assigned_to": "alice.chen",
  "triage_notes": "Confirmed C2 beacon. Isolating host.",
  "escalation_reason": null
}
```

**Investigate Response** (correlated across all security domains):
```json
{
  "alert": { "...full alert record..." },
  "related_alerts": [ "...same source/severity in last 24h..." ],
  "affected_assets": ["ws-042.internal", "185.220.101.42"],
  "incident_history": [ "...matching asset incidents..." ],
  "ioc_summary": { "ips": ["185.220.101.42"], "domains": [], "hashes": [] },
  "graphrag_context": { "...TrustGraph cross-domain context..." },
  "recommended_playbook": "edr_critical_containment"
}
```

---

## 3. Incident Management

**Prefix:** `/api/v1/incident-orchestration/` | **Auth:** API Key + RBAC (analyst+) | **Engine:** `IncidentOrchestrationEngine`

Full incident lifecycle management with 5-state workflow (open, investigating, contained, resolved, closed), timeline events, and MTTR metrics.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/incident-orchestration/incidents` | Create a new security incident. |
| `GET` | `/api/v1/incident-orchestration/incidents` | List incidents (filters: severity, status). |
| `GET` | `/api/v1/incident-orchestration/incidents/{id}` | Get a single incident by ID. |
| `PATCH` | `/api/v1/incident-orchestration/incidents/{id}/status` | Transition incident status. |
| `PATCH` | `/api/v1/incident-orchestration/incidents/{id}/assign` | Assign incident to a user or team. |
| `POST` | `/api/v1/incident-orchestration/incidents/{id}/timeline` | Add a timeline event. |
| `GET` | `/api/v1/incident-orchestration/incidents/{id}/timeline` | Get the full ordered timeline. |
| `GET` | `/api/v1/incident-orchestration/metrics` | Aggregated metrics: MTTD, MTTR, counts by severity. |
| `GET` | `/api/v1/incident-orchestration/incidents/{id}/context` | TrustGraph cross-domain context. |

**Create Incident Request:**
```json
{
  "title": "Ransomware detected on finance server",
  "severity": "critical",
  "type": "malware",
  "source": "edr_alert_42"
}
```

**Metrics Response:**
```json
{
  "total_incidents": 47,
  "open": 3,
  "resolved": 38,
  "mttr_hours": 4.2,
  "mttd_hours": 0.8,
  "by_severity": { "critical": 5, "high": 12, "medium": 22, "low": 8 }
}
```

---

## 4. Vulnerability Management

ALDECI provides four complementary vulnerability management APIs.

### 4a. Vulnerability Intelligence (`/api/v1/vuln-intel/`)

**Engine:** `VulnIntelligenceEngine` | CVE tracking with EPSS, KEV, and PURL-based package lookup.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/vuln-intel/cves` | Add or upsert CVE intelligence. |
| `GET` | `/api/v1/vuln-intel/cves` | List CVEs (filters: severity, kev_listed, exploit_available, status). |
| `GET` | `/api/v1/vuln-intel/cves/{cve_id}` | Get full CVE details. |
| `GET` | `/api/v1/vuln-intel/cves/{cve_id}/context` | Enriched CVE context: affected SBOM components + fix versions + risk score. |
| `PATCH` | `/api/v1/vuln-intel/cves/{cve_id}/status` | Update CVE lifecycle status. |
| `GET` | `/api/v1/vuln-intel/packages/{purl}/issues` | PURL-based package vulnerability lookup (Snyk API parity). |
| `POST` | `/api/v1/vuln-intel/sync` | Pull CVE findings from Brain graph into vuln-intel DB. |
| `GET` | `/api/v1/vuln-intel/stats` | Aggregated vulnerability intelligence statistics. |

**Add CVE Request:**
```json
{
  "cve_id": "CVE-2024-3094",
  "title": "XZ Utils backdoor",
  "cvss_score": 10.0,
  "epss_score": 0.97,
  "kev_listed": true,
  "severity": "critical",
  "exploit_available": true,
  "status": "new"
}
```

**PURL Lookup:** `GET /api/v1/vuln-intel/packages/pkg:npm/lodash@4.17.21/issues`

### 4b. Vulnerability Workflow (`/api/v1/vuln-workflow/`)

**Engine:** `VulnerabilityWorkflowEngine` | Remediation workflow lifecycle with SLA tiers.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/vuln-workflow/workflows` | Create remediation workflow with auto-computed SLA due date. |
| `GET` | `/api/v1/vuln-workflow/workflows` | List workflows (filters: type, status, priority, sla_tier). |
| `PATCH` | `/api/v1/vuln-workflow/workflows/{id}/status` | Transition workflow status (7 states). |
| `POST` | `/api/v1/vuln-workflow/workflows/{id}/comments` | Add a comment to a workflow thread. |
| `GET` | `/api/v1/vuln-workflow/stats` | Totals, overdue count, average resolution days. |

**SLA Tiers:** `p1` (1 day), `p2` (7 days), `p3` (30 days), `p4` (90 days)

### 4c. Vulnerability Scanning (`/api/v1/vuln-scans/`)

**Engine:** `VulnScanEngine` | Manages scan lifecycle across 8 scanner types.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/vuln-scans/scans` | Create a new scan (Nessus, Qualys, Rapid7, OpenVAS, Nuclei, Trivy, Grype, custom). |
| `GET` | `/api/v1/vuln-scans/scans` | List scans with filters. |
| `PATCH` | `/api/v1/vuln-scans/scans/{id}/status` | Update scan status (pending, running, completed, failed, cancelled). |
| `POST` | `/api/v1/vuln-scans/scans/{id}/findings` | Add a finding to a scan. |
| `GET` | `/api/v1/vuln-scans/findings` | List findings (filters: scan_id, severity, finding_status). |
| `GET` | `/api/v1/vuln-scans/stats` | Aggregate scan and finding statistics. |

---

## 5. Compliance

**Prefix:** `/api/v1/compliance-planner/` | **Engine:** `CompliancePlanner`

Gap remediation planning across 7 frameworks: SOC2, PCI-DSS, HIPAA, ISO27001, NIST-CSF, CIS, GDPR.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/compliance-planner/generate/{framework}` | Generate a remediation plan for a framework. |
| `GET` | `/api/v1/compliance-planner/plans` | List all remediation plans for the org. |
| `GET` | `/api/v1/compliance-planner/plans/{framework}` | Get a remediation plan for a specific framework. |
| `GET` | `/api/v1/compliance-planner/remediations` | List remediation items (filters: framework, status, priority). |
| `PUT` | `/api/v1/compliance-planner/remediations/{id}/status` | Update implementation status. |
| `PUT` | `/api/v1/compliance-planner/remediations/{id}/assign` | Assign a remediation item to a person with target date. |
| `GET` | `/api/v1/compliance-planner/effort` | Total estimated effort hours by framework and priority. |
| `GET` | `/api/v1/compliance-planner/blocked` | All remediations currently in BLOCKED status. |
| `GET` | `/api/v1/compliance-planner/overdue` | Remediations past their target date and not yet completed. |
| `GET` | `/api/v1/compliance-planner/stats` | Aggregate stats: by framework, by status, completion rates. |

**Generate Plan Request:**
```json
{
  "gaps": [
    {
      "control_id": "CC6.1",
      "control_name": "Logical and Physical Access Controls",
      "gap_description": "No MFA enforcement on admin accounts",
      "findings_that_fix": ["FINDING-001", "FINDING-002"]
    }
  ]
}
```

**Remediation Statuses:** `not_started`, `in_progress`, `completed`, `blocked`, `deferred`

---

## 6. CSPM / Cloud Security

### 6a. Cloud Workload Protection (`/api/v1/cwpp/`)

**Engine:** `CWPPEngine` | Runtime workload protection for containers, VMs, serverless, and Kubernetes pods.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/cwpp/workloads` | Register a workload for protection. |
| `GET` | `/api/v1/cwpp/workloads` | List workloads (filter by type). |
| `POST` | `/api/v1/cwpp/workloads/{id}/detect` | Detect threats from runtime events (process_exec, network_conn, file_write). |
| `POST` | `/api/v1/cwpp/workloads/{id}/compliance` | Check workload compliance (cis_docker, k8s_bench, nist_800_190). |
| `GET` | `/api/v1/cwpp/threats` | Get threat events across all workloads. |
| `GET` | `/api/v1/cwpp/summary` | Protection summary for an org. |

**Detect Threats Request:**
```json
{
  "events": [
    {
      "event_type": "process_exec",
      "details": { "process": "/bin/bash", "parent": "java", "user": "root" }
    },
    {
      "event_type": "network_conn",
      "details": { "dst_ip": "185.220.101.42", "dst_port": 443 }
    }
  ]
}
```

### 6b. Posture Score (`/api/v1/posture-score/`)

**Engine:** `PostureScoreEngine` | Weighted security posture scoring with component-level granularity.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/posture-score/compute` | Calculate weighted posture score from current components. |
| `GET` | `/api/v1/posture-score/current` | Most recently saved posture score. |
| `GET` | `/api/v1/posture-score/history?days=30` | Score snapshots for the last N days. |
| `POST` | `/api/v1/posture-score/components/{name}` | Upsert a single domain component score (0-100). |
| `GET` | `/api/v1/posture-score/stats` | Summary: current score, grade, 30d trend, days at risk. |

---

## 7. ASPM / Application Security

**Prefix:** `/api/v1/app-security/` | **Auth:** API Key | **Engine:** `AppSecurityEngine`

Application security posture management: application inventory, SAST/DAST scans, finding lifecycle.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/app-security/apps` | Register an application in the inventory. |
| `GET` | `/api/v1/app-security/apps` | List all registered applications. |
| `POST` | `/api/v1/app-security/scans` | Create a SAST or DAST scan record. |
| `GET` | `/api/v1/app-security/scans` | List all scans (filters: app_id, scan_type). |
| `GET` | `/api/v1/app-security/findings` | List findings (filters: app_id, severity, status). |
| `POST` | `/api/v1/app-security/findings` | Create a new application security finding. |
| `PATCH` | `/api/v1/app-security/findings/{id}/status` | Update finding status (open, false_positive, accepted, fixed). |
| `GET` | `/api/v1/app-security/stats` | Org-level AppSec statistics. |

**Register Application Request:**
```json
{
  "name": "payment-service",
  "app_type": "web",
  "repo_url": "https://github.com/acme/payment-service",
  "tech_stack": ["python", "fastapi", "postgresql"],
  "risk_rating": "high"
}
```

**Create Finding Request:**
```json
{
  "app_id": "app_abc123",
  "vuln_type": "sql_injection",
  "severity": "critical",
  "cwe_id": "CWE-89",
  "description": "Unsanitized user input in login query",
  "file_path": "src/auth/login.py",
  "line_number": 42,
  "owasp_category": "A03:2021"
}
```

### Dependency Scanner (`/api/v1/dep-scanner/`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/dep-scanner/scan-requirements` | Scan a requirements.txt file. |
| `POST` | `/api/v1/dep-scanner/scan-package-json` | Scan a package.json file. |
| `GET` | `/api/v1/dep-scanner/vulnerable` | List vulnerable installed packages. |
| `GET` | `/api/v1/dep-scanner/upgrade-plan` | Prioritized upgrade plan. |

---

## 8. Threat Intelligence

### 8a. Threat Intel Fusion (`/api/v1/threat-intel-fusion/`)

**Engine:** `ThreatIntelFusionEngine` | Multi-source indicator fusion with consensus confidence scoring and TLP classification.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/threat-intel-fusion/sources` | Add an intel source (OSINT, commercial, internal). |
| `GET` | `/api/v1/threat-intel-fusion/sources` | List intel sources. |
| `POST` | `/api/v1/threat-intel-fusion/indicators` | Ingest a threat indicator (IP, domain, hash, URL, email). |
| `GET` | `/api/v1/threat-intel-fusion/indicators/search?q=` | Search indicators by value. |
| `GET` | `/api/v1/threat-intel-fusion/indicators/high-confidence?min_confidence=80` | Get high-confidence indicators above threshold. |
| `POST` | `/api/v1/threat-intel-fusion/indicators/expire` | Expire old indicators past their expiry date. |
| `GET` | `/api/v1/threat-intel-fusion/fuse/{indicator_value}` | Fuse an indicator from all sources (consensus confidence). |
| `GET` | `/api/v1/threat-intel-fusion/stats` | Fusion statistics. |

**Ingest Indicator Request:**
```json
{
  "source_id": "src_otx_001",
  "indicator_type": "ip",
  "value": "185.220.101.42",
  "confidence": 85,
  "tags": ["c2", "cobalt-strike"],
  "expiry_days": 30
}
```

**Fuse Response** (consensus from all sources):
```json
{
  "indicator_value": "185.220.101.42",
  "indicator_type": "ip",
  "sources": 4,
  "consensus_confidence": 91,
  "tlp_level": "amber",
  "tags": ["c2", "cobalt-strike", "tor-exit"],
  "first_seen": "2026-03-15T08:00:00Z",
  "last_seen": "2026-04-22T06:30:00Z"
}
```

---

## 9. Attack Path Analysis

**Prefix:** `/api/v1/attack-paths/` | **Engine:** `AttackPathEngine`

Model lateral movement through a network graph, find paths from entry points to crown jewel assets, and compute blast radius for compromised hosts.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/attack-paths/nodes` | Add a network node to the attack graph. |
| `GET` | `/api/v1/attack-paths/nodes` | List nodes (filter by crown_jewel status). |
| `POST` | `/api/v1/attack-paths/edges` | Add a lateral movement edge between nodes. |
| `POST` | `/api/v1/attack-paths/analyze` | Find attack paths from an entry point to crown jewels. |
| `POST` | `/api/v1/attack-paths/blast-radius` | Compute blast radius from a compromised host. |
| `GET` | `/api/v1/attack-paths/crown-jewels-at-risk` | List crown jewels and which entry points can reach them. |
| `GET` | `/api/v1/attack-paths/toxic-combinations` | Detect assets where chained medium findings create critical risk. |
| `GET` | `/api/v1/attack-paths/stats` | Attack graph statistics. |

**Analyze Request:**
```json
{
  "entry_point": "vpn-gateway-01",
  "target": null,
  "max_hops": 5,
  "org_id": "acme-corp"
}
```

**Toxic Combinations Response:**
```json
[
  {
    "asset": { "node_id": "db-prod-01", "name": "Production DB", "risk_score": 45 },
    "findings": ["CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9012"],
    "combined_risk": 92,
    "attack_chain": [
      { "node_id": "vpn-gw", "protocol": "tcp", "port": 443 }
    ]
  }
]
```

---

## 10. Risk Management

### 10a. Composite Risk Scoring (`/api/v1/risk/`)

**Engine:** `CompositeRiskScorer` | ML-powered multi-signal risk scores combining CVSS, EPSS, KEV, asset criticality, SLA breach risk, and lateral movement signals.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/risk/score/finding` | Score a single finding (0-100 composite). |
| `POST` | `/api/v1/risk/score/asset` | Score an asset (worst-case + average blend). |
| `POST` | `/api/v1/risk/score/batch` | Batch score up to 100 findings. |
| `GET` | `/api/v1/risk/top?n=10` | Top N highest-scoring risks for the org. |
| `GET` | `/api/v1/risk/score/{asset_id}` | Latest composite score for an asset. |

**Score Response:**
```json
{
  "score_id": "score_xyz",
  "asset_id": "db-prod-01",
  "score": 87.3,
  "grade": "F",
  "factors": [
    { "name": "cvss", "value": 9.8, "weight": 0.3, "explanation": "CVSS base score" },
    { "name": "epss", "value": 0.94, "weight": 0.25, "explanation": "94% exploit probability" },
    { "name": "kev_listed", "value": 1.0, "weight": 0.2, "explanation": "In CISA KEV catalog" },
    { "name": "asset_criticality", "value": 0.9, "weight": 0.15, "explanation": "Crown jewel asset" },
    { "name": "lateral_reach", "value": 0.7, "weight": 0.1, "explanation": "3-hop path to 5 assets" }
  ],
  "scored_at": "2026-04-22T10:30:00Z"
}
```

### 10b. Posture Score (`/api/v1/posture-score/`)

See [Section 6b](#6b-posture-score-apiv1posture-score) above.

---

## 11. Brain / Knowledge Graph

**Prefix:** `/api/v1/brain/` | **Engine:** `KnowledgeBrain`

Central Knowledge Graph powering cross-domain correlation. Every security entity (CVE, finding, asset, remediation, scan) is a node; relationships are edges. Supports BFS traversal, path finding, risk scoring, and GraphRAG-enhanced AI copilot queries.

### Graph Operations

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/brain/nodes` | Create or update a node in the Knowledge Graph. |
| `GET` | `/api/v1/brain/nodes` | Query nodes (filters: node_type, org_id, full-text search). |
| `GET` | `/api/v1/brain/nodes/{node_id}` | Get a specific node by ID. |
| `DELETE` | `/api/v1/brain/nodes/{node_id}` | Delete a node and all its edges. |
| `POST` | `/api/v1/brain/edges` | Create an edge between two nodes. |
| `GET` | `/api/v1/brain/edges/{node_id}` | Get all edges connected to a node (in/out/both). |

### Traversal and Analytics

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/brain/neighbors/{node_id}?depth=2` | Get neighbors up to N hops deep. |
| `GET` | `/api/v1/brain/paths?source_id=X&target_id=Y` | Find all paths between two nodes (max 10 hops). |
| `GET` | `/api/v1/brain/most-connected?limit=10` | Highest-degree nodes in the graph. |
| `GET` | `/api/v1/brain/risk/{node_id}` | Composite risk score for a node based on graph context. |
| `GET` | `/api/v1/brain/stats` | Graph statistics: node/edge counts, density, type breakdown. |

### Bulk Ingest

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/brain/ingest/cve` | Ingest a CVE into the Knowledge Brain. |
| `POST` | `/api/v1/brain/ingest/finding` | Ingest a security finding. |
| `POST` | `/api/v1/brain/ingest/scan` | Ingest a scan result with findings. |
| `POST` | `/api/v1/brain/ingest/asset` | Ingest an asset. |
| `POST` | `/api/v1/brain/ingest/remediation` | Ingest a remediation task. |

### AI Copilot (`/api/v1/copilot/`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/copilot/ask` | Stateless security Q&A. Answers CWE questions and security-ops queries using GraphRAG. |
| `POST` | `/api/v1/copilot/sessions` | Create a new chat session with a specialized agent. |
| `POST` | `/api/v1/copilot/sessions/{id}/messages` | Send a message and get LLM-powered response (Claude/GPT-4). |
| `POST` | `/api/v1/copilot/quick/analyze` | One-shot CVE/finding analysis with EPSS/KEV enrichment. |
| `GET` | `/api/v1/copilot/suggestions` | Proactive security suggestions based on Knowledge Graph data. |

**Copilot Agent Types:** `security_analyst`, `pentest`, `compliance`, `remediation`, `general`

**Ask Request:**
```json
{
  "question": "What are our top risks right now?",
  "context": { "cwe_id": null, "language": null }
}
```

**Ask Response (GraphRAG-enriched):**
```json
{
  "answer": "## Top Security Risks\n\nBased on 964 relationships in the knowledge graph...",
  "source": "graphrag_security_insight",
  "intent": "top_risks",
  "confidence": 0.85,
  "recommended_actions": [
    { "action": "Review critical findings", "endpoint": "/api/v1/findings?severity=critical" },
    { "action": "Run risk aggregation", "endpoint": "/api/v1/risk-aggregator/summary" }
  ]
}
```

---

## 12. SIEM Integration

**Prefix:** `/api/v1/siem/` | **Engine:** `SIEMIntegrationEngine`

Bidirectional SIEM integration: source registration, event ingestion (structured and raw syslog/CEF), correlation alerts, and aggregate statistics.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/siem/sources` | Register a new SIEM source. |
| `GET` | `/api/v1/siem/sources` | List SIEM sources (filters: source_type, status). |
| `POST` | `/api/v1/siem/events` | Ingest a structured SIEM event. |
| `GET` | `/api/v1/siem/events` | List events (filters: source_id, severity, event_type). |
| `POST` | `/api/v1/siem/ingest` | Parse and ingest raw syslog (RFC 3164/5424) or CEF log line. |
| `POST` | `/api/v1/siem/alerts` | Create a correlation alert from matched events. |
| `GET` | `/api/v1/siem/alerts` | List correlation alerts (filters: status, severity). |
| `PUT` | `/api/v1/siem/alerts/{alert_id}/acknowledge` | Acknowledge a correlation alert. |
| `GET` | `/api/v1/siem/stats` | Aggregate SIEM statistics. |

**Raw Ingest Request (syslog/CEF):**
```json
{
  "org_id": "acme-corp",
  "raw": "CEF:0|TrendMicro|DeepSecurity|12.0|1001|Malware Detected|9|src=10.0.1.42 dst=192.168.1.100 fname=/tmp/payload.exe",
  "format": "auto"
}
```

**Raw Ingest Response:**
```json
{
  "status": "ingested",
  "format": "cef",
  "event": {
    "event_id": "evt_abc123",
    "source_id": "auto",
    "event_type": "malware",
    "severity": "critical",
    "parsed_fields": {
      "vendor": "TrendMicro",
      "product": "DeepSecurity",
      "src": "10.0.1.42",
      "dst": "192.168.1.100",
      "fname": "/tmp/payload.exe"
    }
  }
}
```

---

## 13. Prowler CSPM

**Prefix:** `/api/v1/prowler/` | **Auth:** API Key | **Engine:** `ProwlerEngine`

Agentless cloud security posture scanning via Prowler CLI (AWS, Azure, GCP) with CIS benchmark compliance.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/prowler/scan` | Trigger a Prowler scan against a cloud provider. |
| `POST` | `/api/v1/prowler/ingest` | Ingest raw Prowler JSON output (no CLI required). |
| `GET` | `/api/v1/prowler/scans` | List scan history (filters: provider, status). |
| `GET` | `/api/v1/prowler/findings` | List findings (filters: scan_id, provider, severity, service). |
| `PUT` | `/api/v1/prowler/findings/{id}/resolve` | Resolve a finding. |
| `PUT` | `/api/v1/prowler/findings/{id}/suppress` | Suppress a finding (accepted risk). |
| `GET` | `/api/v1/prowler/compliance` | CIS compliance results (filter by framework). |
| `GET` | `/api/v1/prowler/compliance/summary` | Aggregated compliance summary per framework. |
| `GET` | `/api/v1/prowler/summary` | Overall scan summary for an org. |
| `GET` | `/api/v1/prowler/status` | Check Prowler CLI installation and supported providers. |

**Trigger Scan Request:**
```json
{
  "org_id": "acme-corp",
  "provider": "aws",
  "account_id": "123456789012",
  "regions": "us-east-1,us-west-2",
  "checks": null,
  "timeout": 3600
}
```

**CIS Benchmarks Supported:**
- AWS: CIS Amazon Web Services Foundations Benchmark v1.5.0
- Azure: CIS Microsoft Azure Foundations Benchmark v2.0.0
- GCP: CIS Google Cloud Platform Foundation Benchmark v1.3.0

---

## 14. ServiceNow Integration

**Prefix:** `/api/v1/servicenow-sync/` | **Auth:** API Key (webhooks are unauthenticated, validated by secret) | **Engine:** `ServiceNowSyncEngine`

Bidirectional sync between ALDECI findings and ServiceNow incidents. Supports custom field mappings, conflict resolution policies, and webhook callbacks.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/servicenow-sync/configure` | Set ServiceNow connection and sync policy. |
| `POST` | `/api/v1/servicenow-sync/sync-all` | Sync a batch of findings to ServiceNow. |
| `POST` | `/api/v1/servicenow-sync/sync-finding` | Sync a single finding (create or update incident). |
| `POST` | `/api/v1/servicenow-sync/sync-status` | Propagate finding status change to ServiceNow. |
| `GET` | `/api/v1/servicenow-sync/field-mapping` | Retrieve current field mapping configuration. |
| `PUT` | `/api/v1/servicenow-sync/field-mapping` | Replace field mapping configuration. |
| `GET` | `/api/v1/servicenow-sync/history` | Paginated sync audit history. |
| `GET` | `/api/v1/servicenow-sync/stats` | Sync statistics: total links, events by status/direction. |
| `POST` | `/api/v1/servicenow-sync/webhooks` | Receive ServiceNow webhook events (no API key -- secret validated). |

**Configure Request:**
```json
{
  "instance_url": "https://acme.service-now.com",
  "username": "aldeci_integration",
  "password": "***",
  "assignment_group": "Security Operations",
  "sync_direction": "bidirectional",
  "conflict_resolution": "newest_wins",
  "tags": ["aldeci", "security"],
  "webhook_secret": "whsec_abc123"
}
```

**Sync Directions:** `bidirectional`, `finding_to_servicenow`, `servicenow_to_finding`

**Conflict Resolution:** `newest_wins`, `servicenow_wins`, `finding_wins`, `manual`

---

## 15. CI/CD Integration

ALDECI integrates into CI/CD pipelines via the REST API and the Python SDK.

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: ALDECI Security Gate
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ALDECI scan
        env:
          ALDECI_API_KEY: ${{ secrets.ALDECI_API_KEY }}
          ALDECI_URL: ${{ secrets.ALDECI_URL }}
        run: |
          # Register the application
          curl -s -X POST "$ALDECI_URL/api/v1/app-security/apps" \
            -H "X-API-Key: $ALDECI_API_KEY" \
            -H "Content-Type: application/json" \
            -d '{"name": "${{ github.repository }}", "repo_url": "${{ github.server_url }}/${{ github.repository }}"}'

          # Scan dependencies
          curl -s -X POST "$ALDECI_URL/api/v1/dep-scanner/scan-requirements" \
            -H "X-API-Key: $ALDECI_API_KEY" \
            -F "file=@requirements.txt"

          # Check for critical findings (fail the build if any)
          CRITICAL=$(curl -s "$ALDECI_URL/api/v1/app-security/findings?severity=critical&status=open" \
            -H "X-API-Key: $ALDECI_API_KEY" | jq 'length')

          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::$CRITICAL critical security findings detected"
            exit 1
          fi
```

### GitLab CI

```yaml
# .gitlab-ci.yml
aldeci-security-gate:
  stage: test
  image: curlimages/curl:latest
  script:
    - |
      FINDINGS=$(curl -sf "$ALDECI_URL/api/v1/app-security/findings?severity=critical&status=open" \
        -H "X-API-Key: $ALDECI_API_KEY" | jq 'length')
      if [ "$FINDINGS" -gt 0 ]; then
        echo "Security gate FAILED: $FINDINGS critical findings"
        exit 1
      fi
  variables:
    ALDECI_URL: $ALDECI_URL
    ALDECI_API_KEY: $ALDECI_API_KEY
```

### Python SDK

```python
from aldeci_sdk import ALDECIClient

client = ALDECIClient(
    base_url="https://aldeci.acme.com",
    api_key="aldeci_ci_sk_live_...",
    org_id="acme-corp",
)

# Register app and scan
client.app_security.register_app(name="payment-service", repo_url="https://...")
scan = client.vuln_scans.create_scan(scan_name="CI Scan", scanner_type="trivy", target="payment-service:latest")

# Check risk score
score = client.risk.score_asset(asset_id="payment-service")
if score["score"] > 80:
    raise SystemExit(f"Risk score {score['score']} exceeds threshold")
```

---

## Error Responses

All endpoints return standard HTTP status codes with a JSON error body:

| Code | Meaning |
|------|---------|
| `400` | Bad request / validation error |
| `401` | Missing or invalid API key / token |
| `403` | Insufficient permissions (RBAC) |
| `404` | Resource not found |
| `422` | Unprocessable entity (invalid field values) |
| `429` | Rate limit exceeded (`Retry-After` header included) |
| `500` | Internal server error |
| `503` | Service unavailable (engine not initialized) |

```json
{
  "detail": "CVE 'CVE-2024-0000' not found"
}
```

---

## Pagination

List endpoints accept `limit` (default 50, max 500) and `offset` (default 0) query parameters. Responses include a `total` field for client-side pagination.

```
GET /api/v1/vuln-intel/cves?limit=20&offset=40&severity=critical
```

---

## Webhooks and Event Bus

ALDECI emits events on the internal TrustGraph event bus for every state change. Subscribe via:

- **WebSocket:** `ws://<host>/ws/events` -- real-time event stream
- **Slack:** Configure via `/api/v1/slack/configure` -- alert fanout by severity
- **n8n:** Three default workflow automations (daily digest, alert-triggered, weekly report)
- **ServiceNow:** Bidirectional webhooks (see Section 14)

---

## Additional Resources

- **OpenAPI spec:** `GET /openapi.json` -- auto-generated, importable into Postman/Swagger UI
- **Postman collection:** `docs/ALDECI_Postman_Collection.json` (100 requests, 10 domains)
- **Python SDK:** `sdk/aldeci_sdk.py` -- typed client with auto-retry and 30 engine wrappers
- **Architecture:** `docs/ARCHITECTURE_v3.md`
- **Deployment:** `docs/DEPLOYMENT_GUIDE.md`

---

*Generated from router source code on 2026-04-22. Covers 568 routers across 334 engines. For the complete endpoint list, see the OpenAPI spec at `/openapi.json`.*
