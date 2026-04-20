# ALDECI API Reference

**Base URL**: `http://localhost:8000`  
**API Version**: v1  
**Total Router Files**: 561  
**Total Endpoints**: 5,263+  
**OpenAPI Spec**: `GET /openapi.json`  
**Interactive Docs**: `GET /docs` (Swagger UI), `GET /redoc`

---

## Table of Contents

1. [Authentication](#authentication)
2. [Common Patterns](#common-patterns)
3. [Error Codes](#error-codes)
4. [Domain Groups](#domain-groups)
   - [Asset Management](#1-asset-management)
   - [Vulnerability & Risk Management](#2-vulnerability--risk-management)
   - [Threat Intelligence](#3-threat-intelligence)
   - [Incident Response & SOC](#4-incident-response--soc)
   - [Cloud & Container Security](#5-cloud--container-security)
   - [Identity & Access Management](#6-identity--access-management)
   - [Network Security](#7-network-security)
   - [Compliance & Governance](#8-compliance--governance)
   - [Data Security & Privacy](#9-data-security--privacy)
   - [Endpoint Security](#10-endpoint-security)
   - [Application & API Security](#11-application--api-security)
   - [Security Operations & Metrics](#12-security-operations--metrics)
   - [AI & ML Security](#13-ai--ml-security)
   - [Platform & Infrastructure](#14-platform--infrastructure)

---

## Authentication

All API endpoints (except `/health`, `/metrics`, and public auth endpoints) require authentication.

### API Key Authentication

Pass your API key in the request header:

```http
X-API-Key: your-api-key-here
```

Or as a Bearer token:

```http
Authorization: Bearer your-api-key-here
```

### Obtaining an API Key

```http
POST /api/v1/auth/keys
Content-Type: application/json

{
  "name": "my-integration",
  "org_id": "your-org-id",
  "scopes": ["read:findings", "write:assets"]
}
```

Response:
```json
{
  "key_id": "key_abc123",
  "api_key": "aldeci_sk_...",
  "name": "my-integration",
  "created_at": "2026-04-17T00:00:00Z",
  "expires_at": null
}
```

### API Key Management Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/keys` | Create new API key |
| `GET` | `/api/v1/auth/keys` | List all API keys |
| `GET` | `/api/v1/auth/keys/{key_id}` | Get key details |
| `PUT` | `/api/v1/auth/keys/{key_id}` | Update key metadata |
| `POST` | `/api/v1/auth/keys/{key_id}/rotate` | Rotate (invalidate + reissue) |
| `POST` | `/api/v1/auth/keys/{key_id}/revoke` | Revoke key immediately |
| `GET` | `/api/v1/auth/keys/{key_id}/usage` | Usage audit log |
| `GET` | `/api/v1/auth/keys/expiring` | Keys expiring within 30 days |
| `POST` | `/api/v1/auth/keys/cleanup` | Remove expired keys |

### SSO / SAML / OIDC

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/auth/sso` | List SSO configurations |
| `POST` | `/api/v1/auth/sso` | Create SSO provider config |
| `GET` | `/api/v1/auth/sso/{id}` | Get SSO config |
| `PUT` | `/api/v1/auth/sso/{id}` | Update SSO config |
| `GET` | `/api/v1/auth/sso/callback` | SAML/OIDC callback handler |
| `POST` | `/api/v1/auth/sso/login` | Initiate SSO login |

### Permission Scopes

Scopes gate access to router groups. Common scopes:

| Scope | Access |
|-------|--------|
| `read:findings` | Analytics, triage, findings dashboards |
| `write:assets` | Asset inventory CRUD |
| `read:graph` | Brain/knowledge graph queries |
| `read:sbom` | SBOM inventory |
| `attack:execute` | Attack simulation, red team |
| `admin` | Admin endpoints, tenant management |

---

## Common Patterns

### Multi-Tenancy (`org_id`)

Every request is scoped to an organization. Pass `org_id` as a query parameter or in the request body:

```http
GET /api/v1/assets?org_id=acme-corp&limit=50&offset=0
```

```json
{
  "org_id": "acme-corp",
  "name": "web-server-01",
  ...
}
```

All data is strictly isolated per `org_id`. Cross-org queries return `403 Forbidden`.

### Pagination

List endpoints use `limit` / `offset` pagination:

```http
GET /api/v1/assets?limit=100&offset=0&org_id=acme-corp
```

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | int | 100 | 1000 | Records per page |
| `offset` | int | 0 | — | Records to skip |

Response envelope:
```json
{
  "items": [...],
  "total": 4231,
  "limit": 100,
  "offset": 0
}
```

### Request/Response Format

- All requests: `Content-Type: application/json`
- All responses: `Content-Type: application/json`
- Timestamps: ISO 8601 (`2026-04-17T14:30:00Z`)
- Severity values: `critical`, `high`, `medium`, `low`, `info`

### Severity Enum (used across all domains)

```
critical > high > medium > low > info
```

CVSS scores are clamped to `0.0–10.0`. Confidence values are clamped to `0.0–1.0`.

---

## Error Codes

| HTTP Status | Meaning | Common Cause |
|-------------|---------|--------------|
| `200 OK` | Success | — |
| `201 Created` | Resource created | POST succeeded |
| `400 Bad Request` | Invalid input | Missing required fields, validation failure |
| `401 Unauthorized` | Missing/invalid API key | No `X-API-Key` header |
| `403 Forbidden` | Insufficient scope or org mismatch | Wrong `org_id`, missing scope |
| `404 Not Found` | Resource not found | Invalid ID or wrong `org_id` |
| `409 Conflict` | Duplicate resource | Dedup logic blocked insert |
| `422 Unprocessable Entity` | Schema validation failed | Pydantic model rejection |
| `429 Too Many Requests` | Rate limit exceeded | — |
| `500 Internal Server Error` | Engine error | Check logs |

Error response body:
```json
{
  "detail": "Asset 'abc123' not found in org 'acme-corp'"
}
```

---

## Domain Groups

---

## 1. Asset Management

**Primary prefix**: `/api/v1/assets`  
**Total endpoints in domain**: ~120

### Asset Inventory (`/api/v1/assets`) — 24 endpoints

Core CRUD for all assets (servers, cloud resources, endpoints, applications).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/assets` | List assets (filterable by type, owner, tag) |
| `POST` | `/api/v1/assets` | Register new asset |
| `GET` | `/api/v1/assets/{asset_id}` | Get asset details |
| `PUT` | `/api/v1/assets/{asset_id}` | Update asset |
| `DELETE` | `/api/v1/assets/{asset_id}` | Decommission asset |
| `GET` | `/api/v1/assets/stats` | Inventory statistics by type/owner |
| `GET` | `/api/v1/assets/unowned` | Assets with no assigned owner |
| `GET` | `/api/v1/assets/stale` | Assets with no activity (configurable days) |
| `GET` | `/api/v1/assets/exposed` | Externally exposed assets |
| `GET` | `/api/v1/assets/compliance/{framework}` | Assets in compliance scope |
| `POST` | `/api/v1/assets/discover` | Auto-discover assets from scan findings |
| `POST` | `/api/v1/assets/bulk-import` | Bulk import asset list |
| `POST` | `/api/v1/assets/relationships` | Create asset relationship edge |
| `GET` | `/api/v1/assets/{asset_id}/relationships` | Get asset relationship graph |
| `DELETE` | `/api/v1/assets/relationships/{rel_id}` | Remove relationship |
| `GET` | `/api/v1/assets/{asset_id}/impact` | Blast radius analysis |
| `GET` | `/api/v1/assets/{asset_id}/risk-score` | Computed risk score |
| `GET` | `/api/v1/assets/{asset_id}/timeline` | Asset event history |
| `POST` | `/api/v1/assets/{asset_id}/lifecycle` | Update lifecycle state |
| `POST` | `/api/v1/assets/{asset_id}/owner` | Assign/change owner |
| `POST` | `/api/v1/assets/{asset_id}/tags` | Apply tags |
| `POST` | `/api/v1/assets/{asset_id}/compliance` | Mark compliance status |
| `POST` | `/api/v1/assets/{asset_id}/sync` | Trigger sync from source |
| `GET` | `/api/v1/assets/{asset_id}/sync` | Get sync status |

### Related Asset Endpoints

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/asset-criticality` | 7 | Weighted criticality scoring, BFS critical path |
| `/api/v1/asset-groups` | 10 | Group assets by type, tag, owner |
| `/api/v1/asset-lifecycle` | 7 | Procurement → decommission state machine |
| `/api/v1/asset-risk` | 9 | Per-asset risk calculator |
| `/api/v1/asset-tags` | 10 | Tag assignment and bulk tagging |
| `/api/v1/cmdb` | 9 | CMDB integration and sync |
| `/api/v1/inventory` | 26 | Extended inventory with SBOM linkage |

---

## 2. Vulnerability & Risk Management

**Total endpoints in domain**: ~400

### Vulnerability Workflow (`/api/v1/vuln-workflow`) — 12 endpoints

SLA-tracked ticket lifecycle for vulnerabilities.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/vuln-workflow/tickets` | Create vuln ticket |
| `GET` | `/api/v1/vuln-workflow/tickets` | List tickets (filter: status, severity, assignee) |
| `GET` | `/api/v1/vuln-workflow/tickets/{ticket_id}` | Get ticket details |
| `PATCH` | `/api/v1/vuln-workflow/tickets/{ticket_id}` | Update ticket fields |
| `POST` | `/api/v1/vuln-workflow/tickets/{ticket_id}/comments` | Add comment |
| `POST` | `/api/v1/vuln-workflow/tickets/{ticket_id}/assign` | Assign to user |
| `POST` | `/api/v1/vuln-workflow/tickets/{ticket_id}/accept-risk` | Accept risk (close without fix) |
| `POST` | `/api/v1/vuln-workflow/tickets/bulk-assign` | Bulk reassign |
| `POST` | `/api/v1/vuln-workflow/tickets/bulk-close` | Bulk close |
| `GET` | `/api/v1/vuln-workflow/sla` | Get SLA configuration |
| `POST` | `/api/v1/vuln-workflow/sla` | Set SLA tiers (p1–p4) |
| `GET` | `/api/v1/vuln-workflow/stats` | SLA breach stats, overdue counts |

### SLA Tiers

| Priority | Default SLA |
|----------|-------------|
| `p1` (critical) | 24 hours |
| `p2` (high) | 7 days |
| `p3` (medium) | 30 days |
| `p4` (low) | 90 days |

### Full Vulnerability & Risk Prefix Table

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/vuln-workflow` | 12 | SLA ticket lifecycle |
| `/api/v1/vuln-scans` | 10 | Scan job management, findings ingestion |
| `/api/v1/vuln-age` | 8 | Age analysis, SLA breach rates by cohort |
| `/api/v1/vuln-scoring` | 9 | CVSS+EPSS+KEV composite scoring |
| `/api/v1/vuln-correlation` | 8 | Cross-asset vulnerability correlation |
| `/api/v1/vuln-prioritization` | 8 | Risk-ranked remediation queue |
| `/api/v1/vuln-exception` | 7 | Exception/risk-acceptance workflow |
| `/api/v1/vuln-intel` | 9 | CVE enrichment, EPSS, KEV tracking |
| `/api/v1/vuln-remediation` | 8 | 8-state remediation lifecycle |
| `/api/v1/cve` | 8 | NVD CVE lookup + EPSS enrichment |
| `/api/v1/risks` | 19 | Risk register (likelihood×impact matrix) |
| `/api/v1/risk-register-engine` | 8 | Risk register alternate interface |
| `/api/v1/risk-scenarios` | 9 | Inherent/residual risk scenarios |
| `/api/v1/risk-treatment` | 8 | Treatment plans: mitigate/transfer/accept/avoid |
| `/api/v1/risk-quant` | 8 | FAIR methodology: SLE/ARO/ALE, ROI |
| `/api/v1/attack-paths` | 8 | BFS lateral movement path analysis |
| `/api/v1/attack-chains` | 9 | Kill chain multi-step attack modeling |
| `/api/v1/posture-advisor` | 7 | AI-driven posture recommendations |
| `/api/v1/sbom-export` | 8 | CycloneDX 1.4 + SPDX 2.3 SBOM export |
| `/api/v1/sca` | 7 | Software Composition Analysis |
| `/api/v1/dependency-risk` | 9 | OSS dependency risk scoring |

### Attack Path Analysis (`/api/v1/attack-paths`) — 8 endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/attack-paths/nodes` | Register node in attack graph |
| `GET` | `/api/v1/attack-paths/nodes` | List graph nodes |
| `DELETE` | `/api/v1/attack-paths/nodes/{node_id}` | Remove node |
| `POST` | `/api/v1/attack-paths/edges` | Add directed edge (lateral movement path) |
| `POST` | `/api/v1/attack-paths/analyze` | Run BFS path analysis from entry point |
| `POST` | `/api/v1/attack-paths/blast-radius` | Compute downstream blast radius |
| `GET` | `/api/v1/attack-paths/crown-jewels-at-risk` | Crown jewels reachable from internet |
| `GET` | `/api/v1/attack-paths/stats` | Graph statistics |

---

## 3. Threat Intelligence

**Total endpoints in domain**: ~250

### Threat Indicators (`/api/v1/threat-indicators`) — 10 endpoints

IOC lifecycle management with confidence scoring.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/threat-indicators/indicators` | Create IOC (IP, domain, hash, URL, email) |
| `GET` | `/api/v1/threat-indicators/indicators` | List IOCs (filter: type, confidence, active) |
| `GET` | `/api/v1/threat-indicators/indicators/{indicator_id}` | Get IOC details |
| `POST` | `/api/v1/threat-indicators/indicators/{indicator_id}/enrich` | Trigger enrichment |
| `POST` | `/api/v1/threat-indicators/indicators/{indicator_id}/sighting` | Record sighting (increments counter) |
| `POST` | `/api/v1/threat-indicators/indicators/{indicator_id}/false-positive` | Mark false positive (sets active=0) |
| `POST` | `/api/v1/threat-indicators/indicators/{indicator_id}/expire` | Force expiry |
| `GET` | `/api/v1/threat-indicators/expired` | List expired indicators |
| `GET` | `/api/v1/threat-indicators/search` | Search by value, type, tag |
| `GET` | `/api/v1/threat-indicators/summary` | Summary stats by type and confidence |

**Indicator Types**: `ip`, `domain`, `url`, `file_hash`, `email`, `certificate`, `mutex`, `registry_key`  
**TLP Levels**: `WHITE`, `GREEN`, `AMBER`, `RED`  
**Confidence**: float `0.0–1.0` (auto-clamped)

### Full Threat Intelligence Prefix Table

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/threat-indicators` | 10 | IOC lifecycle, sightings, false positives |
| `/api/v1/threat-intel-platform` | 9 | TIP: feeds, dedup, TLP reports, bulk ingest |
| `/api/v1/ti-automation` | 8 | Automated feed enrichment, SHA-256 key hashing |
| `/api/v1/intel-enrichment` | 9 | Multi-source enrichment, auto-complete |
| `/api/v1/ti-confidence` | 8 | Source reliability, false positive floor |
| `/api/v1/threat-attribution` | 8 | Nation-state actor attribution |
| `/api/v1/threat-landscape` | 9 | Threat landscape risk (actors + categories) |
| `/api/v1/threat-brief` | 8 | TLP-classified threat briefs + distribution |
| `/api/v1/cyber-threat-intel` | 7 | CTI reports, IOC sets |
| `/api/v1/threat-actor` | 8 | Threat actor profiles |
| `/api/v1/actor-tracking` | 9 | 90-day active window, TTP frequency |
| `/api/v1/dark-web` | 8 | Dark web keyword monitoring, credential exposures |
| `/api/v1/feed-subscriptions` | 8 | Feed subscription lifecycle, IOC counter |
| `/api/v1/ioc-enrichment` | 7 | IOC enrichment pipeline |
| `/api/v1/zero-day` | 8 | Zero-day intelligence, CVSS, exploitation status |
| `/api/v1/threat-vectors` | 8 | Threat vector risk analysis |
| `/api/v1/threat-exposure` | 8 | Signal correlation, exposure scoring 0–100 |
| `/api/v1/threat-deception` | 7 | Deception decoys, attacker interaction tracking |
| `/api/v1/threat-response` | 9 | Response playbook execution, resolution metrics |

---

## 4. Incident Response & SOC

**Total endpoints in domain**: ~180

### Incident Orchestration (`/api/v1/incident-orchestration`) — 9 endpoints

5-state incident lifecycle with MTTR tracking.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/incident-orchestration/incidents` | Create incident |
| `GET` | `/api/v1/incident-orchestration/incidents` | List incidents |
| `GET` | `/api/v1/incident-orchestration/incidents/{incident_id}` | Get incident details |
| `PATCH` | `/api/v1/incident-orchestration/incidents/{incident_id}/status` | Transition state |
| `PATCH` | `/api/v1/incident-orchestration/incidents/{incident_id}/assign` | Assign to responder |
| `GET` | `/api/v1/incident-orchestration/incidents/{incident_id}/timeline` | Event timeline |
| `GET` | `/api/v1/incident-orchestration/incidents/{incident_id}/context` | AI-enriched context |
| `GET` | `/api/v1/incident-orchestration/metrics` | MTTD/MTTR/MTTC metrics |

**Incident States**: `open` → `investigating` → `contained` → `remediated` → `closed`

### Full Incident Response & SOC Prefix Table

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/incident-orchestration` | 9 | 5-state lifecycle, MTTR |
| `/api/v1/incidents` | 11 | Core incident CRUD |
| `/api/v1/incident-triage` | 7 | AI-assisted severity scoring |
| `/api/v1/incident-metrics` | 9 | MTTD/MTTR/MTTC daily snapshots |
| `/api/v1/incident-costs` | 8 | Cost tracking by category (10 types) |
| `/api/v1/incident-comms` | 9 | Stakeholder communications, 7 channels |
| `/api/v1/incident-lessons` | 9 | Post-incident lessons, action tracking |
| `/api/v1/incident-kb` | 9 | Knowledge base, LIKE search, top terms |
| `/api/v1/incident-timeline` | 10 | Timeline reconstruction |
| `/api/v1/soc-workflow` | 8 | SOC case management, SLA tracking |
| `/api/v1/soc-triage` | 10 | Alert triage queue |
| `/api/v1/soc-automation` | 8 | SOAR-style automation rules |
| `/api/v1/soc-metrics` | 8 | Analyst workload, MTTD/MTTR via julianday |
| `/api/v1/alert-triage` | 8 | Priority queue (p1-first ordering) |
| `/api/v1/alert-enrichment` | 10 | Alert enrichment, SHA-256 API keys |
| `/api/v1/alerting` | 8 | Alert policies, MTTR, ack/resolve |
| `/api/v1/event-correlation` | 8 | Time-windowed pattern matching |
| `/api/v1/event-timeline` | 9 | Event timeline, LIKE search |
| `/api/v1/breach-detection` | 7 | Behavioral anomalies, IoC correlation |
| `/api/v1/breach-response` | 9 | Breach response playbooks |
| `/api/v1/forensics-readiness` | 7 | Evidence collection readiness scoring |
| `/api/v1/digital-forensics` | 11 | DFIR: evidence, chain of custody |
| `/api/v1/evidence-vault` | 9 | SHA-256 content hash, tamper-evident |
| `/api/v1/evidence-chain` | 11 | Chain of custody, sealed guard |

---

## 5. Cloud & Container Security

**Total endpoints in domain**: ~215

### Cloud Security Findings (`/api/v1/cloud-findings`) — 9 endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/cloud-findings/findings` | Ingest single finding |
| `POST` | `/api/v1/cloud-findings/findings/bulk` | Bulk ingest (dedup by resource+title) |
| `PUT` | `/api/v1/cloud-findings/findings/{finding_id}/resolve` | Resolve finding |
| `POST` | `/api/v1/cloud-findings/findings/{finding_id}/suppress` | Suppress finding |
| `POST` | `/api/v1/cloud-findings/findings/{finding_id}/remediation` | Create remediation task |
| `PUT` | `/api/v1/cloud-findings/remediation/{remediation_id}` | Update remediation |
| `GET` | `/api/v1/cloud-findings/findings` | List findings (filter: provider, severity) |
| `GET` | `/api/v1/cloud-findings/summary` | Summary by provider and severity |
| `GET` | `/api/v1/cloud-findings/top-resources` | Top resources by finding count |

**Cloud Providers**: `aws`, `azure`, `gcp`, `oracle`, `alibaba`, `ibm`

### Full Cloud & Container Prefix Table

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/cloud-findings` | 9 | Cloud misconfig findings, dedup bulk ingest |
| `/api/v1/cloud-compliance` | 11 | CIS/NIST/SOC2/PCI-DSS, drift detection |
| `/api/v1/cloud-posture` | 7 | Cloud posture scoring, ±delta on severity |
| `/api/v1/cloud-accounts` | 10 | Account monitoring, risk_score→status mapping |
| `/api/v1/cloud-analytics` | 9 | Cloud security events, anomalies, rules |
| `/api/v1/cloud-identity` | 9 | Cloud IAM, federated access |
| `/api/v1/cloud-drift` | 8 | IaC baseline drift, acknowledge/remediate |
| `/api/v1/cloud-governance` | 7 | Policy violations, compliance score |
| `/api/v1/cloud-inventory` | 7 | Cloud resource inventory, 7 providers |
| `/api/v1/cloud-ir` | 11 | Cloud incident response, blast radius |
| `/api/v1/cloud-native` | 7 | Cloud-native posture checks |
| `/api/v1/cloud-access-security` | 7 | SaaS/PaaS app access control |
| `/api/v1/cloud-cost` | 18 | Cloud cost security, anomaly detection |
| `/api/v1/cost-optimization` | 10 | ROI computation, underutilized resources |
| `/api/v1/casb` | 12 | Shadow IT discovery, OAuth control |
| `/api/v1/cspm` | 16 | Cloud Security Posture Management |
| `/api/v1/cspm-engine` | 10 | CSPM engine rules |
| `/api/v1/cloud-graph` | 11 | Cloud resource graph |
| `/api/v1/container` | 8 | Container lifecycle |
| `/api/v1/container-posture` | 7 | Container posture score |
| `/api/v1/container-registry-security` | 10 | Image scanning, policy evaluation |
| `/api/v1/container-runtime` | 10 | Runtime violations, policies |
| `/api/v1/kubernetes-security` | 8 | CIS benchmarks, RBAC analysis |
| `/api/v1/k8s` | 10 | Kubernetes security extended |

---

## 6. Identity & Access Management

**Total endpoints in domain**: ~130

### Identity Risk (`/api/v1/identity-risk`) — 10 endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/identity-risk/identities` | Register identity |
| `GET` | `/api/v1/identity-risk/identities` | List identities |
| `GET` | `/api/v1/identity-risk/identities/{identity_id}` | Get identity details |
| `PUT` | `/api/v1/identity-risk/identities/{identity_id}/risk-score` | Update risk score |
| `POST` | `/api/v1/identity-risk/risk-factors` | Add risk factor |
| `GET` | `/api/v1/identity-risk/risk-factors` | List risk factors |
| `PUT` | `/api/v1/identity-risk/risk-factors/{factor_id}/mitigate` | Mitigate factor |
| `POST` | `/api/v1/identity-risk/access-reviews` | Create access review |
| `GET` | `/api/v1/identity-risk/access-reviews` | List access reviews |
| `GET` | `/api/v1/identity-risk/stats` | Risk distribution stats |

### Full IAM Prefix Table

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/identity-risk` | 10 | Identity risk scoring, access reviews |
| `/api/v1/identity-lifecycle` | 10 | Deprovision, orphan detection, event audit |
| `/api/v1/identity-analytics` | 10 | Identity analytics and risk |
| `/api/v1/identity-governance` | 12 | IGA: certification, SoD |
| `/api/v1/digital-identity` | 10 | IAL1/2/3, NIST 800-63 |
| `/api/v1/itdr` | 10 | Identity Threat Detection & Response |
| `/api/v1/access-governance` | 9 | SoD, role→entitlement auto-grant |
| `/api/v1/access-reviews` | 9 | Periodic access certifications |
| `/api/v1/access-requests` | 7 | Access request workflow |
| `/api/v1/access-control` | 8 | RBAC policies, grants, check_access |
| `/api/v1/access-anomaly` | 9 | Impossible travel, baseline COALESCE |
| `/api/v1/access-matrix` | 8 | Permission matrix analysis |
| `/api/v1/mfa` | 10 | MFA enrollment: TOTP/SMS/hardware/push |
| `/api/v1/pam` | 9 | Privileged Access Management |
| `/api/v1/pag` | 8 | Privileged Access Governance |
| `/api/v1/privileged-identity` | 10 | Privileged identity risk, 90-day rotation |
| `/api/v1/iam-policy` | 7 | Wildcard/toxic combo detection |
| `/api/v1/ciem` | 7 | Cloud Infrastructure Entitlement Mgmt |
| `/api/v1/iga` | 9 | Identity Governance & Administration |

---

## 7. Network Security

**Total endpoints in domain**: ~130

### Network Monitoring (`/api/v1/network-monitoring`) — 9 endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/network-monitoring/interfaces` | Register interface |
| `GET` | `/api/v1/network-monitoring/interfaces` | List interfaces |
| `POST` | `/api/v1/network-monitoring/interfaces/{interface_id}/samples` | Ingest traffic sample |
| `GET` | `/api/v1/network-monitoring/interfaces/{interface_id}/stats` | Interface stats |
| `POST` | `/api/v1/network-monitoring/alert-rules` | Create alert rule |
| `GET` | `/api/v1/network-monitoring/alert-rules` | List alert rules |
| `POST` | `/api/v1/network-monitoring/alert-rules/{rule_id}/trigger` | Manually trigger rule |
| `GET` | `/api/v1/network-monitoring/alerts` | List triggered alerts |
| `GET` | `/api/v1/network-monitoring/stats` | Monitoring stats |

### Full Network Security Prefix Table

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/network-monitoring` | 9 | Traffic sampling, alert rules |
| `/api/v1/network-anomaly` | 7 | Baseline stdev, deviation_pct thresholds |
| `/api/v1/network-segmentation` | 8 | Lateral movement risk, segmentation score |
| `/api/v1/network-forensics` | 7 | Captures, artifact analysis |
| `/api/v1/network-threats` | 9 | Threat dedup, packet_count, anomaly |
| `/api/v1/network-topology` | 10 | Network topology visualization data |
| `/api/v1/network-traffic` | 9 | Traffic analysis |
| `/api/v1/network` | 11 | Network security dashboard |
| `/api/v1/firewall` | 10 | Firewall rule management |
| `/api/v1/firewall-mgmt` | 16 | Firewall management extended |
| `/api/v1/firewall-policy` | 8 | Rule conflict detection, shadow rules |
| `/api/v1/waf` | 8 | WAF rules, virtual patches |
| `/api/v1/waf-engine` | 11 | WAF engine, rate limiting |
| `/api/v1/nac` | 11 | NAC: 5-check posture, quarantine |
| `/api/v1/bandwidth-analysis` | 8 | QoS policies, z-score anomaly detection |
| `/api/v1/wireless-security` | 7 | AP security, rogue AP detection |
| `/api/v1/ip-reputation` | 8 | Bulk scoring, category-based risk |

---

## 8. Compliance & Governance

**Total endpoints in domain**: ~130

### Compliance (`/api/v1/compliance`) — 13 endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/compliance/status` | Overall compliance posture |
| `GET` | `/api/v1/compliance/framework/{framework}` | Per-framework control status |
| `GET` | `/api/v1/compliance/gaps` | Control gaps requiring remediation |
| `GET` | `/api/v1/compliance/evidence` | Evidence collection summary |
| `POST` | `/api/v1/compliance/evidence/collect` | Trigger auto-collection |
| `GET` | `/api/v1/compliance/crossmap` | Cross-framework control mapping |
| `GET` | `/api/v1/compliance/poam` | Plan of Action & Milestones |
| `POST` | `/api/v1/compliance/poam` | Create POAM item |
| `PATCH` | `/api/v1/compliance/poam/{poam_id}` | Update POAM status |
| `POST` | `/api/v1/compliance/report/{framework}` | Generate framework report |
| `POST` | `/api/v1/compliance/score/{framework}` | Recompute compliance score |
| `GET` | `/api/v1/compliance/score/{framework}/trend` | Score trend over time |
| `GET` | `/api/v1/compliance/frameworks` | List supported frameworks |

**Supported Frameworks**: `SOC2`, `PCI-DSS`, `HIPAA`, `NIST-CSF`, `ISO27001`, `CIS`, `FedRAMP`, `GDPR`

### Full Compliance & Governance Prefix Table

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/compliance` | 13 | Core compliance posture and scoring |
| `/api/v1/compliance-automation` | 9 | Automated compliance job lifecycle |
| `/api/v1/compliance-calendar` | 9 | 8 event types, recurring schedules |
| `/api/v1/compliance-evidence` | 9 | Evidence collection |
| `/api/v1/compliance-gaps` | 10 | Gap analysis and remediation plans |
| `/api/v1/compliance-mapping` | 10 | Cross-framework control mapping |
| `/api/v1/compliance-workflows` | 9 | 8 frameworks, 6 workflow types |
| `/api/v1/compliance-planner` | 11 | Compliance planning |
| `/api/v1/compliance-reports` | 10 | Report generation |
| `/api/v1/compliance-scanner` | 11 | Automated scanning |
| `/api/v1/ccm` | 10 | Cloud Controls Matrix |
| `/api/v1/gdpr` | 6 | GDPR lawful bases, consent lifecycle |
| `/api/v1/regulatory` | 8 | Regulatory framework tracking |
| `/api/v1/regulatory-reporting` | 7 | Multi-framework report generation |
| `/api/v1/regulatory-tracker` | 10 | Regulatory change tracking |
| `/api/v1/audit-management` | 8 | Audit scheduling, finding lifecycle |
| `/api/v1/audit-analytics` | 10 | Audit analytics |
| `/api/v1/control-testing` | 9 | Rolling avg last 5 tests, 4-tier status |
| `/api/v1/gap-analysis` | 10 | 10 frameworks, coverage_pct recompute |
| `/api/v1/fedramp` | 11 | FedRAMP-specific controls |

---

## 9. Data Security & Privacy

**Total endpoints in domain**: ~115

### Data Privacy (`/api/v1/data-privacy`) — 7 endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/data-privacy/assets` | Register data asset |
| `GET` | `/api/v1/data-privacy/assets` | List data assets |
| `GET` | `/api/v1/data-privacy/assets/{asset_id}` | Get asset privacy profile |
| `POST` | `/api/v1/data-privacy/requests` | Create DSR (Data Subject Request) |
| `GET` | `/api/v1/data-privacy/requests` | List DSRs |
| `PUT` | `/api/v1/data-privacy/requests/{request_id}/status` | Update DSR status |
| `GET` | `/api/v1/data-privacy/stats` | Privacy stats, 30-day overdue DSRs |

**DSR Types**: `access`, `deletion`, `portability`, `rectification`, `restriction`  
**DSR SLA**: 30 days (GDPR mandated)

### Full Data Security & Privacy Prefix Table

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/data-privacy` | 7 | DSR requests, 30-day overdue detection |
| `/api/v1/data-discovery` | 8 | 7 datastore types, sensitive record count |
| `/api/v1/data-governance` | 12 | Data governance and classification |
| `/api/v1/data-retention` | 10 | GDPR/CCPA policy lifecycle, deletion audit |
| `/api/v1/data-lake-security` | 7 | Assessment scoring, exfiltration risk |
| `/api/v1/data-exfiltration` | 9 | 8 incident types, confidence clamping |
| `/api/v1/data-pipeline` | 7 | 8 source types, records_processed counter |
| `/api/v1/dlp` | 17 | DLP: PII detection, policy/incident feed |
| `/api/v1/privacy` | 14 | Privacy management |
| `/api/v1/privacy-impact` | 10 | PIA/DPIA workflow, approve with consultations |
| `/api/v1/retention` | 12 | Retention policy management |
| `/api/v1/classification` | 9 | Data classification |
| `/api/v1/data` | 10 | Data security dashboard |

---

## 10. Endpoint Security

**Total endpoints in domain**: ~74

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/edr` | 10 | EDR: endpoint detection & response |
| `/api/v1/xdr` | 10 | XDR: extended detection across domains |
| `/api/v1/ndr` | 10 | NDR: network detection & response |
| `/api/v1/mdm` | 12 | MDM: device enrollment, compliance, wipe |
| `/api/v1/endpoint-compliance` | 11 | Severity-weighted scoring, bulk ingestion |
| `/api/v1/endpoint-hunting` | 11 | Threat hunting on endpoints |
| `/api/v1/endpoint-security` | 10 | Endpoint security dashboard |

**MDM Platforms**: `ios`, `android`, `windows`, `macos`, `linux`, `chromeos`

---

## 11. Application & API Security

**Total endpoints in domain**: ~250+

### Key Application Security Prefixes

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/appsec` | 11 | AppSec SAST/DAST aggregation |
| `/api/v1/app-security` | 9 | Application security dashboard |
| `/api/v1/app-risk` | 8 | Application risk scoring |
| `/api/v1/api-security` | 7 | API security overview |
| `/api/v1/api-security-engine` | 11 | OWASP API Top 10, SHA-256 key hashing |
| `/api/v1/api-discovery` | 10 | Endpoint discovery, undocumented API detection |
| `/api/v1/api-inventory` | 7 | 6 API types, 6 auth types |
| `/api/v1/api-abuse` | 8 | Abuse detection, 9 abuse types |
| `/api/v1/api-threat-protection` | 7 | 8 threat types, 5 action types |
| `/api/v1/api-gateway-security` | 8 | OWASP, rate limits, SHA-256 key hashing |
| `/api/v1/api-fuzzer` | 4 | API fuzzing runner |
| `/api/v1/arch-review` | 8 | Architecture review, finding lifecycle |
| `/api/v1/asm` | 11 | Attack Surface Management |
| `/api/v1/attack-surface` | 10 | Attack surface scoring |
| `/api/v1/attack-surface-mgmt` | 11 | ASM engine, exposure lifecycle |
| `/api/v1/dast` | 6 | Dynamic Application Security Testing |
| `/api/v1/devsecops` | 10 | DevSecOps pipeline integration |
| `/api/v1/cicd` | 6 | CI/CD security gates |
| `/api/v1/iac` | 7 | Infrastructure-as-Code security |
| `/api/v1/sbom-export` | 8 | CycloneDX/SPDX export |
| `/api/v1/license-security` | 10 | OSS license risk |
| `/api/v1/mobile-app-security` | 9 | OWASP Mobile, 5 platforms |
| `/api/v1/browser-security` | 9 | Browser policies, extensions |

---

## 12. Security Operations & Metrics

**Total endpoints in domain**: ~350+

### Analytics (`/api/v1/analytics`) — 33 endpoints

Cross-domain analytics powered by DuckDB.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/analytics/dashboard/overview` | Full dashboard overview |
| `GET` | `/api/v1/analytics/dashboard/executive` | Executive summary |
| `GET` | `/api/v1/analytics/dashboard/severity` | Severity distribution |
| `GET` | `/api/v1/analytics/dashboard/scanners` | Scanner coverage stats |
| `GET` | `/api/v1/analytics/dashboard/trends` | Trend lines |
| `GET` | `/api/v1/analytics/dashboard/top-risks` | Top risk items |
| `GET` | `/api/v1/analytics/dashboard/compliance-status` | Compliance at-a-glance |
| `GET` | `/api/v1/analytics/findings` | Findings analytics |
| `POST` | `/api/v1/analytics/findings` | Submit finding for analytics |
| `GET` | `/api/v1/analytics/mttr` | MTTR breakdown by severity/team |
| `GET` | `/api/v1/analytics/coverage` | Control coverage gaps |
| `GET` | `/api/v1/analytics/roi` | Security program ROI |
| `GET` | `/api/v1/analytics/noise-reduction` | False positive / alert noise stats |
| `POST` | `/api/v1/analytics/custom-query` | Run DuckDB custom query |
| `GET` | `/api/v1/analytics/export` | Export analytics data (CSV/JSON) |
| `GET` | `/api/v1/analytics/triage-funnel` | Alert → incident conversion funnel |
| `GET` | `/api/v1/analytics/risk-velocity` | Risk trend velocity |
| `GET` | `/api/v1/analytics/live-feed` | Real-time event feed |
| `GET` | `/api/v1/analytics/false-positive-rate` | FP rate by scanner |

### Key Metrics & Reporting Prefixes

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/analytics` | 33 | DuckDB cross-domain analytics |
| `/api/v1/analytics-engine` | 7 | Analytics engine direct |
| `/api/v1/kpi` | 9 | KPI tracking: MTTD/MTTR/scorecard |
| `/api/v1/kpi-tracking` | 8 | KPI direction, achievement%, trend |
| `/api/v1/metrics-dashboard` | 7 | Dashboard + widget + snapshot |
| `/api/v1/metrics-aggregator` | 8 | Cross-source metric aggregation |
| `/api/v1/security-okrs` | 8 | OKR progress, KR velocity history |
| `/api/v1/posture-scoring` | 8 | Weighted control posture score |
| `/api/v1/posture-history` | 8 | 8 domains, trend improving/declining |
| `/api/v1/posture-trends` | 8 | ETA computation, confidence tiers |
| `/api/v1/posture-maturity` | 8 | CMMI 10 domains, maturity 1-5 |
| `/api/v1/posture-benchmarking` | 8 | Percentile interpolation p25–p90 |
| `/api/v1/posture-reports` | 8 | Section status, overall A-F grade |
| `/api/v1/security-baselines` | 8 | Compliance_pct, drift report |
| `/api/v1/security-benchmarks` | 8 | Performance percentile ranking |
| `/api/v1/security-culture` | 8 | 7 categories, 5 maturity levels |
| `/api/v1/security-budget` | 8 | Allocations, ROI assessment |
| `/api/v1/security-investment` | 8 | Portfolio ROI, verified outcomes |
| `/api/v1/security-scoreboard` | 8 | Team gamification |
| `/api/v1/health-scorecard` | 7 | Weighted domain scoring, A-F grade |
| `/api/v1/exec-reporting` | 12 | Executive reports, KPIs, board decks |
| `/api/v1/executive` | 7 | Executive dashboard |
| `/api/v1/ciso-report` | 6 | CISO executive report |
| `/api/v1/dashboards` | 15 | Dashboard management |

---

## 13. AI & ML Security

**Total endpoints in domain**: ~80

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/ai-governance` | 10 | AI model lifecycle, bias/security assessments |
| `/api/v1/ai-soc` | 10 | AI-powered SOC, triage workflow |
| `/api/v1/ai-advisor` | 10 | LLM-powered security advisor (Qwen 3.6 Max) |
| `/api/v1/ai-agent` | 7 | Single AI agent runner |
| `/api/v1/ai-orchestrator` | 8 | Multi-agent orchestration |
| `/api/v1/ml` | 15 | ML model management |
| `/api/v1/anomaly-ml` | 8 | ML-based anomaly detection |
| `/api/v1/anomalies` | 8 | Anomaly management |
| `/api/v1/algorithms` | 12 | Algorithmic analysis |
| `/api/v1/copilot` | 16 | Security copilot (GraphRAG-backed chat) |
| `/api/v1/copilot/agents` | 32 | Copilot agent library |
| `/api/v1/council` | 3 | Karpathy LLM Council (4 models + Opus) |
| `/api/v1/llm` | 6 | LLM inference |
| `/api/v1/llm-monitor` | 5 | LLM usage monitoring |

### Copilot Chat (`/api/v1/copilot`)

The copilot uses GraphRAG (BFS traversal + semantic search over TrustGraph) to answer security questions in context.

```http
POST /api/v1/copilot/chat
Content-Type: application/json
X-API-Key: your-key

{
  "message": "What are my top 5 critical vulnerabilities?",
  "org_id": "acme-corp",
  "context_depth": 2
}
```

---

## 14. Platform & Infrastructure

**Total endpoints in domain**: ~900+

### Brain / Knowledge Graph (`/api/v1/brain`) — 28 endpoints

The core knowledge graph connecting all security entities.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/brain/nodes` | Add entity node |
| `GET` | `/api/v1/brain/nodes` | List nodes (filter: type, risk) |
| `GET` | `/api/v1/brain/nodes/{node_id}` | Get node + edges |
| `DELETE` | `/api/v1/brain/nodes/{node_id}` | Remove node |
| `POST` | `/api/v1/brain/edges` | Create relationship edge |
| `GET` | `/api/v1/brain/neighbors/{node_id}` | Get neighbor nodes |
| `GET` | `/api/v1/brain/paths` | Find paths between nodes |
| `GET` | `/api/v1/brain/stats` | Graph statistics |
| `GET` | `/api/v1/brain/most-connected` | Highest-degree nodes |
| `GET` | `/api/v1/brain/risk/{node_id}` | Node risk propagation score |
| `POST` | `/api/v1/brain/ingest/cve` | Ingest CVE into graph |
| `POST` | `/api/v1/brain/ingest/finding` | Ingest security finding |
| `POST` | `/api/v1/brain/ingest/scan` | Ingest scan results |
| `POST` | `/api/v1/brain/ingest/asset` | Ingest asset |
| `POST` | `/api/v1/brain/ingest/remediation` | Record remediation event |
| `GET` | `/api/v1/brain/health` | Graph engine health |
| `GET` | `/api/v1/brain/pipeline/status` | Processing pipeline status |
| `GET` | `/api/v1/brain/trends` | Risk trend analysis |
| `POST` | `/api/v1/brain/feedback` | Submit signal feedback |
| `GET` | `/api/v1/brain/feedback/auto-suppress-rules` | Auto-suppression rules |

### Key Platform Prefixes

| Prefix | Endpoints | Description |
|--------|-----------|-------------|
| `/api/v1/brain` | 28 | Knowledge graph (TrustGraph backend) |
| `/api/v1/graphrag` | 4 | GraphRAG retrieval (BFS + semantic) |
| `/api/v1/graph` | 5 | Graph queries |
| `/api/v1/knowledge-graph` | 12 | Knowledge graph management |
| `/api/v1/connectors` | 8 | 13 PULL + 7 bidirectional connectors |
| `/api/v1/cloud-connectors` | 10 | Cloud source connectors |
| `/api/v1/integrations` | 10 | External integrations (Jira, Slack, PD) |
| `/api/v1/jira-sync` | 8 | Jira bidirectional sync |
| `/api/v1/pagerduty` | 8 | PagerDuty integration |
| `/api/v1/queue` | 8 | Redis queue (horizontal scaling) |
| `/api/v1/backup-dr` | 24 | Backup validation, DR testing |
| `/api/v1/backups` | 10 | Backup management |
| `/api/v1/bulk` | 14 | Bulk operations across domains |
| `/api/v1/bulk-operations` | 8 | Extended bulk ops |
| `/api/v1/autofix` | 17 | Automated remediation suggestions |
| `/api/v1/autonomous-remediation` | 10 | Workflow-based auto-remediation |
| `/api/v1/change-management` | 7 | Security change workflow |
| `/api/v1/change-tracker` | 10 | Configuration change tracking |
| `/api/v1/crypto-keys` | 8 | Key rotation, expiry, audit |
| `/api/v1/certificates` | 8 | Certificate lifecycle, renewal alerts |
| `/api/v1/pki` | 8 | PKI management, CAs, revocation |
| `/api/v1/deduplication` | 20 | Finding deduplication |
| `/api/v1/grc` | 11 | GRC dashboard |
| `/api/v1/ctem` | 15 | Continuous Threat Exposure Mgmt |
| `/api/v1/mitre-attack` | 10 | MITRE ATT&CK coverage, 14 tactics |
| `/api/v1/hunt` | 14 | Threat hunting |
| `/api/v1/hunting` | 10 | Hunting sessions |
| `/api/v1/hunting-playbooks` | 8 | Playbook execution, success_rate |
| `/api/v1/hunting-automation` | 9 | Automated hunt rules |
| `/api/v1/security-chaos` | 8 | Chaos experiments, resilience scoring |
| `/api/v1/tabletop` | 8 | Tabletop exercises, 8 scenario types |
| `/api/v1/threat-simulation` | 8 | Red/blue team orchestration |
| `/api/v1/awareness-program` | 8 | Security awareness programs |
| `/api/v1/awareness-campaigns` | 7 | Campaign lifecycle, pass_rate |
| `/api/v1/awareness-gamification` | 7 | Challenges, leaderboard, badges |
| `/api/v1/security-training` | 8 | Training assignments, completions |
| `/api/v1/training-effectiveness` | 8 | Score improvement, retention trends |
| `/api/v1/developer` | 9 | Developer security portal |
| `/api/v1/docs` | 6 | API developer docs |
| `/api/v1/sbom` | 8 | SBOM management |
| `/api/v1/airgap` | 27 | Air-gap mode operations |

---

## Quick Reference: Most Used Endpoints

```
# Health check (no auth required)
GET /health

# Metrics (Prometheus format)
GET /metrics

# Create asset
POST /api/v1/assets?org_id=acme

# Search vulnerabilities
GET /api/v1/vuln-workflow/tickets?status=open&severity=critical&org_id=acme

# Get compliance posture
GET /api/v1/compliance/status?org_id=acme

# Run analytics query
POST /api/v1/analytics/custom-query

# Ask the AI copilot
POST /api/v1/copilot/chat

# Export SBOM (CycloneDX)
POST /api/v1/sbom-export/generate/cyclonedx?org_id=acme

# Get attack paths
POST /api/v1/attack-paths/analyze?org_id=acme

# Search IOCs
GET /api/v1/threat-indicators/search?value=192.168.1.1&type=ip&org_id=acme

# Get MTTD/MTTR
GET /api/v1/incident-orchestration/metrics?org_id=acme

# CVE enrichment (NVD + EPSS + KEV)
GET /api/v1/cve/{cve_id}?org_id=acme

# Security posture score
GET /api/v1/posture-scoring/stats?org_id=acme
```

---

## Live Examples: Top 20 Endpoints

All examples below use real responses captured from `http://localhost:8000`.

---

### 1. GET /health

Platform liveness check. No authentication required.

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-04-20T13:06:17.870674+00:00Z",
  "service": "aldeci-api"
}
```

---

### 2. GET /api/v1/platform/health

Full platform health including engine count, router mounts, test stats, and active data.

```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:8000/api/v1/platform/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0-wave47",
  "timestamp": "2026-04-20T13:06:18.120246+00:00Z",
  "uptime_seconds": 2139.9,
  "engines": {
    "total": 344,
    "healthy": 342,
    "degraded": 2
  },
  "routers": {
    "total": 574,
    "mounted": 574
  },
  "frontend": {
    "pages": 296,
    "wired_to_api": 278
  },
  "tests": {
    "total": 8910,
    "beast_mode_passing": 709
  },
  "data": {
    "brain_nodes": 1158,
    "alerts": 358,
    "vulnerabilities": 125,
    "assets": 20,
    "compliance_frameworks": 0
  },
  "intelligence_mesh": {
    "brain_graph": "active",
    "event_bus": "active",
    "subscribers": "active",
    "risk_sync": "active",
    "supply_chain_sync": "active"
  }
}
```

---

### 3. POST /api/v1/assets

Register a new asset in the inventory.

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/assets?org_id=acme" \
  -d '{
    "name": "web-prod-01",
    "asset_type": "server",
    "ip_address": "10.0.1.10",
    "environment": "production",
    "criticality": "high",
    "tags": ["internet-facing", "pci-scope"]
  }'
```

**Response (`201 Created`):**
```json
{
  "id": "masset-cc3090cc8af2",
  "name": "web-prod-01",
  "asset_type": "server",
  "ip_address": "10.0.1.10",
  "criticality": "high",
  "criticality_tier": "T3",
  "data_classification": "internal",
  "compliance_scope": ["gdpr"],
  "environment": "production",
  "lifecycle": "discovered",
  "tags": ["internet-facing", "pci-scope"],
  "finding_count": 0,
  "risk_score": 0.0,
  "org_id": "acme",
  "first_discovered": "2026-04-20T13:07:12.709642+00:00",
  "last_seen": "2026-04-20T13:07:12.709657+00:00"
}
```

---

### 4. POST /api/v1/vuln-workflow/tickets

Create a vulnerability ticket with SLA tracking.

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/vuln-workflow/tickets?org_id=acme" \
  -d '{
    "title": "CVE-2024-3400 PAN-OS Command Injection",
    "cve_id": "CVE-2024-3400",
    "severity": "critical",
    "affected_asset": "firewall-prod-01",
    "source": "nessus",
    "description": "Critical PAN-OS GlobalProtect RCE - actively exploited in the wild"
  }'
```

**Response (`201 Created`):**
```json
{
  "id": "8ffe6583-0395-48a1-a3ca-ab56a21bf9a2",
  "org_id": "acme",
  "cve_id": "CVE-2024-3400",
  "title": "CVE-2024-3400 PAN-OS Command Injection",
  "severity": "critical",
  "cvss_score": 0.0,
  "status": "open",
  "priority": "p3",
  "due_date": "2026-07-19T13:07:39.998322+00:00",
  "source_engine": "manual",
  "created_at": "2026-04-20T13:07:39.998337+00:00",
  "overdue": false
}
```

**GET stats:**

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/vuln-workflow/stats?org_id=acme"
```

```json
{
  "total_open": 1,
  "by_severity": {"critical": 1},
  "by_status": {"open": 1},
  "overdue_count": 0,
  "avg_resolution_days": 0.0,
  "sla_breached": 0,
  "by_source": {"manual": 1}
}
```

---

### 5. POST /api/v1/incident-orchestration/incidents

Create and manage security incidents through a 5-state lifecycle.

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/incident-orchestration/incidents?org_id=acme" \
  -d '{
    "title": "Ransomware detected on finance-srv-02",
    "severity": "critical",
    "description": "Lateral movement detected. Possible ransomware pre-staging."
  }'
```

**Response (`201 Created`):**
```json
{
  "id": "63baa291-4432-45fe-8bbc-fd0d03cdb48f",
  "org_id": "acme",
  "title": "Ransomware detected on finance-srv-02",
  "severity": "critical",
  "type": "other",
  "status": "open",
  "created_at": "2026-04-20T13:07:40.335783+00:00",
  "updated_at": "2026-04-20T13:07:40.335783+00:00",
  "resolved_at": null
}
```

**GET metrics (MTTD/MTTR):**

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/incident-orchestration/metrics?org_id=acme"
```

```json
{
  "open_count": 1,
  "total_count": 1,
  "avg_mttr_hours": 0.0,
  "by_severity": {"critical": 1},
  "by_type": {"ransomware": 1}
}
```

---

### 6. POST /api/v1/threat-indicators/indicators

Create and track IOCs (IPs, domains, file hashes, URLs).

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/threat-indicators/indicators?org_id=acme" \
  -d '{
    "indicator_type": "ip",
    "indicator_value": "185.220.101.47",
    "confidence": 0.95,
    "severity": "high",
    "tlp": "amber",
    "tags": ["tor-exit-node", "c2"],
    "description": "Known Tor exit node used as C2 relay by LockBit 3.0"
  }'
```

**Response (`201 Created`):**
```json
{
  "id": "a93dde90-d559-48a5-a1ca-54d77a73d275",
  "org_id": "acme",
  "indicator_value": "185.220.101.47",
  "indicator_type": "ip",
  "confidence": 0.95,
  "severity": "high",
  "tlp": "amber",
  "tags": "[\"tor-exit-node\", \"c2\"]",
  "active": 1,
  "false_positive": 0,
  "sighting_count": 0,
  "api_key_hash": "727be586f9ffb1c8b8255bb42fd105aa2a89b53b37d040354c78742671a9f0e3",
  "first_seen": "2026-04-20T13:08:04.779540+00:00",
  "created_at": "2026-04-20T13:08:04.779540+00:00"
}
```

**GET summary:**

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/threat-indicators/summary?org_id=acme"
```

```json
{
  "total": 1,
  "active_count": 1,
  "false_positive_count": 0,
  "by_type": {"ip": 1},
  "by_severity": {"high": 1},
  "high_confidence_count": 1,
  "expiring_soon": 0
}
```

---

### 7. GET /api/v1/compliance/status

Real-time compliance posture across all frameworks.

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/compliance/status?org_id=acme"
```

**Response:**
```json
{
  "status": "operational",
  "overall_score": 98.5,
  "scoring_method": "estimated",
  "scoring_note": "Scores are estimated from finding severity counts. Run a compliance assessment for verified control scores.",
  "frameworks": [
    {
      "id": "soc2",
      "name": "SOC 2 Type II",
      "score": 100,
      "controls_met": 0,
      "controls_total": 0,
      "status": "estimated"
    },
    {
      "id": "nist-csf",
      "name": "NIST CSF 2.0",
      "score": 94,
      "controls_met": 0,
      "controls_total": 0,
      "status": "estimated"
    }
  ],
  "last_assessment": "2026-04-20T13:07:52.874709+00:00",
  "evidence_bundles": 0,
  "open_gaps": 0
}
```

**GET supported frameworks:**

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/compliance/frameworks?org_id=acme"
```

```json
{
  "frameworks": ["SOC2", "PCI-DSS", "HIPAA", "FedRAMP", "ISO27001", "NIST-800-53", "CMMC"],
  "count": 7,
  "metadata": {
    "SOC2": {
      "full_name": "SOC 2 (Trust Service Criteria)",
      "issuer": "AICPA",
      "version": "2017",
      "description": "Service Organization Control 2 — Trust Service Criteria covering Security, Availability, Processing Integrity, Confidentiality, and Privacy."
    },
    "PCI-DSS": {
      "full_name": "Payment Card Industry Data Security Standard v4.0",
      "issuer": "PCI Security Standards Council",
      "version": "4.0",
      "description": "12 high-level requirements for protecting cardholder data."
    }
  }
}
```

---

### 8. GET /api/v1/analytics/dashboard/overview

Top-level finding counts for dashboards.

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/analytics/dashboard/overview?org_id=acme"
```

**Response:**
```json
{
  "total_findings": 50,
  "open_findings": 33,
  "critical_findings": 3,
  "recent_findings_30d": 24,
  "timestamp": "2026-04-20T13:08:53.393516+00:00",
  "org_id": "acme"
}
```

---

### 9. GET /api/v1/analytics/dashboard/executive

Executive summary with severity breakdown, scanner coverage, and KPIs.

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/analytics/dashboard/executive?org_id=acme"
```

**Response:**
```json
{
  "status": "ok",
  "total_findings": 50,
  "severity_breakdown": {
    "critical": 5,
    "high": 12,
    "medium": 18,
    "low": 15,
    "info": 0
  },
  "status_breakdown": {
    "open": 33,
    "resolved": 6,
    "in_progress": 11,
    "false_positive": 0
  },
  "scanner_breakdown": {
    "ZAP": 15,
    "Semgrep": 10,
    "Trivy": 9,
    "Nuclei": 7,
    "Bandit": 5,
    "Snyk": 4
  },
  "risk_score": 100,
  "risk_level": "critical",
  "resolution_rate": 12.0,
  "kpis": {
    "mttr_hours": 0,
    "false_positive_rate": 0.0,
    "sla_compliance": 12.0,
    "scanner_coverage": 6
  },
  "org_id": "acme"
}
```

---

### 10. GET /api/v1/cve/{cve_id}

CVE enrichment with NVD details, EPSS exploit probability, and CISA KEV status.

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/cve/CVE-2021-44228?org_id=acme"
```

**Response:**
```json
{
  "cve_id": "CVE-2021-44228",
  "cvss_score": 10.0,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cvss_severity": "critical",
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP endpoints. An attacker who can control log messages can execute arbitrary code loaded from LDAP servers.",
  "epss_score": 0.94358,
  "epss_percentile": 99.96,
  "is_kev": true,
  "kev_due_date": "2021-12-24",
  "cwe": "CWE-917",
  "published": "2021-12-10",
  "source": "cache",
  "enriched_at": "2026-04-20T11:37:28.079442",
  "expires_at": "2026-04-21T11:37:28.079445"
}
```

---

### 11. POST /api/v1/brain/ingest/finding

Ingest a security finding into the knowledge graph. Automatically links to CVEs and assets.

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/brain/ingest/finding?org_id=acme" \
  -d '{
    "finding_id": "finding-001",
    "title": "Log4Shell RCE in logging-service",
    "severity": "critical",
    "source": "snyk",
    "asset_id": "web-prod-01",
    "cve_id": "CVE-2021-44228"
  }'
```

**Response:**
```json
{
  "node_id": "finding:finding-001",
  "node_type": "finding",
  "ingested": true
}
```

---

### 12. GET /api/v1/brain/stats

Knowledge graph statistics — node types, edge types, and org breakdown.

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/brain/stats?org_id=acme"
```

**Response:**
```json
{
  "total_nodes": 1158,
  "total_edges": 26,
  "density": 1.9e-05,
  "node_types": {
    "Asset": 2,
    "CVE": 1,
    "asset": 5,
    "component": 164,
    "cve": 2,
    "finding": 984
  },
  "edge_types": {
    "AFFECTED_BY": 1,
    "references": 25
  },
  "organizations": {
    "aldeci-self": 911,
    "aldeci": 227,
    "default": 2,
    "e2e-test-org": 18
  }
}
```

---

### 13. GET /api/v1/brain/pipeline/status

Status of the 12-step CTEM processing pipeline.

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/brain/pipeline/status?org_id=acme"
```

**Response:**
```json
{
  "status": "operational",
  "pipeline": "12-step-ctem",
  "steps": [
    "CONNECT", "NORMALIZE", "RESOLVE", "DEDUPLICATE",
    "BUILD_GRAPH", "ENRICH", "SCORE", "EVALUATE_POLICY",
    "MULTI_LLM_CONSENSUS", "MICRO_PENTEST", "AUTOFIX", "GENERATE_EVIDENCE"
  ],
  "active_runs": 0,
  "completed_runs": 0,
  "avg_duration_ms": 0,
  "last_run": null
}
```

---

### 14. POST /api/v1/attack-paths/analyze

Run BFS attack path analysis from an entry point through the asset graph.

**Step 1 — Register nodes:**

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/attack-paths/nodes?org_id=acme" \
  -d '{"node_id":"internet","name":"Internet Entry Point","node_type":"external","is_crown_jewel":false}'
```

```json
{
  "node_id": "internet",
  "node_type": "external",
  "name": "Internet Entry Point",
  "risk_score": 50.0,
  "is_crown_jewel": false,
  "vulnerabilities": [],
  "org_id": "acme"
}
```

**Step 2 — Add edges:**

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/attack-paths/edges?org_id=acme" \
  -d '{"from_node":"internet","to_node":"web-prod-01","technique":"T1190","weight":0.8}'
```

```json
{
  "edge_id": "b1109578-7d62-4bf1-873a-3077a6f9b92c",
  "from_node": "internet",
  "to_node": "web-prod-01",
  "protocol": "tcp",
  "port": 0,
  "org_id": "acme"
}
```

**Step 3 — Run analysis:**

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/attack-paths/analyze?org_id=acme" \
  -d '{"entry_point":"internet","max_depth":5}'
```

```json
{
  "entry_point": "internet",
  "target_nodes_reached": ["db-prod-01"],
  "paths": [
    {
      "path": ["internet", "web-prod-01", "db-prod-01"],
      "hops": 2,
      "risk_score": 75.0,
      "vulnerabilities_required": [],
      "gnn_risk_score": 100.0
    }
  ],
  "total_paths": 1,
  "max_blast_radius": 2
}
```

---

### 15. POST /api/v1/copilot/chat

GraphRAG-backed AI security copilot. Answers questions using the live knowledge graph.

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/copilot/chat?org_id=acme" \
  -d '{
    "message": "What are my top critical vulnerabilities?",
    "org_id": "acme",
    "context_depth": 1
  }'
```

**Response:**
```json
{
  "session_id": "sess-621783ad",
  "message_id": "msg-c322ea63",
  "agent_id": "security-analyst",
  "response": "Your environment has 50 findings across 6 sources (ZAP: 15, Semgrep: 10, Trivy: 9, Nuclei: 7, Bandit: 5, Snyk: 4).\n\nSeverity: 5 Critical, 12 High, 18 Medium, 15 Low. 8 confirmed exploitable.\n\nTop critical:\n  1. XZ Utils Backdoor — Supply Chain Compromise (CVE-2024-3094) — CVSS 10.0, EPSS 0.97\n  2. Apache Log4Shell — JNDI Injection (RCE) (CVE-2021-44228) — CVSS 10.0, EPSS 0.98\n  3. PHP CGI Argument Injection (RCE) (CVE-2024-4577) — CVSS 9.8, EPSS 0.95\n  4. Fortinet FortiOS Out-of-Bound Write (RCE) (CVE-2024-21762) — CVSS 9.6, EPSS 0.93\n  5. OpenSSH regreSSHion Race Condition (CVE-2024-6387) — CVSS 8.1, EPSS 0.88\n\nStatus: 33 open, 11 in progress, 6 resolved.",
  "suggestions": [
    "Show exploitable findings",
    "Generate remediation plan",
    "Run MPTE validation",
    "Map to compliance frameworks"
  ],
  "timestamp": "2026-04-20T13:09:33.841183+00:00",
  "confidence": 0.96,
  "sources": ["analytics_db", "findings_store"]
}
```

---

### 16. POST /api/v1/sbom-export/components + POST /generate/cyclonedx

Register software components and export a CycloneDX 1.4 SBOM.

**Step 1 — Register component:**

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/sbom-export/components?org_id=acme" \
  -d '{
    "org_id": "acme",
    "project_name": "web-prod-01",
    "component_name": "log4j-core",
    "component_version": "2.14.1",
    "component_type": "library",
    "ecosystem": "maven",
    "license": "Apache-2.0",
    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
  }'
```

```json
{
  "id": "0d3229f3-e6b5-4404-9bef-f064aef7fd51",
  "org_id": "acme",
  "project_name": "web-prod-01",
  "component_name": "log4j-core",
  "component_version": "2.14.1",
  "component_type": "library",
  "ecosystem": "maven",
  "license": "Apache-2.0",
  "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  "vuln_count": 0,
  "created_at": "2026-04-20T13:09:59.510963+00:00"
}
```

**Step 2 — Generate CycloneDX SBOM:**

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/sbom-export/generate/cyclonedx?org_id=acme" \
  -d '{"org_id": "acme", "project_name": "web-prod-01"}'
```

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2026-04-20T13:09:59.538985+00:00",
    "component": {
      "name": "web-prod-01",
      "version": "1.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "licenses": [{"license": {"id": "Apache-2.0"}}]
    }
  ],
  "vulnerabilities": [],
  "_export_id": "68f29ef0-e706-4918-ba3f-9447a126e994"
}
```

> For SPDX 2.3 format, use `POST /api/v1/sbom-export/generate/spdx` with the same body.

---

### 17. POST /api/v1/risks

Create a risk register entry with likelihood × impact scoring.

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/risks?org_id=acme" \
  -d '{
    "title": "Unpatched critical CVEs in production",
    "category": "technical",
    "likelihood": 4,
    "impact": 5,
    "owner": "security-team",
    "description": "Multiple critical CVEs unpatched for 30+ days in internet-facing systems"
  }'
```

**Response (`201 Created`):**
```json
{
  "id": "risk-7e081ff51a95",
  "title": "Unpatched critical CVEs in production",
  "description": "Multiple critical CVEs unpatched for 30+ days in internet-facing systems",
  "category": "technical",
  "owner": "security-team",
  "likelihood": 4,
  "impact": 5,
  "inherent_risk_score": 20.0,
  "residual_risk_score": 20.0,
  "status": "open",
  "treatment_action": null,
  "score_history": [20.0],
  "created_at": "2026-04-20T13:08:52.607195+00:00"
}
```

**Risk scoring**: `inherent_risk_score = likelihood × impact` (max 25). Valid categories: `operational`, `compliance`, `technical`, `strategic`, `reputational`.

---

### 18. POST /api/v1/feed-subscriptions/subscriptions

Subscribe to a threat intelligence feed. API keys are SHA-256 hashed at rest.

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/feed-subscriptions/subscriptions?org_id=acme" \
  -d '{
    "feed_name": "abuse-ipdb",
    "feed_type": "osint",
    "url": "https://api.abuseipdb.com/api/v2/blacklist",
    "api_key": "your-abuseipdb-key",
    "refresh_interval_hours": 24
  }'
```

**Response (`201 Created`):**
```json
{
  "id": "ec206132-23fe-4cc0-b89e-97323a7b9df7",
  "org_id": "acme",
  "feed_name": "abuse-ipdb",
  "feed_type": "osint",
  "api_key_hash": "727be586f9ffb1c8b8255bb42fd105aa2a89b53b37d040354c78742671a9f0e3",
  "status": "active",
  "refresh_interval_minutes": 60,
  "last_fetched": null,
  "ioc_count": 0,
  "error_count": 0,
  "created_at": "2026-04-20T13:09:28.204104+00:00"
}
```

**Valid feed types**: `internal`, `osint`, `isac`, `vendor`, `government`, `community`, `commercial`

---

### 19. GET /api/v1/posture-scoring/stats

Security posture score across domains. Controls are weighted 0.0–1.0.

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "http://localhost:8000/api/v1/posture-scoring/stats?org_id=acme"
```

**Response:**
```json
{
  "org_id": "acme",
  "overall_score": 0.0,
  "by_domain": {
    "identity": 0.0
  },
  "total_controls": 1,
  "implemented_count": 0,
  "gaps_count": 1
}
```

**Add a control:**

```bash
curl -X POST \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  "http://localhost:8000/api/v1/posture-scoring/controls?org_id=acme" \
  -d '{
    "control_id": "ctrl-mfa-001",
    "name": "MFA on all admin accounts",
    "domain": "identity",
    "weight": 0.9,
    "status": "implemented"
  }'
```

```json
{
  "id": "90bba5f4-cdf3-4061-9a54-ccbf5663336b",
  "org_id": "acme",
  "name": "MFA on all admin accounts",
  "domain": "identity",
  "weight": 0.9,
  "control_status": "not_implemented",
  "created_at": "2026-04-20T13:09:20.570784+00:00"
}
```

---

### 20. GET /metrics

Prometheus metrics endpoint. Exposes per-endpoint request counts, HTTP status codes, and Python GC stats.

```bash
curl http://localhost:8000/metrics
```

**Response (Prometheus text format):**
```
# HELP fixops_http_requests_total Total HTTP requests handled by the ALdeci API
# TYPE fixops_http_requests_total counter
fixops_http_requests_total{endpoint="/api/v1/brain/ingest/finding",method="POST",status_code="200"} 615.0
fixops_http_requests_total{endpoint="/api/v1/brain/nodes",method="POST",status_code="201"} 35.0
fixops_http_requests_total{endpoint="/api/v1/analytics/dashboard/executive",method="GET",status_code="200"} 4.0
fixops_http_requests_total{endpoint="/api/v1/analytics/dashboard/overview",method="GET",status_code="200"} 4.0
fixops_http_requests_total{endpoint="/api/v1/brain/stats",method="GET",status_code="200"} 15.0
fixops_http_requests_total{endpoint="/api/v1/health",method="GET",status_code="200"} 8.0
# HELP python_info Python platform information
# TYPE python_info gauge
python_info{implementation="CPython",major="3",minor="11",patchlevel="15",version="3.11.15"} 1.0
```

> No authentication required. Suitable for Prometheus scrape config: `scrape_configs: [{job_name: "aldeci", static_configs: [{targets: ["localhost:8000"]}]}]`

---

## Endpoint Count Summary

| Domain | Prefixes | Est. Endpoints |
|--------|----------|----------------|
| Platform & Infrastructure | 263 | ~2,100 |
| Application & API Security | 73 | ~550 |
| Vulnerability & Risk Management | 44 | ~380 |
| Security Operations & Metrics | 41 | ~350 |
| Threat Intelligence | 29 | ~240 |
| Cloud & Container Security | 25 | ~215 |
| Incident Response & SOC | 20 | ~180 |
| Network Security | 17 | ~140 |
| Compliance & Governance | 15 | ~130 |
| Identity & Access Management | 13 | ~120 |
| Data Security & Privacy | 12 | ~115 |
| Endpoint Security | 8 | ~74 |
| AI & ML Security | 1 | ~15 |
| **Total** | **561** | **~5,263** |

---

*Generated: 2026-04-17 | Branch: features/intermediate-stage | Server: http://localhost:8000*
