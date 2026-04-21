# CrowdStrike Falcon API vs. ALDECI API — Competitive Comparison

**Date:** 2026-04-17
**Analyst:** Executor (Claude Sonnet 4.6)
**Branch:** features/intermediate-stage
**Purpose:** API-level competitive intelligence — gaps, parity, and ALDECI advantages

---

## 1. CrowdStrike Falcon API — Overview

CrowdStrike Falcon exposes a unified REST API called the **Falcon OAuth2 API**, documented at
`developer.crowdstrike.com` (login required for full OpenAPI spec). The Python SDK
[FalconPy](https://falconpy.io) is the authoritative open-source reference for all service
collections and operations.

| Dimension | CrowdStrike Falcon |
|---|---|
| API base URL | `https://api.crowdstrike.com` |
| Auth method | OAuth2 client credentials (Bearer token) |
| Token TTL | 30 minutes, auto-renewable |
| Total service collections | **106** |
| Total operations | 500+ (estimated from FalconPy coverage) |
| Rate limit | **6,000 requests/minute** per customer account |
| Rate limit headers | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-RetryAfter` |
| Rate limit error | HTTP 429 with `Retry-After` (10s / 15s / 30s) |
| Pagination | `offset` + `limit` pattern; max 500 IOCs per call |
| Streaming API | Yes — Event Streams API (real-time detection feed) |
| SDK languages | Python (FalconPy), Go, PowerShell (PSFalcon), JavaScript, Rust, Ruby |
| OpenAPI spec | Available at developer.crowdstrike.com (authenticated) |
| On-premise option | No — SaaS only |

---

## 2. CrowdStrike API Categories (106 Service Collections)

The 106 service collections group into these functional domains:

### 2.1 Detection & Response
| Collection | Key Operations |
|---|---|
| **Detections** | Query detections, get detection details, resolve detections, update status |
| **Incidents** | Query incidents, get incident details, link detections to incidents |
| **Alert Triage** | Assign, update severity, bulk-resolve alerts |
| **Real Time Response (RTR)** | Execute commands on live endpoints, file upload/download, script execution |
| **Real Time Response Admin** | Manage RTR scripts, put-file management, admin command exec |
| **Event Streams** | Establish streaming connection, refresh partition, get available topics |

### 2.2 Endpoint Security (EDR/XDR)
| Collection | Key Operations |
|---|---|
| **Hosts** | Query devices, get device details, contain host, lift containment, hide/unhide hosts |
| **Host Groups** | CRUD group membership, assign prevention policies |
| **Sensor Update Policies** | Manage sensor versions, build targeting, policy assignment |
| **Prevention Policies** | CRUD AV/malware prevention policy rules |
| **Device Control Policies** | USB and removable media control |
| **Firewall Management** | Rule groups, policy rules, network location management |
| **Firewall Policies** | Assign firewall policy sets to host groups |

### 2.3 Threat Intelligence
| Collection | Key Operations |
|---|---|
| **Intel** | Query threat actors, get actor details, query indicators (IOCs), query reports |
| **IOC Manager** | Create/read/update/delete custom IOCs, bulk IOC ingestion (500/call max) |
| **IOCs** | Legacy IOC endpoint (deprecated, use IOC Manager) |
| **MITRE ATT&CK** | Query technique details, technique coverage |

### 2.4 Vulnerability Management
| Collection | Key Operations |
|---|---|
| **Spotlight Vulnerabilities** | Query CVEs on endpoints, get vulnerability details, get remediation paths |
| **Spotlight Evaluation Logic** | Query CVE evaluation logic, get applicable logic |

### 2.5 Cloud Security (CSPM / CNAPP)
| Collection | Key Operations |
|---|---|
| **CSPM Registration** | Register cloud accounts (AWS/Azure/GCP), delete registrations |
| **Horizon** | Query cloud posture findings, get finding details, remediation guidance |
| **D4C Registration** | Discover for Cloud registration |
| **Kubernetes Protection** | Register Kubernetes clusters, query cluster findings |
| **Container Alerts** | Query container-level alerts |
| **Container Detections** | Query container runtime detections |
| **Container Images** | Scan container images, get findings |
| **Container Packages** | Query packages in containers for vulnerabilities |
| **Container Vulnerabilities** | Query CVEs affecting container images |

### 2.6 Identity Security
| Collection | Key Operations |
|---|---|
| **Identity Protection** | Query identity-based detections, get identity entities |
| **Zero Trust Assessment** | Query ZTA scores per device/user, get assessment details |
| **User Management** | CRUD users, roles, role assignments |
| **OAuth2** | Generate/revoke access tokens |

### 2.7 Asset Discovery
| Collection | Key Operations |
|---|---|
| **Discover** | Query discovered applications, hosts, accounts, logins |
| **Asset Graph** | Graph-based asset relationship queries |

### 2.8 Compliance & Benchmarking
| Collection | Key Operations |
|---|---|
| **Compliance Assessments** | Query CIS/NIST/PCI benchmark results per device |

### 2.9 Exposure Management
| Collection | Key Operations |
|---|---|
| **Exposure Management** | External attack surface queries, asset prioritization |
| **ThreatGraph** | Threat activity graph, adversary pattern queries |

### 2.10 SOAR / Automation
| Collection | Key Operations |
|---|---|
| **Falcon Fusion Workflows** | CRUD automation workflows (SOAR-lite) |
| **Workflows** | Trigger executions, query workflow run history |

### 2.11 Infrastructure / Platform
| Collection | Key Operations |
|---|---|
| **Foundry LogScale** | Ingest logs, query log data (NG-SIEM) |
| **Message Center** | Read platform notices, support case management |
| **Sample Uploads** | Upload malware samples to Falcon Sandbox |
| **Sandbox** | Submit samples for analysis, get analysis reports |
| **Quick Scan** | Rapid AV scan using cloud hash lookup |
| **Custom Storage** | Custom data store within Falcon platform |
| **Recon** | Digital risk protection — dark web monitoring |

### 2.12 MSSP / Tenant Management
| Collection | Key Operations |
|---|---|
| **Flight Control (MSSP)** | Manage child CIDs, delegate permissions, aggregate across tenants |
| **Installation Tokens** | Generate/revoke sensor installation tokens |
| **Sensor Download** | Download sensor installers for Windows/Linux/macOS |

---

## 3. CrowdStrike Event Streams API (Real-Time)

The Event Streams API is CrowdStrike's streaming layer — the equivalent of a webhook/push model
for continuous event delivery.

**Technical details:**
- Protocol: Server-sent events (SSE) over HTTPS — long-lived HTTP connection
- Endpoint: `/sensors/entities/datafeed/v2`
- Event types delivered: Detection events, incident events, audit events, auth activity, IOA events, sensor lifecycle events
- Partitioning: Multiple partitions supported for high-throughput consumers
- Refresh: Partition offset must be refreshed periodically to maintain connection
- Use case: Feed into SIEM (Splunk, Elastic, QRadar), custom SOC tooling, data lake pipelines

**Event payload schema:**
```json
{
  "metadata": { "eventType": "DetectionSummaryEvent", "offset": 12345 },
  "event": {
    "DetectId": "ldt:abc123",
    "Severity": 4,
    "SeverityName": "High",
    "FileName": "malware.exe",
    "CommandLine": "...",
    "Tactic": "Execution",
    "Technique": "T1059.001"
  }
}
```

---

## 4. CrowdStrike Auth — OAuth2 Flow

```
POST https://api.crowdstrike.com/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=CLIENT_ID&client_secret=CLIENT_SECRET
```

Response:
```json
{ "access_token": "eyJ...", "token_type": "bearer", "expires_in": 1799 }
```

All subsequent calls use: `Authorization: Bearer <access_token>`

API scopes are defined at client creation time in the Falcon console and cannot be changed
per-request. Scope examples: `detections:read`, `hosts:read:write`, `ioc:read:write`,
`real-time-response:read:write:admin`, `spotlight-vulnerabilities:read`.

---

## 5. ALDECI API — Current State

### 5.1 Scale
| Dimension | ALDECI |
|---|---|
| Total router files | **568** |
| Estimated endpoints | **574+ route prefixes** (each with 5-15 operations) |
| Auth method | API key (`X-API-Key` header) + JWT session tokens |
| Rate limiting | Per-org Redis-backed rate limiter (`tenant_rate_limiter_router.py`) |
| Streaming | WebSocket (`ws_events`, `websocket_alerts`, `streaming`, `stream` routers) |
| Multi-tenant | Yes — org_id isolation on all engines |
| On-premise | Yes — fully self-hosted (Docker + Kubernetes) |
| OpenAPI | Yes — `/api/v1/docs` (FastAPI auto-generated) |

### 5.2 ALDECI API Domain Map

**Detection & Response (SOC)**
- `/api/v1/alert-triage` — AI-assisted alert triage, bulk resolve
- `/api/v1/alerting` — Alert policies, MTTR, acknowledge/resolve
- `/api/v1/alert-enrichment` — SHA-256 IOC enrichment, priority queue
- `/api/v1/soc-workflow` — Case management, SLA tracking
- `/api/v1/soc-metrics` — MTTD/MTTR daily snapshots, analyst workload
- `/api/v1/incident-orchestration` — 5-state incident lifecycle
- `/api/v1/incident-triage` — AI severity scoring
- `/api/v1/incident-metrics` — MTTR/MTTC computation
- `/api/v1/incident-comms` — 7-channel stakeholder notifications
- `/api/v1/incident-costs` — 10-category cost tracking, estimated vs actual
- `/api/v1/incident-lessons` — Post-incident knowledge capture
- `/api/v1/incident-kb` — Knowledge base search, top-5 article ranking
- `/api/v1/ai-soc` — AI-powered triage, model accuracy tracking

**Threat Intelligence**
- `/api/v1/threat-intel` — Feeds, IOC management
- `/api/v1/threat-indicators` — IOC lifecycle, sighting_count, TTL
- `/api/v1/threat-intel-fusion` — Multi-source fusion, consensus confidence
- `/api/v1/ti-automation` — Feed automation, SHA-256 API key hashing
- `/api/v1/ti-confidence` — IOC confidence weighted avg, false-positive floor
- `/api/v1/cyber-threat-intel` — CTI reports, IOC TLP management
- `/api/v1/threat-attribution` — Nation-state actor tracking, TTP frequency
- `/api/v1/threat-landscape` — 6 actor types, overall risk computation
- `/api/v1/dark-web` — Dark web monitoring, credential exposure, SHA-256 URL hashing
- `/api/v1/intel-enrichment` — Bulk IOC enrichment, auto-complete on source response
- `/api/v1/threat-vectors` — 8 vector types, risk_score avg computation
- `/api/v1/threat-briefs` — TLP-classified brief distribution
- `/api/v1/feed-subscriptions` — 7 feed types, error_count/success tracking
- `/api/v1/zero-day` — ZeroDayIntelligence, CVSS, exploitation status

**Endpoint / Host Security**
- `/api/v1/edr` — Endpoint Detection & Response
- `/api/v1/xdr` — Extended Detection & Response
- `/api/v1/ndr` — Network Detection & Response
- `/api/v1/endpoint-hunting` — Hunt lifecycle, planned→active→completed
- `/api/v1/endpoint-compliance` — Severity-weighted scoring, bulk ingestion
- `/api/v1/patch-management` — Deploy/fail counters, undeployed_critical tracking
- `/api/v1/firmware-security` — 9 device types, scan lifecycle
- `/api/v1/mobile-app-security` — OWASP mapping, 5 platforms
- `/api/v1/itdr` — Identity threat detection, behavior analytics

**Vulnerability Management**
- `/api/v1/vuln-lifecycle` — 8-state machine, SLA tracking
- `/api/v1/cve` — NVD + EPSS + KEV enrichment
- `/api/v1/vuln-intel` — CVE upserts, EPSS/KEV, advisories
- `/api/v1/vuln-prioritization` — CVSS+EPSS+KEV+exposure composite scoring
- `/api/v1/vuln-scoring` — Criticality multipliers 0.75–2.0, override audit
- `/api/v1/vuln-age` — SLA per severity, sla_breached detection
- `/api/v1/vuln-correlation` — Asset-vuln cross-correlation
- `/api/v1/vuln-remediation` — 8-state lifecycle, SLA enforcement
- `/api/v1/vuln-workflow` — SLA tiers p1-p4, overdue detection, comment threading
- `/api/v1/vulnerability-correlation` — KEV tracking, JSON round-trip
- `/api/v1/spotlit-vulnerabilities` — (Spotlight parity endpoint)
- `/api/v1/sca` — Software Composition Analysis, Log4Shell detection

**Cloud Security (CSPM / CNAPP)**
- `/api/v1/cloud-compliance` — CIS/NIST/SOC2/PCI-DSS, drift detection
- `/api/v1/cloud-posture` — 6 providers, posture score delta
- `/api/v1/cloud-findings` — Cloud security findings dedup, bulk_ingest
- `/api/v1/cloud-native` — Cloud misconfigs, posture checks
- `/api/v1/cloud-drift` — IaC baseline drift, acknowledge/remediate
- `/api/v1/cloud-accounts` — 7 providers, risk_score→status auto-mapping
- `/api/v1/cloud-access-security` — SaaS/PaaS apps, unique users
- `/api/v1/kubernetes-security` — CIS benchmarks, RBAC analysis
- `/api/v1/cloud-ir` — Cloud incident response, blast_radius
- `/api/v1/container-registry-security` — Image scanning, severity counts
- `/api/v1/container-runtime` — Container lifecycle, violations
- `/api/v1/container-posture` — Posture score delta, clusters_at_risk
- `/api/v1/cwp` — Cloud Workload Protection, 7 providers

**Identity Security**
- `/api/v1/ciem` — IAM entitlement, privilege escalation
- `/api/v1/iam-policy` — Wildcard/toxic combo detection
- `/api/v1/digital-identity` — IAL1/2/3, NIST 800-63
- `/api/v1/cloud-identity` — Federated access, permission analysis
- `/api/v1/identity-risk` — Identity risk factors, access reviews
- `/api/v1/identity-lifecycle` — Deprovision, orphan detection
- `/api/v1/privileged-identity` — Risk auto-compute, anomaly_score clamp
- `/api/v1/access-anomaly` — Impossible travel, high_risk_users
- `/api/v1/mfa` — TOTP/SMS/hardware key enrollment
- `/api/v1/pag` — Privileged access governance
- `/api/v1/session-recording` — 7 session types, alerts_count

**Asset Discovery & Inventory**
- `/api/v1/assets` — Asset inventory
- `/api/v1/asset-criticality` — Weighted scoring, BFS critical path
- `/api/v1/asset-lifecycle` — Procurement→decommission, EOL alerts
- `/api/v1/asset-tagging` — 8 tag categories, idempotent assign
- `/api/v1/asset-groups` — 8 group types, MAX(0,n-1) remove floor
- `/api/v1/cmdb` — CMDB integration
- `/api/v1/cloud-inventory` — 7 providers, 10 resource types
- `/api/v1/api-inventory` — 6 API types, undocumented API detection
- `/api/v1/api-discovery` — Endpoint discovery, risk scoring

**Compliance**
- `/api/v1/compliance` — 7 frameworks (SOC2/ISO27001/NIST/PCI-DSS/HIPAA/GDPR/CIS)
- `/api/v1/compliance-mapping` — 8 frameworks, implementation_rate
- `/api/v1/compliance-gaps` — Control gaps, remediation plans
- `/api/v1/compliance-automation` — Automated control testing, pass-rate stats
- `/api/v1/compliance-workflows` — 8 frameworks, approve/reject lifecycle
- `/api/v1/compliance-calendar` — Recurring events, overdue detection
- `/api/v1/gdpr` — 6 lawful bases, consent lifecycle
- `/api/v1/data-privacy` — DSR requests, 30-day overdue
- `/api/v1/regulatory-reporting` — Multi-framework report generation
- `/api/v1/audit-management` — Audit scheduling, finding lifecycle

**SOAR / Automation**
- `/api/v1/soar` — SOAR playbooks
- `/api/v1/security-playbooks` — IR playbook execution
- `/api/v1/autonomous-remediation` — Workflows, success_rate tracking
- `/api/v1/security-automation` — Rules, execution history
- `/api/v1/incident-orchestration` — 5-state lifecycle, MTTR

**Streaming / Real-Time**
- `/ws/events` (WebSocket) — Real-time alert/event push
- `/api/v1/websocket-alerts` — WebSocket alert subscriptions
- `/api/v1/stream` — Event streaming endpoint
- `/api/v1/streaming` — Streaming configuration

---

## 6. Head-to-Head API Comparison

### 6.1 Authentication

| Feature | CrowdStrike | ALDECI |
|---|---|---|
| Auth method | OAuth2 client credentials | API key (header) + JWT |
| Token TTL | 30 min | Configurable (JWT exp) |
| Scope granularity | Per-client scope at creation time | Role-based (RBAC, 6 roles) |
| Multi-tenant auth | Flight Control (MSSP) | org_id isolation on all endpoints |
| SSO | Falcon console SSO | SAML/OIDC bridge (PyJWKClient RS256) |

**ALDECI gap:** OAuth2 client credentials flow not exposed — enterprise integrators expect OAuth2. ALDECI exposes API keys which are simpler but less standard for machine-to-machine auth.

**ALDECI advantage:** SAML/OIDC bridge already built; SSO is first-class, not just console-level.

### 6.2 Rate Limiting

| Feature | CrowdStrike | ALDECI |
|---|---|---|
| Default limit | 6,000 req/min per account | Org-configured via Redis rate limiter |
| Headers | `X-RateLimit-Limit/Remaining/RetryAfter` | Not yet standardized in headers |
| Error code | HTTP 429 | HTTP 429 |
| Per-endpoint limits | Yes (varies by collection) | Configurable per-org |

**ALDECI gap:** Rate limit headers (`X-RateLimit-*`) are not uniformly emitted across all routers. CrowdStrike exposes these consistently — important for SDK/integration authors.

### 6.3 Detection & Alert APIs

| Capability | CrowdStrike | ALDECI |
|---|---|---|
| Detection queries | Yes — filter by host, severity, status | Yes — `/api/v1/alert-triage` |
| Bulk resolve | Yes | Yes — bulk_triage |
| Alert enrichment | Limited (inline context) | Yes — dedicated `/api/v1/alert-enrichment` |
| AI triage scoring | No | Yes — `/api/v1/incident-triage` AI severity |
| MTTD/MTTR tracking | Via LogScale (paid add-on) | Yes — `/api/v1/soc-metrics`, `/api/v1/incident-metrics` |
| Incident cost tracking | No | Yes — `/api/v1/incident-costs` (10 categories) |
| Post-incident lessons | No | Yes — `/api/v1/incident-lessons` |
| Incident KB search | No | Yes — `/api/v1/incident-kb` |

**ALDECI advantage:** More granular SOC operational APIs. CrowdStrike's detection API is read-only for most third-party tools; ALDECI exposes full lifecycle.

### 6.4 Threat Intelligence APIs

| Capability | CrowdStrike | ALDECI |
|---|---|---|
| Threat actor profiles | Yes — Intel API (100+ actors) | Yes — `/api/v1/threat-attribution`, `/api/v1/actor-tracking` |
| IOC management | Yes — IOC Manager (create/read/update/delete) | Yes — `/api/v1/threat-indicators` |
| IOC bulk ingestion | 500/call max | Configurable batch size |
| Dark web monitoring | Yes — Recon API | Yes — `/api/v1/dark-web` (SHA-256 URL hashing) |
| TLP classification | TLP:WHITE/GREEN/AMBER/RED | Yes — TLP classification on all intel endpoints |
| IOC confidence scoring | Limited | Yes — weighted avg, false-positive floor 0.1 |
| Threat feed subscriptions | Via Falcon platform (not API-configurable) | Yes — `/api/v1/feed-subscriptions` (7 types) |
| Fusion/consensus | No | Yes — `/api/v1/threat-intel-fusion` (multi-source consensus) |
| Zero-day intelligence | Limited (via Intel API) | Yes — `/api/v1/zero-day` (exploitation status) |

**ALDECI advantage:** Richer IOC confidence model, fusion engine, and feed subscription management via API.

**ALDECI gap:** CrowdStrike Intel API has ~100 structured threat actor profiles built by their Adversary Intelligence team. ALDECI's actor data depends on what is ingested — no curated actor dataset built-in.

### 6.5 Real-Time Response (RTR) — Critical Gap

| Capability | CrowdStrike RTR | ALDECI |
|---|---|---|
| Live shell on endpoint | Yes — bi-directional command channel | No |
| File upload to endpoint | Yes | No |
| File download from endpoint | Yes | No |
| Script execution | Yes (PowerShell, Bash, Python) | No |
| Host containment (network isolate) | Yes — `/devices/entities/devices-actions/v2` | Partial — containment status tracking only |
| Memory forensics | Yes (via RTR + Sandbox) | No |

**ALDECI gap (Critical):** CrowdStrike RTR is their most-used API by SOC teams. It enables live response on any managed endpoint. ALDECI has no equivalent — no agent deployed to endpoints, no command channel. This is the single largest functional gap for enterprise SOC use cases.

### 6.6 Streaming API

| Capability | CrowdStrike Event Streams | ALDECI |
|---|---|---|
| Protocol | SSE (Server-Sent Events) over HTTPS | WebSocket |
| Event types | Detection, incident, audit, auth, IOA, sensor lifecycle | Alert, SOC events, threat intel updates |
| Partition support | Yes — multi-partition for high throughput | Single stream per connection |
| Offset management | Yes — resumable from offset | No offset/resumability |
| SIEM-ready | Yes — Splunk/QRadar/Elastic add-ons | Partial — no official SIEM connectors |
| Volume | Full telemetry from all managed endpoints | Platform-level events only |

**ALDECI gap:** Event Streams API is resumable via offset — consumers can reconnect and pick up where they left off. ALDECI WebSocket is fire-and-forget. Also, SSE is simpler for HTTP clients (no WebSocket upgrade required).

### 6.7 Vulnerability Management

| Capability | CrowdStrike Spotlight | ALDECI |
|---|---|---|
| CVE on endpoints | Yes — agent-reported, real-time | No agent — scan-based only |
| EPSS scoring | Yes | Yes — `/api/v1/cve` |
| KEV flagging | Yes | Yes — `/api/v1/cve` |
| Remediation guidance | Per-CVE patch info | Yes — `/api/v1/vuln-remediation` |
| SLA tracking | No | Yes — SLA tiers p1-p4, overdue detection |
| Risk-based prioritization | Yes — ExPRT.AI scoring | Yes — CVSS+EPSS+KEV+exposure composite |
| Vuln workflow / ticketing | Via Fusion workflows | Yes — dedicated `/api/v1/vuln-workflow` |
| SCA / SBOM | Via Falcon SCA module (add-on) | Yes — `/api/v1/sca`, `/api/v1/sbom-export` (free) |

**ALDECI advantage:** More complete vuln lifecycle management (8-state machine, SLA, workflow, SBOM). CrowdStrike's Spotlight is real-time but requires agent; ALDECI is agentless.

**ALDECI gap:** CrowdStrike's ExPRT.AI proprietary risk scoring and agent-based real-time CVE detection are not replicable without an endpoint agent.

### 6.8 Cloud Security

| Capability | CrowdStrike Horizon/CSPM | ALDECI |
|---|---|---|
| Cloud providers | AWS, Azure, GCP, OCI | AWS, Azure, GCP (6 total via cloud_posture) |
| Account registration API | Yes — CSPM Registration | Yes — `/api/v1/cloud-accounts` |
| Misconfig detection | Yes | Yes — `/api/v1/cloud-compliance`, `/api/v1/cloud-native` |
| IaC drift | Limited | Yes — `/api/v1/cloud-drift` |
| Kubernetes security | Yes — cluster registration + findings | Yes — `/api/v1/kubernetes-security` |
| Container image scan | Yes | Yes — `/api/v1/container-registry-security` |
| Container runtime | Yes — real-time agent-based | Yes — `/api/v1/container-runtime` (agentless) |

**Near parity** — both cover the major cloud security use cases.

### 6.9 Compliance

| Capability | CrowdStrike | ALDECI |
|---|---|---|
| CIS benchmark per device | Yes — Compliance Assessments API | Yes — `/api/v1/config-benchmark`, `/api/v1/endpoint-compliance` |
| Framework count | CIS only (via API) | 7 frameworks (SOC2/ISO27001/NIST/PCI-DSS/HIPAA/GDPR/CIS) |
| Compliance automation | No | Yes — `/api/v1/compliance-automation` |
| GDPR DSR workflow | No | Yes — `/api/v1/gdpr`, `/api/v1/data-privacy` |
| Audit management | No | Yes — `/api/v1/audit-management` |
| Evidence collection | No | Yes — `/api/v1/auto-evidence`, `/api/v1/evidence-vault` |
| Compliance calendar | No | Yes — `/api/v1/compliance-calendar` |

**ALDECI advantage:** Substantially richer compliance API surface. CrowdStrike's compliance API is limited to CIS device benchmarks; ALDECI covers the full GRC lifecycle.

### 6.10 MSSP / Multi-Tenancy

| Capability | CrowdStrike Flight Control | ALDECI |
|---|---|---|
| Child tenant management | Yes — delegate, aggregate, manage CIDs | Yes — org_id isolation, tenant API |
| Cross-tenant queries | Yes — aggregate across all child CIDs | Yes — analytics_router cross-org |
| Per-tenant rate limiting | No (account-level only) | Yes — `tenant_rate_limiter_router` |
| Tenant onboarding API | Yes | Yes — `/api/v1/tenant` |

**Near parity** — ALDECI adds per-tenant rate limiting which CrowdStrike lacks.

---

## 7. Summary Scorecard

| Domain | CrowdStrike | ALDECI | Winner |
|---|---|---|---|
| Auth (OAuth2 standard) | OAuth2 client credentials | API key + JWT | CrowdStrike |
| Rate limit transparency | X-RateLimit-* headers, 6k/min | Redis-backed, headers not uniform | CrowdStrike |
| Detection / Alert APIs | Standard CRUD + bulk resolve | Full lifecycle + AI triage + cost tracking | ALDECI |
| Threat Intelligence APIs | Curated actor DB, IOC CRUD | Fusion engine, confidence model, dark web | Tie |
| Real-Time Response (RTR) | Live endpoint shell, file I/O | Not implemented | CrowdStrike |
| Streaming API | SSE + resumable offsets | WebSocket, no offsets | CrowdStrike |
| Vulnerability Management | Agent-based real-time, ExPRT.AI | Agentless, full workflow, SBOM | Tie |
| Cloud Security (CSPM) | Horizon, 4 providers, agent-optional | 6 providers, IaC drift, agentless | Tie |
| Compliance / GRC | CIS benchmarks only | 7 frameworks, full GRC lifecycle | ALDECI |
| Identity Security | Identity Protection, ZTA | CIEM, ITDR, PAG, access anomaly | Tie |
| MSSP / Multi-Tenancy | Flight Control | org_id + per-tenant rate limiting | Tie |
| Self-hosted / On-prem | No — SaaS only | Yes — Docker + Kubernetes | ALDECI |
| Pricing | $100–$200+/endpoint/year | $35–60/month self-hosted | ALDECI |
| Total API surface | 106 collections, 500+ ops | 568 routers, 574+ prefixes, 2,800+ ops | ALDECI |

---

## 8. Priority Gaps for ALDECI to Close

### Gap 1 — OAuth2 Client Credentials Flow (Priority: HIGH)
Enterprise integrators expect OAuth2. Every SIEM, SOAR, and MSSP tool auto-discovers OAuth2
endpoints. ALDECI's API key is fine for simple integrations but blocks automated onboarding by
enterprise security tools that require OAuth2 machine-to-machine auth.

**Recommendation:** Add `POST /api/v1/oauth2/token` endpoint that issues short-lived JWT access
tokens. Wrap existing API key validation — no breaking changes.

### Gap 2 — Uniform X-RateLimit-* Headers (Priority: MEDIUM)
CrowdStrike emits `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-RetryAfter` on
every response. This allows SDK authors to implement backoff automatically.

**Recommendation:** Add a FastAPI middleware that injects these headers from Redis rate limiter
state. Single middleware, zero per-router changes.

### Gap 3 — Resumable Streaming (SSE + Offsets) (Priority: MEDIUM)
ALDECI WebSocket streaming is fire-and-forget. CrowdStrike Event Streams can be reconnected
from a saved offset — no events lost on reconnect. This is critical for SIEM integrations.

**Recommendation:** Add an SSE endpoint (`/api/v1/events/stream`) backed by Redis XREAD
(Redis Streams) for offset-based resumability. Keep WebSocket for browser clients.

### Gap 4 — Endpoint Agent / RTR (Priority: LOW — Strategic)
CrowdStrike RTR requires a deployed sensor on each endpoint. This is their moat. Building a
competing agent is out of scope for ALDECI's self-hosted strategy.

**Recommendation:** Rather than build an agent, wire ALDECI to *ingest RTR data from CrowdStrike
via the connector framework* — position ALDECI as the aggregation/analytics layer above CrowdStrike.
This turns the gap into a partnership surface.

### Gap 5 — Curated Threat Actor Intelligence (Priority: MEDIUM)
CrowdStrike Intelligence team maintains ~100 named adversary profiles (BEAR, PANDA, KITTEN, etc.)
with TTPs, infrastructure, campaigns. ALDECI's actor data is user-ingested.

**Recommendation:** Wire MISP integration (already planned) and TAXII/STIX feed subscriptions
to auto-populate actor profiles. Use `threat_actor_tracking_engine.py` as the target store.

---

## 9. ALDECI Differentiators vs. CrowdStrike

1. **Self-hosted at 1/50th the cost** — CrowdStrike runs $100–$200/endpoint/year. ALDECI runs
   $35–60/month for the entire platform. For mid-market (500–5,000 seats) this is a $500K–$1M+
   annual saving.

2. **7-framework GRC out of the box** — CrowdStrike's compliance API is CIS benchmarks only.
   ALDECI covers SOC2, ISO27001, NIST, PCI-DSS, HIPAA, GDPR, and CIS with automation, evidence
   collection, and audit calendar.

3. **AI-native SOC layer** — ALDECI's AI-powered SOC engine, AI triage scoring, and AI security
   advisor have no equivalent in CrowdStrike's API surface (they have CrowdAI internally but it
   is not API-exposed for custom use).

4. **2,800+ API operations vs. 500+** — ALDECI's API surface is 5x larger, covering domains
   CrowdStrike doesn't touch (OKRs, security investment ROI, tabletop exercises, quantum-safe
   crypto assessment, digital twin security).

5. **Full data ownership** — CrowdStrike stores all telemetry in their cloud. ALDECI's SQLite
   per-engine model means all data stays in the customer's infrastructure.

6. **Agentless cloud security** — ALDECI achieves cloud security coverage without a deployed
   sensor, using API-based polling. CrowdStrike Horizon is also largely agentless but requires
   account registration through CrowdStrike's SaaS.

---

## 10. Sources

- [CrowdStrike Developer Center](https://developer.crowdstrike.com/)
- [FalconPy Operations Overview](https://www.falconpy.io/Operations/Operations-Overview.html)
- [FalconPy All Operations](https://www.falconpy.io/Operations/All-Operations.html)
- [FalconPy Event Streams](https://falconpy.io/Service-Collections/Event-Streams.html)
- [FalconPy Real Time Response Admin](https://falconpy.io/Service-Collections/Real-Time-Response-Admin.html)
- [FalconPy Spotlight Vulnerabilities](https://www.falconpy.io/Service-Collections/Spotlight-Vulnerabilities.html)
- [How to Get Access to the CrowdStrike API](https://www.crowdstrike.com/blog/tech-center/get-access-falcon-apis/)
- [CrowdStrike API Rate Limits — Axis Security](https://docs.axissecurity.com/docs/checking-your-crowdstrike-rate-limit)
- [CrowdStrike Falcon Streaming v2 — Cortex XSOAR](https://xsoar.pan.dev/docs/reference/integrations/crowd-strike-falcon-streaming-v2)
- [CrowdStrike Falcon Event Streams Add-on Guide (PDF)](https://www.crowdstrike.com/wp-content/uploads/2022/12/CrowdStrike-Falcon-Event-Streams-Add-on-Guide-v3.pdf)
- [CrowdStrike Pricing Guide 2026 — Redress Compliance](https://redresscompliance.com/crowdstrike-falcon-licensing-guide.html)
- [CrowdStrike Pricing 2026 — CostBench](https://costbench.com/software/cybersecurity/crowdstrike/)
- [GitHub CrowdStrike/falconpy](https://github.com/CrowdStrike/falconpy)
- [CrowdStrike API Connector — Medium Feb 2026](https://medium.com/@max_23713/crowdstrike-api-connector-unlocking-the-full-power-of-falcon-c439ca384dcd)
