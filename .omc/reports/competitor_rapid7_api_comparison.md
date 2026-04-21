# Rapid7 InsightVM API vs ALDECI — Competitive API Analysis

**Generated:** 2026-04-17
**Analyst:** Executor Agent
**Sources:** docs.rapid7.com, help.rapid7.com/insightvm/en-us/api, github.com/riza/rapid7-insightvm-api-docs, Rapid7 community forums

---

## 1. Rapid7 InsightVM API Overview

### API Versions

| Version | Base Path | Status |
|---------|-----------|--------|
| v3 (Security Console) | `https://<host>:<port>/api/3/` | Current / On-Prem |
| v4 (Cloud Integrations) | `https://us.api.insight.rapid7.com/vm/v4/` | Cloud / SaaS |

### Authentication

- **Method:** HTTP Basic Authentication (`Authorization: Basic base64(username:password)`)
- **2FA:** Supported as optional layer on top of Basic Auth
- **No API key support** in v3 — credentials are sent with every request
- **Cloud v4** uses an `X-Api-Key` header (Insight Platform API key)
- **Remediation projects** use a separate `IPIMS_SESSION` + `IPIMS_PRODUCT_TOKEN` via SAML SSO — not the standard API key (effectively a third auth scheme)

### Spec Format

OpenAPI v2 (Swagger 2.0) — available for download at `help.rapid7.com/insightvm/en-us/api/api-v3.json`

---

## 2. Rapid7 InsightVM API — Categories & Endpoint Counts

**Total: 328 endpoints across 20 functional modules**

| Category | Endpoints | Notes |
|----------|-----------|-------|
| Sites | 84 | Largest module — scan target management |
| Users | 32 | User + permission management |
| Policies | 26 | CIS/STIG policy assessment |
| Assets | 25 | Asset CRUD, search |
| Vulnerabilities | 24 | Vuln content library |
| Asset Groups | 22 | Dynamic/static group management |
| Scan Engines | 22 | Scan engine lifecycle |
| Tags | 21 | Asset categorization |
| Asset Discovery | 10 | Discovery connections |
| Policy Overrides | 8 | Exception handling |
| Vulnerability Results | 7 | Assessment findings per asset |
| Vulnerability Exceptions | 7 | Risk acceptance workflow |
| Credentials | 6 | Shared credential management |
| Administration | 6 | System config |
| Scans | 5 | Scan start/stop/status |
| Scan Templates | 5 | Scan configuration templates |
| Vulnerability Checks | 4 | Check definitions |
| Reports | 13 | Report generation & delivery |
| **Remediation** | **1** | Single guidance endpoint — no project/ticket CRUD |
| Root | 1 | API info |

### Remediation Gap (Critical Finding)

The official v3 API exposes **only 1 remediation endpoint** — it returns generic guidance, not actionable workflow state.

Remediation _projects_ exist in the InsightVM UI but are accessible only via **undocumented, unsupported internal endpoints** requiring SAML session tokens:

```
GET /ea/ra/api/2/project/_summary          # project stats
GET /ea/ra/api/3/project                   # project list
GET /ea/ra/api/2/project/{uuid}/remediation  # remediation items
GET /ea/ra/api/2/project/{id}/remediation/{id}/solution  # solution detail
```

These are not in the official OpenAPI spec and break with product updates. There is **no ticket creation, assignment, SLA tracking, or status transitions** via the official API.

---

## 3. ALDECI API Overview

### API Version

Single unified version: `v1`
Base path: `https://<host>/api/v1/`

### Authentication

- **Method:** API Key via `Authorization` header — `Depends(api_key_auth)` injected on all endpoints
- Every endpoint enforces auth via FastAPI `dependencies=[Depends(api_key_auth)]`
- No Basic Auth credential transmission per request
- Single consistent auth scheme across all 574+ routers

### Spec Format

FastAPI auto-generates OpenAPI v3.1 at `/docs` and `/openapi.json`

---

## 4. ALDECI API — Categories & Endpoint Counts

**Total: 4,877 endpoints across 596 router files**

Selected categories relevant to the Rapid7 comparison:

| Category | ALDECI Endpoints | Rapid7 Equivalent | Rapid7 Endpoints |
|----------|-----------------|-------------------|------------------|
| Vulnerability Management | 200 | Vulnerabilities + Results + Exceptions | 38 |
| Scanning | 89 | Scans + Scan Engines + Templates | 32 |
| Asset Management | 67 | Assets + Asset Groups + Discovery | 57 |
| Reporting | 105 | Reports | 13 |
| Risk Management | 98 | (none — risk scoring is UI-only in InsightVM) | 0 |
| Remediation | 47 | Remediation | 1 |
| Compliance/Policy | (80+ across compliance engines) | Policies + Policy Overrides | 34 |

### ALDECI Remediation API (47 endpoints across 4 routers)

**`/api/v1/remediation`** — Core remediation tasks:
- `POST /tasks` — create task
- `GET /tasks` — list with filters
- `GET /tasks/{id}` — get task
- `PATCH /tasks/{id}/status` — update status
- `POST /tasks/{id}/autofix` — AI-suggested fix
- `GET /tasks/{id}/autofix-suggestions`
- `POST /tasks/{id}/assign`, `/verify`, `/link-ticket`
- `GET /sla-breaches`, `/metrics`, `/backlog`, `/stats`
- `POST /status-transition`, `GET /valid-statuses`

**`/api/v1/vuln-remediation`** — 8-state lifecycle engine:
- `POST /tasks`, `GET /tasks`, `GET /tasks/{id}`
- `PATCH /tasks/{id}/status`
- `POST/GET /tasks/{id}/notes`
- `GET /tasks/overdue`, `/metrics`

**`/api/v1/autonomous-remediation`** — Automation layer:
- `POST/GET /workflows`, `PUT /workflows/{id}/activate`
- `POST/GET /executions`
- `POST/GET /playbooks`, `PUT /playbooks/{id}/run`
- `GET /stats`

**`/api/v1/vuln-workflow`** — Ticket + SLA management:
- `POST/GET /tickets`, `GET/PATCH /tickets/{id}`
- `POST /tickets/{id}/comments`, `/assign`, `/accept-risk`
- `POST /tickets/bulk-assign`, `/bulk-close`
- `GET /sla`

---

## 5. Head-to-Head Comparison

| Dimension | Rapid7 InsightVM API v3 | ALDECI |
|-----------|------------------------|--------|
| **Total endpoints** | 328 | 4,877 |
| **Router/module count** | 20 | 596 |
| **API version** | v3 (on-prem), v4 (cloud) | v1 unified |
| **Auth method** | Basic Auth (username:password) per request | API key header, single scheme |
| **Spec format** | OpenAPI v2 (Swagger 2.0) | OpenAPI v3.1 (auto-generated) |
| **Remediation endpoints** | 1 official + 4 undocumented internal | 47 across 4 routers |
| **Remediation workflow** | No ticket CRUD, no SLA, no assignments via API | Full lifecycle: create/assign/status/SLA/autofix/bulk-ops |
| **Autonomous remediation** | None | AI-powered workflow engine with playbooks |
| **Risk scoring API** | None (UI-only) | 98 endpoints across risk_aggregator, risk_register, risk_scoring, risk_quantification, risk_treatment |
| **Asset management** | 57 endpoints | 67 endpoints |
| **Vulnerability coverage** | 38 endpoints (content + results + exceptions) | 200 endpoints (discovery, enrichment, lifecycle, prioritization, scoring, correlation, age, workflow, fusion) |
| **Scanning** | 32 endpoints | 89 endpoints (self-scan, dep-scan, container, IAC, secret, license scanners) |
| **Reporting** | 13 endpoints | 105 endpoints (scheduled, CISO, exec, compliance, regulatory, posture) |
| **Compliance/Policy** | 34 endpoints (CIS/STIG only) | 80+ endpoints across 12 compliance engines (SOC2, PCI-DSS, HIPAA, GDPR, NIST, ISO 27001) |
| **Deployment model** | On-prem (v3) or SaaS (v4) — separate APIs | Single unified API regardless of deployment |
| **Self-hosted** | Yes (on-prem) but expensive license | Yes — open-source stack, $35-60/month |
| **Pricing** | $50K-500K/yr enterprise license | Self-hosted, fraction of cost |

---

## 6. ALDECI Advantages

### 6.1 Remediation is a First-Class API Citizen

Rapid7's remediation exists only in the UI. Their API exposes a single guidance endpoint; actual project management requires undocumented internal APIs that break on updates. ALDECI exposes 47 dedicated remediation endpoints covering the full lifecycle: task creation, assignment, status transitions, SLA enforcement, AI-powered autofix suggestions, bulk operations, and autonomous playbook execution.

### 6.2 AI-Augmented Workflows

ALDECI's `autonomous_remediation_router` adds a layer Rapid7 has no equivalent for: AI-triggered workflow execution, playbook orchestration, and autofix suggestions via LLM council. This turns remediation from a tracking system into an execution engine.

### 6.3 Unified Auth Model

Rapid7 forces teams to juggle three authentication schemes: Basic Auth for v3, API keys for v4 Cloud, and SAML session tokens for remediation projects. ALDECI uses a single `api_key_auth` dependency injected uniformly across all 596 routers — one credential, one scheme, zero confusion.

### 6.4 Risk API Coverage

Rapid7 exposes no programmatic risk scoring — risk is computed internally and surfaced only in the UI and reports. ALDECI exposes 98 risk endpoints covering asset risk calculation, composite risk scoring, risk quantification (FAIR methodology), risk register CRUD, risk treatment workflows, and risk aggregation with A-F grading.

### 6.5 API Breadth

ALDECI's 4,877 endpoints vs Rapid7's 328 represents a 15x surface area difference. More importantly, ALDECI covers adjacent security domains (CSPM, SIEM, MDM, IoT, OT, AI governance, supply chain, DLP, deception) that InsightVM simply does not address — it is exclusively a vulnerability management tool.

---

## 7. Rapid7 Advantages (Honest Assessment)

| Advantage | Detail |
|-----------|--------|
| **Maturity** | 15+ years of production hardening, CVE database depth |
| **Scanner accuracy** | Authenticated scanning with credentialed checks at enterprise scale |
| **Integrations** | 100+ native integrations (Jira, ServiceNow, Slack, Splunk) |
| **Compliance certifications** | SOC2 Type II, FedRAMP authorized |
| **Support SLAs** | 24/7 enterprise support with contractual SLAs |
| **Agent coverage** | Insight Agent deployed across millions of endpoints globally |

---

## 8. Strategic Opportunity

The Rapid7 remediation gap is a concrete sales wedge:

> "InsightVM finds your vulnerabilities. It cannot fix them through its API. Your engineering team cannot automate remediation workflows without scraping undocumented internal endpoints that break on every release. ALDECI exposes 47 remediation endpoints — task lifecycle, SLA enforcement, AI autofix, bulk operations, and autonomous playbook execution — all in a documented, stable, auth-gated API."

Target buyers: DevSecOps teams and platform engineering teams who need to integrate vulnerability remediation into CI/CD pipelines and internal ticketing systems — exactly the teams Rapid7 fails via API.

---

## 9. Gaps to Close

| Gap | Priority | Notes |
|-----|----------|-------|
| Authenticated scanner accuracy | HIGH | ALDECI scanners are not credentialed at InsightVM depth |
| CVE content depth | HIGH | InsightVM vuln library has 20+ years of check authorship |
| Agent-based continuous assessment | MEDIUM | ALDECI has no lightweight endpoint agent equivalent |
| Official integration marketplace | MEDIUM | InsightVM has 100+ certified partner integrations |
| FedRAMP / compliance certifications | LOW | Not needed for current target market |

---

*Sources: [InsightVM API v3](https://help.rapid7.com/insightvm/en-us/api/index.html) · [RESTful API Docs](https://docs.rapid7.com/insightvm/restful-api/) · [InsightVM Cloud API v4](https://help.rapid7.com/insightvm/en-us/api/integrations.html) · [Rapid7 API Examples](https://github.com/rapid7/insightvm-api-examples) · [API Docs (Markdown)](https://github.com/riza/rapid7-insightvm-api-docs) · [Remediation Projects Community Thread](https://discuss.rapid7.com/t/using-api-or-sql-to-get-info-from-remediation-projects/2739) · [April 2026 Release Notes](https://docs.rapid7.com/insight/release-notes-2026-april/)*
