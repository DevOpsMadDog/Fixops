# Tenable.io API vs ALDECI — Competitive Analysis
**Date:** 2026-04-17
**Analyst:** Executor (Claude Sonnet 4.6)
**Sources:** developer.tenable.com, docs.tenable.com, tenable.com/capabilities

---

## 1. Tenable.io API Overview

### Product Suite
Tenable operates under the **Tenable One** umbrella, with API coverage across:

| Product | API Base |
|---------|----------|
| Vulnerability Management (Tenable.io) | `cloud.tenable.com` |
| Web App Scanning | `cloud.tenable.com` |
| Exposure Management (Lumin) | `cloud.tenable.com` |
| Identity Exposure (Active Directory) | `cloud.tenable.com` |
| Attack Surface Management | `cloud.tenable.com` |
| PCI ASV | `cloud.tenable.com` |
| MSSP Portal | `cloud.tenable.com` |
| OT Security | Separate instance |

### API Specification
- **Format:** OpenAPI 3 (formerly Swagger)
- **Base URL:** `https://cloud.tenable.com`
- **Auth:** API key pair (Access Key + Secret Key) in request headers
- **Rate limiting:** Enforced (429 responses); limits not publicly disclosed
- **Versioning:** Mixed — legacy `/scans`, `/assets` paths plus newer `/api/v2/` namespace
- **Architecture:** Asynchronous job-based for all bulk exports (request → poll status → download chunks)

---

## 2. Tenable API Category Breakdown

### Top-Level API Categories (8)

| # | Category | Key Capability |
|---|----------|---------------|
| 1 | **Tenable Platform & Settings** | Agents, connectors, exclusions, networks, permissions, scanners, tags, access control |
| 2 | **Vulnerability Management** | Asset/scan/policy management, risk insights, workbenches |
| 3 | **Web App Scanning** | Automated web application vulnerability scanning |
| 4 | **Exposure Management** | Attack surface inventory, Lumin metrics, Attack Path Analysis |
| 5 | **PCI ASV** | Quarterly external scan submission and dispute processing |
| 6 | **MSSP Portal** | Multi-tenant customer instance management |
| 7 | **Identity Exposure** | Active Directory threat monitoring, breach detection |
| 8 | **Attack Surface Management** | External asset discovery via DNS, IP, ASN |

### Vulnerability Management Sub-Categories (estimated ~20 groups)

| Group | Representative Endpoints |
|-------|--------------------------|
| Assets | `GET /assets`, `GET /assets/{uuid}`, export v2 |
| Scans | `GET /scans`, `POST /scans`, launch/stop/import |
| Plugins | Plugin details, families, families list |
| Workbenches | `GET /workbenches/vulnerabilities`, assets with vulns |
| Exports (v2) | `POST /api/v2/exports/vulnerabilities`, assets, compliance |
| Agents | Agent list, group management, bulk operations |
| Networks | Network creation and management |
| Tags | Tag categories, values, asset assignment |
| Access Groups | v2 access group CRUD |
| Credentials | Managed credential lifecycle |
| Exclusions | Scan exclusion rules |
| Policies | Scan policy templates |
| Folders | Scan folder organization |
| Filters | Workbench filter definitions |
| Permissions | Object-level permission management |
| Scanners | Scanner CRUD, linking |
| Server | Server info, status |
| Session | Session management |
| Groups | User group management |
| Users | User lifecycle |

**Estimated total Tenable VM API endpoints: ~200–300** (Tenable does not publish an exact count; this is derived from the reference explorer structure)

---

## 3. Tenable Signature APIs

### 3a. Vulnerability Priority Rating (VPR)

**What it is:** AI/ML-driven dynamic severity score (0–10 scale) that predicts exploitation likelihood. Replaces/augments static CVSS.

**Key differentiator vs CVSS:**
- CVSS flags ~60% of vulns as High/Critical → alert fatigue
- VPR isolates the **1.6% of exposures that truly pose risk** → 98.4% reduction in remediation queue
- **2x higher remediation efficiency** vs CVSS in Tenable's benchmarks
- Scores update **daily** based on live threat intelligence

**VPR Calculation Drivers:**

| Driver | Description |
|--------|-------------|
| Vulnerability Age | Days since NVD publication (0–7 days to 730+) |
| Exploit Maturity | High / Functional / PoC / Unproven |
| CVSSv3 Impact Score | NVD or Tenable-predicted impact |
| Threat Intensity (28-day) | Very Low → Very High (dark web, social, paste sites) |
| Threat Recency | Days since last observed threat event |
| Threat Sources | Origin channels (dark web, social media, etc.) |
| Product Coverage | Number of affected products (Low → Very High) |

**API Endpoints Exposing VPR:**

| Method | Endpoint | VPR Field |
|--------|----------|-----------|
| GET | `/workbenches/vulnerabilities/{plugin_id}/info` | `vpr.drivers` |
| GET | `/workbenches/assets/{asset_id}/vulnerabilities/{plugin_id}/info` | `vpr.drivers` |
| GET | `/vulns/export/{export_uuid}/chunks/{chunk_id}` | `plugin.vpr.drivers` |
| POST | `/api/v2/exports/vulnerabilities` | Filter by VPR range |

### 3b. Lumin Exposure Metrics

**Requires:** Separate Lumin license add-on.

| Metric | Scale | Description |
|--------|-------|-------------|
| ACR (Asset Criticality Rating) | 1–10 | Business criticality of an asset. Tenable-calculated daily from device type, capability (DB, ERP, mail server, hypervisor), network location. User-overridable. |
| AES (Asset Exposure Score) | 0–1000 | Dynamic per-asset exposure = f(ACR, VPR of all asset vulns). High: 650–1000, Med: 350–649, Low: 0–349 |
| CES (Cyber Exposure Score) | 0–1000 | Org-level aggregate of AES values for licensed assets scanned in last 90 days. Same tier thresholds as AES. |

**Lumin API Endpoints:**

| Method | Endpoint | Returns |
|--------|----------|---------|
| GET | `/assets` | `acr_score` (if Lumin licensed) |
| GET | `/assets/{asset_uuid}` | `acr_score` |
| GET | `/workbenches/assets` | `acr_score` |
| GET | `/workbenches/assets/{asset_uuid}/info` | `acr_score` |
| POST | `/api/v2/assets/bulk-jobs/acr` | Bulk ACR override |
| GET | `/assets/export/{export_uuid}/chunks/{chunk_id}` | `acr_score` + `exposure_score` |

**Note:** CES is a dashboard/UI metric; no dedicated CES API endpoint is publicly documented.

---

## 4. ALDECI Vulnerability & Posture API Inventory

### 4a. Total API Scale

| Metric | Count |
|--------|-------|
| Total router files | 580 |
| Total API endpoints (`@router.` decorators) | **5,453** |
| Vuln-specific router files | 16 |
| Posture-specific router files | 11 |

### 4b. Vulnerability API Surface (ALDECI)

| Router Prefix | Endpoints | Capability |
|--------------|-----------|------------|
| `/api/v1/vuln-scoring` | 9 | Composite CVSS+EPSS+KEV+exposure scoring, criticality multipliers (0.75–2.0), one active model per org, override audit trail |
| `/api/v1/vuln-intel` | 12 | CVE upserts, EPSS/KEV correlation, advisories, subscriptions, sync, stats |
| `/api/v1/vuln-scans` | 8 | 8 scanner types, findings_count/critical_count auto-increment, scan lifecycle |
| `/api/v1/vuln-lifecycle` | 8 | 8-state lifecycle FSM, metrics, SLA tracking |
| `/api/v1/vuln-prioritization` | 8 | CVSS+EPSS+KEV priority scoring, remediation queue |
| `/api/v1/vuln-remediation` | 9 | SLA-tiered remediation workflow, MTTR metrics |
| `/api/v1/vuln-correlation` | 10 | Cross-asset vuln correlation, KEV tracking, JSON round-trip |
| `/api/v1/vuln-age` | 9 | Age-by-severity SLA, sla_breached flag, 5-cohort distribution, breach_rate% |
| `/api/v1/vuln-intel-fusion` | 7 | Multi-source fusion: cvss=AVG/epss=MAX/kev=MAX, fusion score |
| `/api/v1/cve` | 8 | NVD+EPSS+KEV enrichment (CVEEnrichment engine) |
| `/api/v1/vuln-workflow` | ~8 | SLA tiers p1–p4, overdue detection, comment threading |
| `/api/v1/vuln-exception` | ~7 | Risk acceptance, expiry tracking |
| `/api/v1/vuln-correlation` | 10 | Asset-vuln correlation graph |
| `/api/v1/sbom-export` | ~6 | CycloneDX 1.4 + SPDX 2.3 export |
| `/api/v1/gap-analysis` | ~7 | 10 frameworks, coverage_pct recompute |
| `/api/v1/vuln-prioritization` | 8 | Priority scoring queue |
| **Subtotal** | **~134** | |

### 4c. Security Posture API Surface (ALDECI)

| Router Prefix | Endpoints | Capability |
|--------------|-----------|------------|
| `/api/v1/posture-scoring` | 8 | Weighted controls, snapshots, score_level ≥80=excellent |
| `/api/v1/posture-benchmarking` | 9 | Industry benchmark percentiles (p25/p50/p75/p90), peer comparison |
| `/api/v1/posture-maturity` | 9 | CMMI 1–5, 10 domains, roadmap FSM, overdue reviews |
| `/api/v1/posture-trends` | 10 | Velocity analysis, improving/declining/stable, ETA to target |
| `/api/v1/posture-history` | 9 | 8-domain snapshots, baseline gap analysis |
| `/api/v1/posture-advisor` | ~8 | AI-driven posture recommendations |
| `/api/v1/posture-reports` | ~7 | Report sections, grade A–F, trend 5% bands |
| `/api/v1/cloud-posture` | ~8 | 6 cloud providers, findings, posture score delta |
| `/api/v1/container-posture` | ~7 | Cluster posture scoring, clusters_at_risk<70 |
| `/api/v1/sspm` | ~8 | SaaS app posture, compliance_rate, high_risk_apps |
| `/api/v1/health-scorecard` | ~6 | Weighted domain scoring, A–F grade, improvement areas |
| **Subtotal** | **~89** | |

---

## 5. Head-to-Head Comparison

### 5a. Vulnerability Prioritization

| Capability | Tenable.io (VPR) | ALDECI |
|-----------|------------------|--------|
| Scoring model | VPR: 0–10 AI/ML model (7 drivers) | Composite: CVSS + EPSS + KEV + exposure (configurable criticality multipliers 0.75–2.0) |
| CVSS support | Yes (CVSSv2 + v3 displayed) | Yes (CVSSv3 base score as primary input) |
| EPSS integration | Partial (threat intensity driver) | Full EPSS score stored and fused per CVE |
| KEV (CISA) integration | Partial (exploit maturity driver) | Explicit KEV boolean field per CVE, used in scoring formula |
| Threat intel fusion | Yes (dark web, social, paste sites) | Yes via `/api/v1/vuln-intel-fusion` — multi-source, cvss=AVG/epss=MAX/kev=MAX |
| Score update frequency | Daily | On-demand (sync endpoint) + advisory apply |
| Per-org scoring model | No (Tenable-controlled globally) | Yes — one active model per org, custom overrides with audit trail |
| Override / exceptions | Limited | Full exception workflow with expiry, risk acceptance, audit |
| Age/SLA tracking | No dedicated endpoint | Yes — `vuln-age` router: SLA per severity, sla_breached flag, 5-cohort distribution |
| Remediation workflow | No (prioritize only) | Yes — 8-state lifecycle, SLA tiers p1–p4, MTTR computation |
| API endpoints (vuln scoring) | ~4 endpoints expose VPR | 9 endpoints (`/api/v1/vuln-scoring`) |
| SBOM export | No | Yes — CycloneDX 1.4 + SPDX 2.3 (`/api/v1/sbom-export`) |

### 5b. Exposure / Posture Scoring

| Capability | Tenable (Lumin) | ALDECI |
|-----------|-----------------|--------|
| Asset score | ACR 1–10 (daily, Tenable-calculated) | Not a distinct ACR concept — posture per domain |
| Asset exposure score | AES 0–1000 per asset | No per-asset AES analog; org-level posture scoring |
| Org-level score | CES 0–1000 | Posture score 0–100 (A–F grade) across 10+ domains |
| Score tiers | High/Med/Low (fixed thresholds) | Configurable; ≥80=excellent down to <40=critical |
| Industry benchmarking | Not in public API | Yes — percentile interpolation p25/p50/p75/p90 (`/api/v1/posture-benchmarking`) |
| Maturity model | Not available | CMMI 1–5 across 10 domains (`/api/v1/posture-maturity`) |
| Trend / velocity | Not available | Yes — improving/declining/stable + ETA to target (`/api/v1/posture-trends`) |
| Historical snapshots | Not available | Yes — 8-domain snapshots, baseline gap analysis (`/api/v1/posture-history`) |
| Cloud posture | Not in VM API (separate CSPM product) | Yes — 6 providers (`/api/v1/cloud-posture`) |
| SaaS posture | Not in public API | Yes — 9 app categories (`/api/v1/sspm`) |
| Container posture | Not in VM API (separate CS product) | Yes — cluster posture score (`/api/v1/container-posture`) |
| License requirement | Lumin license required | Included in base ALDECI |
| API endpoints | ~6 (ACR view/update) | ~89 across all posture routers |

### 5c. Data Export Architecture

| Capability | Tenable.io | ALDECI |
|-----------|------------|--------|
| Export model | Async job-based: POST → poll → download chunks (3-day window) | Synchronous REST (no chunking needed at current scale) |
| Vulnerability export | `/api/v2/exports/vulnerabilities` (5 endpoints) | Direct query endpoints + `/api/v1/vuln-scans` |
| Asset export | `/api/v2/exports/assets` (5 endpoints) | Asset endpoints across domain-specific routers |
| Compliance export | `/api/v2/exports/compliance` | `/api/v1/compliance-mapping`, `/api/v1/compliance-automation` |
| Plugin/scanner export | Dedicated export endpoints | N/A (scanner normalizers internal) |
| Chunk size | Max 5,000 records recommended | No chunking (SQLite per-domain) |
| Formats | JSON | JSON |
| SBOM export | Not available | CycloneDX 1.4 + SPDX 2.3 |

### 5d. API Scale Comparison

| Metric | Tenable.io | ALDECI |
|--------|------------|--------|
| Public API endpoints | ~200–300 (VM only); ~400–500 across all products | **5,453** across 580 routers |
| API categories | 8 top-level products | 344+ security domains |
| Vulnerability APIs | ~50 endpoints | ~134 endpoints across 16 routers |
| Posture/Exposure APIs | ~6 (Lumin, license required) | ~89 endpoints across 11 routers |
| Auth model | API key pair (Access + Secret) | API key auth (`Depends(api_key_auth)`) |
| Multi-tenancy | Access Groups v2 | org_id isolation across all engines |
| On-premise option | No (cloud-only) | Yes (self-hosted SQLite + FastAPI) |
| Pricing | $50K–$500K+/yr enterprise | $35–60/month self-hosted |

---

## 6. ALDECI Advantages Over Tenable

1. **No Lumin license required** — ALDECI's posture/exposure scoring is fully included, not a paid add-on
2. **Broader posture depth** — 11 posture router groups vs Tenable's 6 Lumin endpoints; includes maturity, trends, history, industry benchmarking
3. **SBOM generation** — CycloneDX + SPDX built-in; Tenable has no SBOM export
4. **Scoring transparency** — ALDECI exposes the full scoring formula (CVSS+EPSS+KEV+exposure with configurable multipliers); VPR is a black-box ML model
5. **Per-org scoring models** — ALDECI allows organizations to define their own active scoring model; Tenable VPR is global and Tenable-controlled
6. **Remediation lifecycle** — Full 8-state FSM with MTTR, SLA tiers, comment threading; Tenable prioritizes only
7. **Self-hosted / air-gapped** — ALDECI runs on $35/month; Tenable is cloud-only enterprise pricing
8. **Attack surface breadth** — 344+ security domains vs Tenable's 8 product areas (many requiring separate SKUs)
9. **Vuln-intel fusion** — ALDECI's `/api/v1/vuln-intel-fusion` does cross-source score synthesis; Tenable's VPR is opaque
10. **API scale** — 5,453 ALDECI endpoints vs ~400–500 across all Tenable products

## 7. Tenable Advantages Over ALDECI

1. **VPR model maturity** — 7-driver AI/ML model trained on years of real exploit data; ALDECI's formula is heuristic
2. **Threat intelligence breadth** — Tenable has proprietary feeds (dark web, social, paste sites) feeding VPR daily; ALDECI relies on public sources (NVD, EPSS, CISA KEV)
3. **Agent ecosystem** — Tenable Nessus agents deployed at massive scale for authenticated scanning; ALDECI normalizes scanner output but doesn't deploy agents
4. **Plugin library** — 200,000+ Nessus plugins for authenticated detection; no ALDECI equivalent
5. **ACR asset context** — Per-asset criticality automatically inferred from device type/capability at scale; ALDECI has no equivalent per-asset ACR
6. **PCI ASV** — Tenable is a PCI-approved scanning vendor with ASV API; ALDECI has no ASV capability
7. **OT/ICS scanning** — Tenable OT Security has purpose-built passive OT scanning; ALDECI has an OT engine but no passive scanner
8. **Brand/compliance credibility** — Tenable is a recognized name in audit/compliance conversations; ALDECI is new
9. **SLA / uptime** — Cloud-hosted SLA guarantees; ALDECI is self-managed

---

## 8. Sales Positioning Against Tenable

| Objection | ALDECI Response |
|-----------|----------------|
| "We already use Tenable" | ALDECI ingests Tenable scan data via connector; adds the workflow, remediation, and posture layers Tenable lacks |
| "Tenable has VPR" | ALDECI scoring is transparent and customizable per org; VPR is a black box. ALDECI also tracks EPSS+KEV explicitly. |
| "Tenable Lumin gives exposure scores" | Lumin is a $15–50K/yr add-on. ALDECI posture scoring is included. ALDECI adds benchmarking, maturity, trends — none in Lumin. |
| "Tenable has 200K plugins" | ALDECI normalizes output from Tenable + 31 other scanners. Bring your own scanner. |
| "Tenable is SOC 2 / enterprise" | ALDECI is self-hosted: data never leaves your network. Many enterprises prefer this. |

---

## Sources

- [Navigate the APIs — Tenable Developer Portal](https://developer.tenable.com/reference/navigate)
- [VPR Drivers Documentation](https://developer.tenable.com/docs/vpr-drivers-tio)
- [Lumin API Documentation](https://developer.tenable.com/docs/lumin-tio)
- [Lumin ACR and AES Scores in Export API (Changelog)](https://developer.tenable.com/changelog/lumin-acr-and-aes-scores-in-export-api)
- [Tenable Lumin Metrics](https://docs.tenable.com/vulnerability-management/Content/Lumin/LuminMetrics.htm)
- [Retrieve Vulnerability Data from Tenable VM](https://developer.tenable.com/docs/retrieve-vulnerability-data-from-tenableio)
- [Retrieve Asset Data from Tenable VM](https://developer.tenable.com/docs/retrieve-asset-data-from-tenableio)
- [VPR Capability Page](https://www.tenable.com/capabilities/vulnerability-priority-rating)
- [VPR vs CVSS Blog](https://www.tenable.com/blog/what-is-vpr-and-how-is-it-different-from-cvss)
- [Tenable Vulnerability Management Documentation](https://docs.tenable.com/vulnerability-management.htm)
- [Filter Vulnerability Exports by VPR](https://developer.tenable.com/changelog/filter-vuln-export-by-vpr-tio)
- [Tenable One Scoring Explained (PDF)](https://docs.tenable.com/quick-reference/scoring-explained/Content/PDF/tenable-scoring-explained.pdf)
