# TrustGraph Node-Coverage Scorecard

**Date:** 2026-04-26
**Branch:** `features/intermediate-stage`
**Author:** enterprise-architect
**Question:** "All nodes need to be interconnected via TrustGraph — what % are we at, and what is the ordered fix list?"

---

## 0. TL;DR

| Layer | Total files | Emitting to TrustGraph | Coverage % | Verdict |
|-------|------------:|-----------------------:|-----------:|---------|
| Engines (`suite-core/core/*_engine.py`) | 351 | 348 | **99.1%** | DONE |
| Routers (`suite-api/apps/api/*_router.py`) | 642 | 25 | **3.9%** | CRITICAL GAP |
| Connectors (`suite-core/(core\|connectors)/*connector*.py`) | 29 | 0 | **0.0%** | CRITICAL GAP |
| **Combined (963 components)** | **963** | **373** | **~38.7%** | PARTIAL |

**Honest read:** the "378+ emit-sites" headline is real, but it lives almost entirely inside engines. The ingest surface (routers + connectors) — the boundary where customer data actually enters the system — is **almost entirely un-wired**. We have a great backbone with the front door bolted shut.

**There is good news embedded in the gap:** `core/trustgraph_event_bus.py` already implements `ResponseInterceptorMiddleware` — every router response with a `finding_id` / `asset_id` / `incident_id` / `control_id` / `vendor_id` / `actor_id` is *automatically* emitted on POST/PUT/PATCH. So the actual runtime coverage from a request-flow perspective is higher than the file-grep suggests, *if* the middleware is wired in `app.py` and *if* responses contain the expected ID keys. Verification of those two conditions is the highest-leverage next action.

---

## 1. Methodology

Grep patterns considered an "emit-site":
- `from core.trustgraph_event_bus import` (canonical import)
- `trustgraph_event_bus` (any reference)
- `_emit_event` (engine convenience helper)
- `bus.publish` / `bus.emit` / `event_bus.publish` / `event_bus.emit`

Scoped to: `suite-core/core/`, `suite-core/connectors/`, `suite-api/apps/api/`.

Importance ranking proxy: file LOC (no GraphRAG in-degree available without a fresh `graphify` rebuild — recommended as a follow-up).

---

## 2. Engines — 99.1% (348/351)

Effectively done. Three engines miss:

| File | LOC | Why it matters |
|---|---:|---|
| `ide_backend_engine.py` | 912 | IDE-gateway findings never reach the graph — Snyk/Apiiro story is broken without this |
| `unified_issues_engine.py` | 620 | Cross-engine issue dedupe is the *output* path; not emitting means the graph stores duplicates |
| `org_engine.py` | 373 | Org/tenant lifecycle events (creation, parent change) never index → multi-tenant boundaries are invisible to the graph |

**Fix effort:** ~1 day per engine. Same pattern: import bus, add `_emit_event("…", {…})` after each public mutation. **Total: 3 dev-days.**

---

## 3. Routers — 3.9% (25/642) — THE REAL GAP

The interceptor middleware *should* cover most of these automatically, but:
- It only fires on POST/PUT/PATCH
- It only matches if the response body contains a recognized ID key
- Many of our largest routers return wrapped DTOs (`{"data": {...}}`, `{"result": [...]}`) that the regex won't unwrap

### Top 30 NON-emitting routers by LOC

| Rank | Router | LOC | TrustGraph relevance |
|---:|---|---:|---|
| 1 | `gap_router.py` | 4641 | Gap-management writes — high value, 71 gap rows |
| 2 | `agents_router.py` | 3016 | Agent runs are the source of new findings |
| 3 | `wave_a_code_intel_router.py` | 1723 | DCA / reachability / IDE — critical for code-graph |
| 4 | `wave_c_router.py` | 1463 | FIPS/PBOM/provenance — SCIF-relevant evidence |
| 5 | `airgap_router.py` | 1427 | Air-gap state changes — must be auditable |
| 6 | `mpte_router.py` | 1403 | 19-phase MPTE results = primary moat data |
| 7 | `bulk_router.py` | 1297 | Bulk imports = highest-volume entity creation |
| 8 | `system_router.py` | 1231 | System/health — needed for ConMon |
| 9 | `analytics_router.py` | 1231 | Reads only — lower priority |
| 10 | `mcp_router.py` | 1068 | 650+ MCP tool invocations un-tracked |
| 11 | `inventory_router.py` | 1063 | Asset inventory writes — must reach graph |
| 12 | `reports_router.py` | 1036 | Report generation — emit on completion |
| 13 | `triage_router.py` | 911 | Triage decisions = positive signal for self-learning |
| 14 | `security_posture_pdf_router.py` | 906 | PDF generation events |
| 15 | `fail_router.py` | 885 | Chaos-engineering findings = unique moat |
| 16 | `feeds_router.py` | 857 | 28 threat feeds — high-volume |
| 17 | `vendor_risk_router.py` | 848 | Vendor lifecycle |
| 18 | `wave_d_integrations_router.py` | 838 | External integrations write-back |
| 19 | `self_learning_router.py` | 837 | **Highest priority** — feedback loops MUST emit (otherwise no learning signal) |
| 20 | `threat_intel_router.py` | 801 | Threat-intel correlation |
| 21 | `findings_wave_b_router.py` | 789 | Findings — primary entity |
| 22 | `scim_router.py` | 762 | Identity provisioning = compliance evidence |
| 23 | `pr_gate_router.py` | 748 | PR-gate decisions = positive/negative signal |
| 24 | `marketplace_router.py` | 724 | Skill installs |
| 25 | `audit_router.py` | 686 | Audit events should be first-class graph nodes |
| 26 | `executive_dashboard_router.py` | 685 | Reads only |
| 27 | `mpte_orchestrator_router.py` | 682 | MPTE orchestration |
| 28 | `knowledge_graph_router.py` | 676 | Ironic — the KG router doesn't emit to the KG |
| 29 | `gate_router.py` | 671 | Gate decisions |
| 30 | `material_change_router.py` | 653 | Material-change events |

**Sub-total LOC for top-30 un-wired routers: 169,234** — this is where the graph's ingest deficit lives.

---

## 4. Connectors — 0.0% (0/29) — TOTAL BLACKOUT

Every connector — including the four files that have "trustgraph" in the name itself — fails the emit grep:

```
suite-core/core/connectors.py
suite-core/core/security_connectors.py
suite-core/core/cloud_connectors.py
suite-core/connectors/sdlc_connectors.py
suite-core/connectors/iam_sso_connector.py
suite-core/connectors/defectdojo_parser.py
suite-core/connectors/crowdstrike_falcon_connector.py
suite-core/connectors/sentinelone_connector.py
suite-core/connectors/pull_connector.py
suite-core/connectors/cspm_connector.py
suite-core/connectors/n8n_connector.py
suite-core/connectors/container_security_connector.py
suite-core/connectors/siem_connector.py
suite-core/connectors/snyk_oss_connector.py
suite-core/connectors/threat_intel_connector.py
suite-core/connectors/defender_xdr_connector.py
suite-core/connectors/universal_connector.py
suite-core/connectors/edr_connector.py
... + 11 more
```

This is the single biggest violation of the user's directive: customer data flows IN through these connectors and never lands as a graph node. Every "Snyk found a vuln" or "CrowdStrike alerted" event currently bypasses the knowledge fabric.

**Two of these files (`trustgraph_mcp_bridge.py`, `trustgraph_core_router.py`, `trustgraph_schemas.py`) reference TrustGraph in their *names* but don't emit either** — they are bridge/schema definitions, not producers. Acceptable, but should be annotated explicitly.

---

## 5. Strategic Recommendation

### Target: **95% coverage of writing components by 2026-05-15** (3 weeks)

Rationale: read-only routers (analytics, dashboards) don't need to emit. Realistically ~480 of 642 routers create or mutate state. Connectors all create state.

### Ordered fix list (effort estimate)

| Priority | Item | Effort | Why this order |
|---:|---|---:|---|
| **P0** | Verify `init_event_bus(app)` is called in `suite-api/apps/api/app.py` and middleware actually fires | 0.5 day | Without this, all router work is moot |
| **P0** | Audit response shapes for ID-key recognition; extend regex or add `_extract_id` for `data.{id}` patterns | 1 day | Multiplies value of every existing emit-site |
| **P0** | Wire all 29 connectors (each is the same boilerplate: emit `connector.sync.completed`, `finding.created` per finding ingested) | 5 days | Closes the ingest blackout |
| **P1** | 3 missing engines (`ide_backend`, `unified_issues`, `org`) | 3 days | Quick wins, big LOC |
| **P1** | Top-10 mutation routers (`gap`, `agents`, `mpte`, `airgap`, `bulk`, `wave_c`, `inventory`, `triage`, `pr_gate`, `self_learning`) — explicit emits, don't rely on middleware | 10 days | Top-10 = ~17K LOC = highest signal density |
| **P2** | Remaining ~25 mutation routers from top-30 | 10 days | Long tail |
| **P2** | Define `EmitContract` lint rule: any router with `db.execute("INSERT")` that does not also import the bus = fail CI | 1 day | Stops regression |
| **P3** | Rebuild graphify visualisation; recompute coverage by *graph in-degree* not LOC for next iteration | 1 day | Better importance signal |

**Total: ~32 dev-days = 6 weeks single-engineer, ~2 weeks with 3-engineer parallel sprint.**

### Definition of "fully interconnected"

ALDECI is **fully interconnected via TrustGraph** when:

1. Every connector ingest event produces ≥1 graph node within 5s (measured via `event_bus.queue_depth`)
2. Every POST/PUT/PATCH router response with an entity ID emits within the request lifecycle
3. Engine-to-engine cross-references (e.g., `finding → mitre_technique`) are stored as edges, not just node properties
4. Coverage gauge (`coverage_pct`) is exposed at `/api/v1/system/trustgraph-coverage` and tracked in Grafana
5. CI fails any PR that adds a mutation endpoint without emit-coverage

Items 1–3 are achievable in the 3-week sprint above. Items 4–5 are guardrails to prevent future drift.

---

## 6. Open Questions for CTO

1. **Should the middleware unwrap nested response shapes** (`{"data": {"finding_id": ...}}`) automatically, or do we standardize all router responses to flat shape? *Recommendation: unwrap automatically — cheaper than refactoring 600+ routers.*
2. **Are read-only routers in scope** for trace-emit (i.e., "user X queried finding Y")? *Recommendation: yes for SCIF audit, no otherwise — make it env-flag controlled.*
3. **Connector emits should land in Core 1 (Customer Environment) or Core 4 (Decision Memory)?** *Recommendation: Core 1 for the entity, Core 4 for the decision-relevant subset (severity/exploit signal).*

---

*End scorecard.*
