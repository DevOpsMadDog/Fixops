# FixOps — UI ↔ API Contracts (boundary risk map)

> **Purpose**: pin down the interface between `suite-ui/aldeci-ui-new` and the FastAPI
> backend so one side stops silently breaking the other (the documented churn source).
> Documentation only. Claims cited; gaps marked **UNKNOWN**/**ASSUMPTION**.
> **Last updated**: 2026-06-21. Companion to `system-overview.md` and `docs/GAP_MAP.md`.

---

## 1. The core problem
There is **no enforced schema contract** between UI and API:
- The UI calls the backend through a central client (`src/lib/api.ts`, `apiFetch`), but
  response bodies are largely **untyped** (`any`-shaped) — **ASSUMPTION** pending a per-call
  audit (verify: grep `src/` for `: any`, response generics, and zod usage; the agent map
  found no generated client).
- The backend returns Python dicts assembled in routers with **no shared schema artifact**
  (no OpenAPI-derived TS types, no zod). FastAPI generates `/openapi.json` at runtime, but it
  is **not** used to generate the FE client — **UNKNOWN** if `/openapi.json` is even exported in
  builds (verify).
- ⇒ A backend that renames/reshapes a field, or a UI that assumes an old shape, breaks at
  runtime with no compile-time or CI signal. This is precisely R7 in `system-overview.md`.

### Evidence the drift is real (already observed)
- **Two readback stores for findings** (GAP_MAP #12): `POST /api/v1/scanner-ingest/upload`
  writes the `SecurityFindingsEngine` DB, but `GET /api/v1/findings` reads an **in-memory**
  store — so ingested findings can be invisible on that path. The working path is
  `GET /api/v1/security-findings/` (verified this session). *Two endpoints, two shapes, one
  concept = a contract trap.*
- **Field-name drift**: the findings readback exposes CVE identity as **`cve_id`**, not
  `rule_id` (confirmed via live readback KEYS this session). A UI assuming `rule_id` shows blanks.
- **Envelope vs bare list**: `/api/v1/analytics/findings` returns a paginated envelope
  `{items,total,limit,offset}`, but tests/older callers assumed a bare list (de-staled tick213).
- **Shape redesign without versioning**: `/api/v1/analytics/triage-funnel` was redesigned
  (`without_aldeci/with_aldeci/reduction_percentage` → `funnel/fail_distribution`) with no
  contract test — old consumers silently broke (tick213).

## 2. Target: contract-first pipeline (Phase 3)
```
Spec → API contract (OpenAPI / shared types / Zod) → backend validation
     → generated client → UI → end-to-end test
```
Adopt incrementally — **highest-risk endpoint first, not a big-bang rewrite**.

## 3. Highest-risk endpoints to pin FIRST (the contract backlog)
Ranked by customer-criticality × drift-likelihood. "Shape (known)" = observed this session;
fields not personally verified are marked UNKNOWN.

| # | Endpoint | Why high-risk | Shape (known) | Action |
|---|---|---|---|---|
| C1 | `POST /api/v1/scanner-ingest/upload` | The #1 buyer action; multipart; promotes to findings | req: file + `scanner_type` + `app_id`; resp: `{findings_count, …}` | Pin req/resp; assert `findings_count` + org scoping |
| C2 | `GET /api/v1/security-findings/` | Primary findings readback (the working store) | fields incl `cve_id, severity, cvss_score, epss_score, is_kev, org_id, correlation_key, occurrence_count, status, title` | Pin full schema; this is the canonical findings contract |
| C3 | `GET /api/v1/findings` | **Conflicts with C2** — in-memory store, may not reflect ingest | UNKNOWN | Decide: deprecate, or back it by the same engine; document which UI uses it |
| C4 | `GET /api/v1/analytics/summary` (+ dashboard) | Drives the exec/dev dashboards | numeric KPIs; honest-empty when no data (SPEC-029) | Pin numeric fields + ranges (all pct ∈ [0,100]) |
| C5 | `GET /api/v1/analytics/triage-funnel` | Already drifted once; shows the noise-reduction moat | `{funnel, fail_distribution, reduction_percentage}` (monotonic) | Pin + contract test (regressed before) |
| C6 | Council verdict (`/api/v1/brain/...` / pipeline) | The $100K moat output | `cost_usd, reasoning, raw_analyses` (SPEC-020/032) | Pin verdict schema; assert never-fabricated |
| C7 | `GET /api/v1/brain/correlations/{finding_id}` | TrustGraph enrichment; **no UI consumer yet** | `TrustGraphEnrichmentResult` (`trustgraph_integrations.py:1512`) | Pin schema *and* wire a UI consumer (GAP_MAP #1) |
| C8 | `GET /api/v1/threat-intel/feeds/status` | Just de-mocked; UI feed widgets | `feeds[].{ioc_count, health, last_updated}` (honest 0 now) | Pin; assert no fabricated counts |
| C9 | Evidence download/verify (`/api/v1/evidence/...`) | Chain-of-custody; investor/auditor facing | 404 when absent (honest), verify=honest | Pin honest-empty + signed-bundle shape |
| C10 | Auth/org headers (cross-cutting) | `X-API-Key` + org resolution affects every call | `get_org_id`: contextvar>query>header | Pin the auth/tenancy contract once; reuse |

## 4. Weak/under-validated spots (flagged)
- **Request validation**: many routers accept raw query params (e.g. former `org_id` spoofing).
  Audit for missing Pydantic bodies / unconstrained query params.
- **Pagination inconsistency**: some list endpoints return envelopes, some bare lists (C5/§1).
  Pick one convention and enforce it.
- **Error contract**: **UNKNOWN** whether errors are uniform (`{detail}` vs custom). Verify and
  pin — the UI's error handling depends on it.
- **OpenAPI completeness**: routers using bare dict returns won't have rich response schemas in
  `/openapi.json`. **UNKNOWN** coverage — verify before generating a client from it.

## 5. Recommended first move (Phase 3, non-big-bang)
1. Write **SPEC-033 — UI↔API contract baseline** (see `system-overview.md §9`).
2. Start with **C1 + C2** (the ingest→readback path): add response-schema contract tests that
   assert exact field names/types, wire them into `regression-gates.yml`.
3. Resolve **C3** (the `/findings` vs `/security-findings/` split) — the single clearest
   correctness/contract trap.
4. Only then expand to C4–C10. Each becomes a Phase-4 spec→task→implement slice with its own
   contract test before any UI rewiring.

> Phase-3 work items (expected-UI per endpoint) to be created in Multica for pickup — scope
> confirmed with founder before creation (top-risk-first vs full-boundary audit).
