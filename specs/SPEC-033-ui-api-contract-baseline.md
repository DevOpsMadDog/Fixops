# SPEC-033 — UI↔API Contract Baseline (stop the FE/BE churn)

- **Status**: IN PROGRESS — C1+C2, C4, C5, C6, C8, C9, C10 DONE (gated via `test_contract_*.py`); C3 (#9094, founder public-API decision) + C7 (#9101, UI consumer) remain
- **Owner family**: Customer-Readiness / Contracts
- **Depends on**: `docs/architecture/api-contracts.md`, `docs/GAP_MAP.md`
- **Multica**: #9093 (C1+C2), #9094 (C3), #9095 (C6), #9096 (C10), #9097 (C4), #9098 (C5), #9099 (C8), #9100 (C9), #9101 (C7)
- **Last updated**: 2026-06-21

## 1. Intent
The documented churn source is an **unpinned UI↔API interface**: responses are untyped, no
shared schema, so a backend field rename or shape change breaks the UI with zero CI signal
(`docs/architecture/api-contracts.md §1`). This spec pins the response contracts of the highest-risk
endpoints with **contract tests** — incrementally, highest-risk first, **not a big-bang rewrite**.

## 2. Scope
Per-endpoint contract tests that assert exact field names + types + key invariants, wired into the
blocking CI gate. Ordered C1→C10 (`api-contracts.md §3`). This spec's **first task = C1+C2** (the
ingest→readback path), the #1 buyer action.

## 3. Contract pinned by this task (C1 + C2)
```
C1  POST /api/v1/scanner-ingest/upload
    req : multipart file + scanner_type + app_id
    resp: 200, body has integer `findings_count` >= 1 for a real multi-finding SARIF
C2  GET /api/v1/security-findings/?org_id=<org>
    resp: 200, findings[] where each finding carries the canonical fields:
          cve_id, severity, title, org_id  (+ cvss_score, status, correlation_key, occurrence_count)
    invariants:
      - readback reflects the upload (uploaded CVE titles present)
      - CVE identity is `cve_id` (NOT `rule_id`) — the observed drift
      - org-scoped: a fresh org that uploaded nothing sees 0
```

## 4. Functional requirements (this task)
- **REQ-033-01**: a real SARIF upload returns `findings_count` (int) ≥ 1.
- **REQ-033-02**: readback findings expose `cve_id`, `severity`, `title`, `org_id` (the canonical
  contract); at least one uploaded CVE title is present on readback.
- **REQ-033-03**: tenant isolation — a fresh org's readback is empty.
- **REQ-033-04**: the contract test is a blocking step in `regression-gates.yml`.

## 5. Non-functional
- Additive test only — **no public API behavior changed** by this task (Phase-4 safe slice).
- Uses the real app via `create_app` + TestClient (no mocks).

## 6. Acceptance criteria
- **AC-033-01** (2026-06-21): `tests/test_contract_ingest_readback.py` passes (real upload →
  pinned readback shape → empty fresh org).
- **AC-033-02**: wired blocking in `regression-gates.yml`.
- **AC-033-03**: registered in `specs/INDEX.md`.

## 7. Backlog (later tasks — Multica)
C3 store split (#9094, public-API → founder review), C6 council verdict (#9095), C10 auth/tenancy
(#9096), C4 analytics summary (#9097), C5 triage-funnel (#9098), C8 threat-intel feeds (#9099),
C9 evidence (#9100), C7 brain/correlations + UI consumer (#9101).
