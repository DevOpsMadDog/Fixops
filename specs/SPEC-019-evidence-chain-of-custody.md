# SPEC-019 — Evidence Chain-of-Custody

- **Status**: BACKFILL (documents shipped code; reconciled to source 2026-06-02)
- **Owner family**: Evidence / Forensics / ATO
- **Routers**: `evidence_chain_router.py` (prefix `/api/v1/evidence-chain`)
- **Engines**: `core/evidence_chain_engine.py` (`EvidenceChainEngine`)
- **Stores**: SQLite `evidence_items` + cases + custody tables (org-scoped)
- **Related**: `core/evidence_chain.py` (HMAC `EvidenceChain`, internal append-only log used by closed-loop signed decisions — NOT this HTTP router); SPEC-006b (crypto/immutable audit), SPEC-016 (closed-loop signed evidence).
- **Last updated**: 2026-06-02

## 1. Intent (the why)
A SCIF customer's ATO/forensics process needs a defensible **chain of custody** for evidence
artifacts: who collected what, when, every custody transfer, a tamper-evident seal, and an
integrity check that actually proves the artifact hasn't changed. This API provides case
management, evidence registration, custody transfer, sealing, and **real content-integrity
verification** (re-hash, not trust-the-stored-hash).

**Code-truth (2026-06-02):** real engine, 0 stub markers, SQLite-backed. `verify_integrity` was
hardened this session to RECOMPUTE sha256/md5 from the artifact at `storage_location` and compare
to the recorded hash (SPEC-019 REQ-019-05) — previously it returned `verified=True` from a merely
non-empty stored hash (a fake result). All endpoints `api_key_auth` + org-scoped.

## 2. Scope — endpoints (as implemented)
| Method | Path | Purpose | Auth | Tenant |
|--------|------|---------|------|--------|
| GET  | /api/v1/evidence-chain/ | summary/stats | api_key_auth | org |
| GET/POST | /api/v1/evidence-chain/cases | list / create case | api_key_auth | org |
| GET  | /api/v1/evidence-chain/cases/{case_id} | get case | api_key_auth | org |
| POST | /api/v1/evidence-chain/cases/{case_id}/close | close case | api_key_auth | org |
| GET/POST | /api/v1/evidence-chain/cases/{case_id}/evidence | list / add evidence | api_key_auth | org |
| GET  | /api/v1/evidence-chain/evidence/{id}/custody | custody chain | api_key_auth | org |
| POST | /api/v1/evidence-chain/evidence/{id}/custody | transfer custody | api_key_auth | org |
| POST | /api/v1/evidence-chain/evidence/{id}/seal | seal evidence | api_key_auth | org |
| GET  | /api/v1/evidence-chain/evidence/{id}/verify | verify integrity (REAL re-hash) | api_key_auth | org |
| POST | /api/v1/evidence-chain/export-coverage | framework export-coverage check | api_key_auth | org |
| GET  | /api/v1/evidence-chain/verifications | list verifications | api_key_auth | org |

Out of scope: the internal HMAC `EvidenceChain` append log (closed-loop signed decisions, SPEC-016) — not exposed here.

## 3. Data contracts
```
POST /cases/{id}/evidence  {evidence_type, filename, hash_sha256, hash_md5?, storage_location, size_bytes, collected_by, ...}
GET  /evidence/{id}/verify → 200 {
  "verified": bool, "hash_match": bool, "hash_recomputed": bool,
  "content_integrity": "verified" | "tampered" | "unverified_no_artifact",
  "chain_intact": bool, "sealed": bool, "evidence_id": "..."
}
```

## 4. Functional requirements (reconciled to code)
- **REQ-019-01**: cases + evidence + custody are CRUD, org-scoped (all queries filter `org_id`); cross-org → not visible.
- **REQ-019-02**: `transfer_custody` appends an immutable custody event (who→who, when, reason); custody chain is queryable.
- **REQ-019-03**: `seal_evidence` marks an item sealed with a `sealed_at` timestamp; sealed items are tamper-flagged on change.
- **REQ-019-04**: `verify_integrity` checks chain_intact = custody timestamps monotonically non-decreasing (≥ the collection event).
- **REQ-019-05** *(hardened 2026-06-02)*: `verify_integrity` RECOMPUTES sha256/md5 from the artifact at `storage_location`
  when locally readable and compares to the recorded hash — REAL content integrity. Tampered content → `verified=False`,
  `content_integrity="tampered"`. When the artifact is not retrievable → `content_integrity="unverified_no_artifact"`
  (NEVER a fabricated `verified=True` from a non-empty stored hash).
- **REQ-019-06**: every endpoint `api_key_auth`; org resolved per request (no cross-tenant evidence access).

## 5. Non-functional requirements
- Tenancy: every SQL query predicated on `org_id`; cross-org → empty/404.
- Honesty: integrity never overstated — content is "verified" only after a real recompute-and-match.
- Durability: SQLite WAL; custody + seal events are append-style (no destructive edits to recorded events).

## 6. Acceptance criteria (executable — locked in tests/test_evidence_integrity_rehash.py)
- **AC-019-01**: matching artifact → `content_integrity="verified"`, `hash_recomputed=True`, `verified=True`.
- **AC-019-02**: tampered artifact (content changed after record) → `content_integrity="tampered"`, `verified=False`.
- **AC-019-03**: missing/unreadable artifact → `content_integrity="unverified_no_artifact"`, `hash_recomputed=False` (no fake verified).
- **AC-019-04**: org-A cannot read org-B's cases/evidence (org-scoped).
- **AC-019-05**: `create_app()` boots with the router mounted; 13-file Beast smoke stays 756.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-02 | Author (backfill) | Documented as-built; recorded the REQ-019-05 integrity hardening shipped this session (real re-hash, tamper→verified=False). |
| — | SCIF-Accreditor (pending) | Confirm sealed evidence cannot be silently edited; export-coverage maps to a real framework control set. |
| — | Red-Team (pending) | Attack: spoof storage_location to a path the attacker controls to force a false "verified"; mitigation = trust only operator-managed storage roots. |

## 8. Implementation notes
Backfill of shipped code + the 2026-06-02 `verify_integrity` real-rehash hardening (commit 869ebb4a),
regression-locked by `tests/test_evidence_integrity_rehash.py` (commit 6c09e227). Pending: full debate +
org-isolation AC tests; consider a storage-root allowlist for REQ-019-05 (Red-Team note).
