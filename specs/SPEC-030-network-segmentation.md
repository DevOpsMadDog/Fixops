# SPEC-030 — Network Segmentation Analyzer

- **Status**: BACKFILL (documents existing engine; honest-empty invariant test added)
- **Owner family**: Network / CTEM / Customer-Readiness
- **Routers**: `suite-api/apps/api/network_analyzer_router.py` (`/api/v1/network/*`)
- **Engines**: `suite-core/core/network_analyzer.py` (`NetworkAnalyzer`)
- **Stores**: `data/network_analyzer.db` (SQLite: `zones`, `flows`, `violations`)
- **Depends on**: SPEC-027 (auth); CLAUDE.md NO-MOCKS / ingest-first invariant
- **Last updated**: 2026-06-03
- **Multica**: n/a (board offline — docker down)

## 1. Intent (the why)
Network micro-segmentation analysis: model trust zones (DMZ/internal/external/restricted/
management), record observed flows, and flag segmentation violations + lateral-movement paths
against a zone-trust policy matrix. Must follow the ingest-first rule: a fresh deployment that has
ingested no zones/flows reads **honest-empty** (zeros / `[]`), never fabricated or seeded demo data.

## 2. Scope — endpoints (network_analyzer_router)
- `POST /api/v1/network/zones` · `GET /zones` · `GET /zones/{zone_id}` — zone CRUD/read.
- `POST /api/v1/network/flows` · `GET /flows` — flow record/read.
- `GET /analysis/segmentation` · `POST /analysis/detect-violations` · `GET /analysis/zone-matrix`
  · `GET /analysis/lateral-movement` · `GET /analysis/segmentation-score` — analysis.
- `GET /stats` — aggregate counts (zones/flows/violations, avg risk, by-type/by-severity).

(Sibling `/api/v1/network/*` paths — dns/firewall/tls/zerotrust/topology — are served by other
routers and out of scope for this spec.)

## 3. Zone-trust policy matrix (source of truth: network_analyzer.py `_ZONE_POLICY`)
Allowed/denied directed pairs, e.g. external→dmz allowed; external→internal/restricted/management
forbidden; dmz→internal allowed; internal→restricted/management forbidden; restricted→* forbidden;
management→internal/dmz allowed, management→external forbidden. Violations are derived from observed
flows that contradict this matrix.

## 4. Contracts
```
fresh deploy (no zones/flows ingested) → GET /stats = {zone_count:0, flow_count:0,
   violation_count:0, avg_risk_score:0.0, zones_by_type:{}, violations_by_severity:{}}
GET /zones, /flows on fresh deploy → []
ingested → real counts derived from zones/flows tables + the policy matrix
```

## 5. Functional requirements
- **REQ-030-01**: `_init_tables()` creates schema only — NO demo/sample rows seeded on init.
- **REQ-030-02**: `get_network_stats()` / `list_zones()` / flow listings derive purely from ingested
  rows; an empty store yields all-zeros / `[]`.
- **REQ-030-03**: segmentation violations are computed from the `_ZONE_POLICY` matrix, not fabricated.

## 6. Non-functional requirements
- `create_app()` boots; engine import clean; Beast smoke green.

## 7. Acceptance criteria
- **AC-030-01** (verified 2026-06-03): a fresh-db `NetworkAnalyzer` returns
  `get_network_stats()` all-zeros and `list_zones()`/flows empty — enforced by
  `tests/test_network_analyzer_honest_empty.py`.
- **AC-030-02**: registered in `specs/INDEX.md`.

## 8. Known limitation (founder-gated)
The engine + tables are **single-tenant** — `zones`/`flows`/`violations` carry no `org_id` column,
and `network_analyzer_router` handlers take no `org_id`. On a shared multi-tenant deployment all orgs
share one zone/flow store (no cross-tenant isolation). Customer-facing behaviour is still correct for
the common single-deployment case (fresh = honest-empty, verified). True per-org isolation needs a
schema migration (add `org_id`) + ingestion plumbing — same class as SPEC-029's `/metrics/sla`
finding. Deferred to a founder-prioritised tenancy epic; do NOT fake org scoping at the read layer.

## 9. Debate log
| Date | Mode | Verdict |
|------|------|---------|
| 2026-06-03 | Backfill + live verify | Probe showed identical /stats for 2 fresh orgs + default → traced to local stale test data, NOT a code bug: `_init_tables` does no auto-seed, fresh-db deploy returns all-zeros (verified). Single-tenant schema gap recorded as founder-gated. |
