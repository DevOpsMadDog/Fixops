# SPEC-022 — Threat Intelligence Layer (Feeds + Actors + IOC Enrichment)

- **Status**: BACKFILL
- **Owner family**: Threat Intelligence
- **Routers**: `suite-api/apps/api/threat_intel_router.py` (prefix `/api/v1/threat-intel`), `suite-core/api/feeds_router.py` + the feed-manager/registry/offline/aggregator routers (prefix `/api/v1/feeds`), `suite-api/apps/api/ioc_enrichment_router.py` (prefix `/api/v1/ioc-enrichment`)
- **Engines**: `suite-feeds/*` (feed aggregator/connectors — NVD, CISA-KEV, EPSS, Exploit-DB, MITRE ATT&CK + 28+ sources), `core/ioc_enrichment_engine` (IOC store + enrichment + watchlist), threat-actor store
- **Stores**: per-source feed caches (SQLite), IOC SQLite (iocs / enrichment / watchlist), org-scoped
- **Depends on**: SPEC-005 (air-gap — feeds must support offline/cached operation), SPEC-001/005b (correlate TI into TrustGraph + attack-paths)
- **Last updated**: 2026-06-03

## 1. Intent (the why)
The intelligence layer is **ingest-first**: it serves real CVE/EPSS/KEV/actor/IOC data
from cached feeds and ingested indicators, and — critically for a SCIF buyer — returns an
**honest empty** state (`count:0`, `iocs:[]`, zeroed stats) when a source is unrefreshed or
air-gapped, never a fabricated score or invented indicator. It powers exploitability
prioritisation (EPSS/KEV), actor attribution, and IOC watchlisting/enrichment, and feeds the
Brain Pipeline + TrustGraph correlation. See memory: intelligence-layer ingest-first.

## 2. Scope — endpoints (live-verified subset)
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | /api/v1/threat-intel/actors | threat-actor profiles (id, aliases, ttps, origin_country, motivation, associated_campaigns) | api_key | yes |
| GET | /api/v1/threat-intel/cves/recent | recently-cached CVEs (EPSS-enriched) | api_key | yes |
| GET | /api/v1/threat-intel/iocs | IOC list `{total, iocs[], offset, limit}` | api_key | yes |
| GET | /api/v1/threat-intel/kev | CISA KEV catalog (cached) | api_key | yes |
| GET | /api/v1/threat-intel/feeds/summary | aggregate feed/IOC summary (real route; was mis-documented as `/threat-intel/summary`, which has no implementation or UI consumer) | api_key | yes |
| GET | /api/v1/feeds/status | feed-manager health + total_feeds | api_key | n/a |
| GET | /api/v1/feeds/nvd/recent | recent NVD CVEs `{cves[], count, severity_filter}` | api_key | yes |
| GET | /api/v1/ioc-enrichment/ · /stats | IOC stats `{total, by_type, by_severity, enriched_count, watchlist_count}` | api_key | yes |
| GET·POST | /api/v1/ioc-enrichment/iocs | list / add IOCs | api_key | yes |
| POST | /api/v1/ioc-enrichment/iocs/{id}/enrich | enrich one IOC | api_key | yes |
| GET·POST | /api/v1/ioc-enrichment/watchlist/{name} | watchlist read / add | api_key | yes |
| POST | /api/v1/ioc-enrichment/bulk-import | bulk IOC import | api_key | yes |

Note: `/api/v1/feeds` mounts 58 routes across several feed routers (feed-manager, registry,
offline, aggregator) covering 28+ sources; per-source endpoints are documented in their own
routers. Out of scope here: enumerating every per-source feed path; live external fetching
(governed by SPEC-005 air-gap — feeds operate from cache when offline); the UI (must follow
NO-MOCKS and consume these endpoints).

## 3. Data contracts (honest-empty is a first-class state)
```
GET /api/v1/threat-intel/iocs?org_id=O      → 200 {"total":N,"iocs":[...],"offset":0,"limit":100}   (empty: total:0, iocs:[])
GET /api/v1/feeds/nvd/recent?org_id=O        → 200 {"cves":[...],"count":N,"severity_filter":null}   (unrefreshed: count:0, cves:[])
GET /api/v1/feeds/status?org_id=O            → 200 {"status":"healthy","engine":"feed-manager","total_feeds":N}
GET /api/v1/ioc-enrichment/stats?org_id=O    → 200 {"total":N,"by_type":{...},"by_severity":{...},"enriched_count":N,"watchlist_count":N}
(missing X-API-Key) → 401
```

## 4. Functional requirements
- **REQ-022-01**: Empty/unrefreshed sources return honest empty (200 with `count:0`/`iocs:[]`/
  zeroed stats) — NEVER a fabricated CVE/score/IOC. (the core ingest-first guarantee)
- **REQ-022-02**: CVE data carries real EPSS + KEV enrichment when present; absent → 0.0 / false,
  not invented.
- **REQ-022-03**: IOC reads/writes/watchlists are org-scoped; one org never sees another's IOCs.
- **REQ-022-04**: Feeds operate from cache when air-gapped (no hard dependency on live external
  fetch to serve a read) — aligns with SPEC-005.
- **REQ-022-05**: Threat-actor records expose real fields (aliases, ttps, origin_country,
  motivation, associated_campaigns) from the store, not hardcoded profiles.

## 5. Non-functional requirements
- Latency: GET reads < 2s; refresh/fetch is POST-triggered, not synchronous on a GET.
- Tenancy: org_id via get_org_id; cross-org → no foreign records.
- Auth: every endpoint requires X-API-Key; missing → 401.
- Failure mode: source error/empty → honest empty or 503 not_configured, never 500/hang/fake.

## 6. Acceptance criteria (executable, verified 2026-06-03)
- **AC-022-01**: `GET /api/v1/threat-intel/actors?org_id=X` → 200 list of actors with keys
  ⊇ {id, name, aliases, ttps, origin_country, motivation, associated_campaigns}. (verified — 10 actors)
- **AC-022-02**: `GET /api/v1/threat-intel/iocs?org_id=X` → 200 `{total, iocs, offset, limit}`. (verified)
- **AC-022-03**: `GET /api/v1/feeds/nvd/recent?org_id=X` → 200 `{cves, count, severity_filter}`;
  unrefreshed cache → `count:0, cves:[]` (honest empty, not fabricated). (verified)
- **AC-022-04**: `GET /api/v1/feeds/status` → 200 `{status:"healthy", engine:"feed-manager", total_feeds}`. (verified)
- **AC-022-05**: `GET /api/v1/ioc-enrichment/stats?org_id=X` → 200 with
  {total, by_type, by_severity, enriched_count, watchlist_count}; empty org → all-zero. (verified)
- **AC-022-06**: `GET /api/v1/ioc-enrichment/stats` without `X-API-Key` → 401. (verified)
- **AC-022-07**: ingest/normalizer + feed test suites pass (e.g. `tests/test_*feed*`, `tests/test_*ioc*`).

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Backfill-author | Documented existing TI layer (threat-intel + feeds + ioc-enrichment); grounded ACs against live TestClient probes; only live-verified endpoints listed (epss/mitre per-source paths left to their routers — guessed paths 404'd and were NOT included, per no-fabrication). |

## 8. Implementation notes
Already implemented; this spec backfills governance over the TI surface for the Augment Code
intent-IDE map (specs/INDEX.md). The honest-empty behaviour (REQ-022-01) was verified live:
empty org returns zeroed stats / empty lists, not fabricated data — the same NO-MOCKS principle
the UI layer enforces. The `/api/v1/feeds` prefix aggregates several feed routers; this spec
governs the layer + the verified core endpoints, not every per-source path. No code change.
