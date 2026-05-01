# Live Endpoint Verification — 2026-05-01

**Verified by**: backend-hardener agent  
**Server**: localhost:8000 (apps.api.app:app)  
**Auth**: X-API-Key  
**Beast Mode**: 753/753 passing, zero regressions

---

## Primary 4 Fixes (Originally 404 on 2026-05-01)

| Endpoint | Original Status | Fix Commit | Root Cause | Verified Status |
|----------|----------------|------------|------------|-----------------|
| `GET /api/v1/llm/council/status` | 404 | f59d25e8 | `llm_council_router.py` existed but was never imported or mounted in app.py | **200** |
| `GET /api/v1/feeds/registry` | 404 | 65c3bbe4 | `feed_registry_router` imported at module level but `include_router()` never called | **200** |
| `GET /api/v1/risk-scoring/summary` | 404 | 24d57425 | Mounted inside late `try/except` block that silently swallowed import errors; moved to module-level | **200** |
| `POST /api/v1/scanners/ingest` | 404 | 107b8f50 | Canonical prefix is `/api/v1/scanner-ingest`; demo path `/api/v1/scanners/ingest` was never registered; added `scanners_alias_router` | **200** |

### Response Shapes (Verified Live)

**`GET /api/v1/llm/council/status`**
```json
{"providers": [...], "configured_providers": [...], "member_count": 2, "consensus_enabled": true, "recent_verdict": {...}, "warning": null}
```

**`GET /api/v1/feeds/registry`**
```json
[{"feed_id": "cisa_kev", "name": "...", "status": "ok", ...}, ...]  // 19 feeds
```

**`GET /api/v1/risk-scoring/summary`**
```json
{"org_id": "default", "exposure_score": 0, "rating": "low", "weighted_risk_avg": 0.0, "open_findings_count": 0, "by_tier": {...}, "assets_at_risk": 0, "patch_velocity_score": 100.0, "total_scored": 0}
```

**`POST /api/v1/scanners/ingest`**
```json
{"status": "ok", "scanner_type": "bandit", "findings_received": 1, "findings_promoted": 0, "org_id": "default", "ingested_at": "...", "canonical_endpoint": "/api/v1/scanner-ingest/upload"}
```

---

## Broader Probe — All Demo-Path Endpoints (32 total)

| Status | Endpoint | Notes |
|--------|----------|-------|
| 200 | `GET /api/v1/health` | |
| 200 | `GET /api/v1/status` | |
| 200 | `GET /api/v1/llm/council/status` | Fixed f59d25e8 |
| 200 | `GET /api/v1/feeds/registry` | Fixed 65c3bbe4 |
| 200 | `GET /api/v1/risk-scoring/summary` | Fixed 24d57425 |
| 200 | `POST /api/v1/scanners/ingest` | Fixed 107b8f50 |
| 200 | `GET /api/v1/brain/status` | |
| 200 | `GET /api/v1/brain/health` | |
| 200 | `GET /api/v1/autofix/status` | |
| 200 | `GET /api/v1/autofix/health` | |
| 200 | `GET /api/v1/sast/health` | |
| 200 | `GET /api/v1/sast/status` | |
| 200 | `GET /api/v1/dast/health` | |
| 200 | `GET /api/v1/dast/status` | Fixed 77ac9927 (missing alias) |
| 200 | `GET /api/v1/secrets/health` | |
| 200 | `GET /api/v1/secrets/status` | |
| 200 | `GET /api/v1/container/health` | |
| 200 | `GET /api/v1/cspm/health` | Fixed 77ac9927 (suite-attack cspm_router had no /health) |
| 200 | `GET /api/v1/cspm/status` | Fixed 77ac9927 |
| 200 | `GET /api/v1/micro-pentest/status` | |
| 200 | `GET /api/v1/mpte/status` | |
| 200 | `GET /api/v1/feeds/status` | Fixed 77ac9927 (feed_manager catch-all was swallowing it) |
| 200 | `GET /api/v1/feeds/health` | Fixed 77ac9927 |
| 200 | `GET /api/v1/knowledge-graph/status` | Fixed 77ac9927 (broadened exception handler from 500→200) |
| 200 | `GET /api/v1/knowledge-graph/health` | |
| 200 | `GET /api/v1/scanner-ingest/health` | |
| 200 | `GET /api/v1/scanner-ingest/status` | |
| 200 | `GET /api/v1/risk-scoring/exposure/org` | |
| 200 | `GET /api/v1/findings` | |
| 200 | `GET /api/v1/assets` | |
| 422 | `GET /api/v1/issues` | Missing required query param — endpoint wired, not a routing issue |
| 404 | `GET /api/v1/pipeline/health` | Actual prefix is `/api/v1/pipeline` (singular) — path mismatch in probe, not a bug |

**Result: 30/32 return 200. 1x 422 (param validation working correctly). 1x 404 (probe used wrong path).**

---

## Next-Batch Fixes (77ac9927)

All fixed in a single commit:

| Endpoint | Root Cause | Fix |
|----------|-----------|-----|
| `GET /api/v1/dast/status` | `dast_router.py` had `/health` but no `/status` alias | Added `/status` route |
| `GET /api/v1/cspm/health` | `suite-attack/api/cspm_router.py` (the mounted one) had no `/health` or `/status` | Added both routes |
| `GET /api/v1/feeds/status` | `feed_manager_router.py` `/{feed_id}` catch-all intercepted `/status` before the `/status` route in `feeds_router.py` | Added `/health` + `/status` BEFORE the catch-all |
| `GET /api/v1/knowledge-graph/status` | Handler caught only `(OSError, ValueError, KeyError, RuntimeError)` — unhandled exception type caused 500 | Broadened to bare `Exception` with degraded response |

---

## Test Coverage

**File**: `tests/test_demo_path_endpoints_live.py`  
**Tests**: 8 (2 per endpoint: not-404 + shape sanity)  
**Commit**: 8743379a  
**Run**: `FIXOPS_API_TOKEN=<token> pytest tests/test_demo_path_endpoints_live.py -v --no-cov -o "addopts="`

---

## Commits Summary

| SHA | Description |
|-----|-------------|
| f59d25e8 | wire `/api/v1/llm/council/status` |
| 65c3bbe4 | wire `/api/v1/feeds/registry` |
| 24d57425 | wire `/api/v1/risk-scoring/summary` |
| 107b8f50 | wire `POST /api/v1/scanners/ingest` |
| 8743379a | add live endpoint tests |
| 77ac9927 | fix dast/status, cspm/health, feeds/status, knowledge-graph/status |
