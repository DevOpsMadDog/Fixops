# FixOps Backend Stub & Hardening Audit — Re-Validated

**Date**: 2026-02-23 (re-validation of 2026-02-20 audit)  
**Scope**: All backend Python files (`suite-api/`, `suite-core/`, `suite-attack/`, `suite-feeds/`, `suite-evidence-risk/`, `suite-integrations/`)  
**Method**: Every claim from prior audits (`BACKEND_STUB_AUDIT_2026-02-20.md`, `need_hardening.md`, `fake_make_it_real.md`) validated against current codebase  
**UI stubs**: Excluded

---

## Executive Summary

| Category | Items | Fixed | Still Open | Change Since Last Audit |
|----------|-------|-------|------------|------------------------|
| **P0 Stubs** (fake data = real) | 2 | 1 | 1 | P0 #1 FIXED. P0 #2 renamed but still hardcoded. |
| **P1 Stubs** (noticeable gaps) | 6 | 5 | 1 | #3,4,6,8 FIXED. #7 intentional fallback. #5 merged into P0 #2. |
| **P2 Stubs** (pending endpoints) | 20 | 18 | 2 | 16 agent stubs FIXED. 2 evidence-risk stubs remain. |
| **fake_make_it_real.md** (84 items) | 84 | 82 | 2 | `intelligent_engine_routes.py` consensus endpoint still hardcoded. `new_backend/api.py` still present. |
| **Hardening** (security issues) | 9 categories | 0 | 9 | **Zero hardening work done.** All issues persist. |
| **In-Memory Stores** | 14 | 0 | 14 | **Zero migrated to SQLite.** All data lost on restart. |

### Bottom Line

**Stub removal: 78% done.** Most fake endpoints now call real engines (AnalyticsDB, ComplianceEngine, AutoFixEngine, FeedsService, KnowledgeBrain).

**Hardening: 0% done.** All 9 security/reliability issues from the original audit are untouched — SSRF, missing RBAC, no rate limiting, TLS disabled, in-memory state loss, unauthenticated webhooks, broken LLM consensus.

---

## Part 1: Stub Audit — What Changed

### P0 — Breaks User Trust

#### P0 #1: `suite-core/api/decisions.py` — Fake Metrics ✅ FIXED

**Previous**: Hardcoded `"validation_accuracy": 0.987`, `"model": "gpt-5 (demo)"`, `"current_rate": 0.87`  
**Current** (lines 118-180): Queries real sources:
- Vector DB stats from `decision_engine.real_vector_db_stats`
- LLM client availability check via `decision_engine.chatgpt_client`
- Policy decision counts from `policy_decision_logs` SQLite table
- Returns `"not_initialized"` / `"not_configured"` when services unavailable

**Verdict**: ✅ **FIXED** — no fabricated metrics remain.

---

#### P0 #2: `suite-api/apps/api/marketplace_router.py` — Hardcoded Counts ⚠️ CHANGED (not fully fixed)

**Previous**: `_DEMO_MARKETPLACE_ITEMS` with downloads 1542/967/423, ratings 4.5/4.8/4.2, `total_downloads: 2932`  
**Current**: Renamed to `_BUILTIN_MARKETPLACE_ITEMS` (L128) with **new** hardcoded values:
- Downloads: 3842, 2156, 5631
- Ratings: 4.8, 4.6, 4.7
- `_MARKETPLACE_STATS["total_downloads"]`: 11629
- `_BUILTIN_CONTRIBUTORS` with `total_downloads: 11629` and `4520`

The `/stats` endpoint (L690-697) tries `service.get_stats()` first, falls back to `_MARKETPLACE_STATS`.

**Verdict**: ⚠️ **PARTIALLY FIXED** — "demo" branding removed, but download counts and ratings are still fabricated numbers that look like real marketplace activity. The fallback path always returns them when no enterprise backend is configured.

**Recommendation**: Either (a) zero out counts when in fallback mode, or (b) add `"source": "builtin_defaults"` field so consumers can distinguish.

---

### P1 — Noticeable Gaps

| # | File | Issue | Status | Notes |
|---|------|-------|--------|-------|
| 3 | `agents_router.py` L1720 | Hardcoded framework control counts | ✅ **FIXED** | Real `_FRAMEWORK_CONTROLS` dict with named controls. Counts computed via `len()`. ComplianceEngine integrated. |
| 4 | `vuln_discovery_router.py` L326 | `_calculate_cvss` always None | ✅ **FIXED** | Imports `cvss` library, calls `CVSS3(vector).base_score`. Falls back to None only on parse error. |
| 5 | `marketplace_router.py` L697 | `/stats` returns `total_downloads: 2932` | ⚠️ **CHANGED** | Value changed to 11629. Enterprise path added but fallback still hardcoded. See P0 #2 above. |
| 6 | `reports_router.py` L295 | Synthetic demo report generation | ✅ **FIXED** | Real `Report` object via `db.create_report()`, actual file generation via `_generate_report_file()`. No demo_data import. |
| 7 | `micro_pentest_router.py` L895 | `_hardcoded_poc` static PoCs | ⚠️ **INTENTIONAL FALLBACK** | LLM-generated PoCs attempted first (L870-892). Static PoCs only used when LLM unavailable. Labeled as "fallback." |
| 8 | `business_context_enhanced.py` L53 | TODO: Store ssvc_context | ✅ **FIXED** | Data persisted in session store with `stored_at` timestamp. TODO comment removed. |

---

### P2 — Agent Stubs (16 copilot endpoints)

**All 16 agent stubs in `agents_router.py`: ✅ FIXED**

Every endpoint now integrates with real backends:

| Endpoint | Engine Used | Falls Back To |
|----------|-------------|---------------|
| `POST /analyst/attack-path` | KnowledgeBrain graph traversal | `"engine_unavailable"` |
| `GET /analyst/risk-score/{id}` | KnowledgeBrain + AnalyticsDB | `"no_graph_data"` |
| `POST /compliance/map-findings` | ComplianceEngine.evaluate() | `"integration_required"` |
| `POST /compliance/gap-analysis` | ComplianceEngine + AnalyticsDB findings | `"integration_required"` |
| `POST /compliance/audit-evidence` | AnalyticsDB artifact collection | `"no_findings"` |
| `POST /compliance/regulatory-alerts` | CISA KEV SQLite table | Empty list |
| `GET /compliance/controls/{fw}` | Built-in control library + ComplianceEngine | Static controls |
| `GET /compliance/dashboard` | ComplianceEngine × all frameworks | `"integration_required"` |
| `POST /compliance/generate-report` | ComplianceEngine + AnalyticsDB | `"integration_required"` |
| `POST /remediation/generate-fix` | AutoFixEngine.generate_fix() | `"engine_unavailable"` |
| `POST /remediation/create-pr` | AutoFixEngine + Git (create_pr=True) | `"engine_unavailable"` |
| `POST /remediation/update-dependencies` | AutoFixEngine per package | `"engine_unavailable"` |
| `POST /remediation/playbook` | PlaybookRunner dry-run validation | `"pending"` (no runner) |
| `GET /remediation/recommendations/{id}` | AnalyticsDB + KEV + KnowledgeBrain | `"finding_not_found"` |
| `POST /remediation/verify` | AnalyticsDB status check | Per-finding results |
| `GET /remediation/queue` | AnalyticsDB list_findings(status=open) | Empty queue |

**Pattern**: All 16 follow the same graceful degradation pattern — try real engine → fall back with clear status message. No more `"status": "pending"` with empty data masquerading as functioning endpoints.

---

### P2 — Other Stubs

| # | File | Issue | Status |
|---|------|-------|--------|
| 25 | `vuln_discovery_router.py` L711 | `external_count = 0` hardcoded | ✅ **FIXED** — attempts FeedsService EPSS lookup, falls back to 0 |
| 26 | `vuln_discovery_router.py` L859 | `_run_training` returns pending | ✅ **FIXED** — trains real scikit-learn models (RF, GB, IF) with cross-validation |
| 27 | `risk/reachability/monitoring.py` L221 | `get_metrics_summary` returns "N/A" | ⚠️ **CHANGED** — returns OTel instrument descriptors when enabled, `"not_configured"` when disabled. Actual metric *values* still require Prometheus scrape endpoint. |
| 28 | `risk/runtime/cloud.py` L136 | AWS analyzers return empty | ❌ **STILL STUBBED** — `_analyze_aws_s3`, `_analyze_aws_rds`, `_analyze_aws_ec2`, `_analyze_aws_iam` still `return []` after boto3 import check. Comment: `"production implementation goes here"`. |

---

### P3 — Acceptable Patterns (unchanged)

All 8 P3 items (abstract interfaces, protocol methods, marketplace demo fallbacks) remain correctly implemented. No changes needed.

---

### Dead Code & Duplicate Files

| File | Status |
|------|--------|
| `suite-core/api/analytics_routes.py` | ✅ **Removed** |
| `suite-core/api/auditing_routes.py` | ✅ **Removed** |
| `suite-core/api/pentest_routes.py` | ✅ **Removed** |
| `suite-core/api/reports_routes.py` | ✅ **Removed** |
| `suite-core/new_backend/api.py` | ⚠️ **Still present** — 85-line standalone FastAPI test harness. Low risk but dead code. |
| `suite-core/api/intelligent_engine_routes.py` | ❌ **LIVE STUB FOUND** — Still 596 lines. Lines 566-596 (`/consensus/analyze`) returns **hardcoded fake LLM responses** (`confidence: 0.92, 0.88, 0.87`) with no real LLM calls. `mindsdb_router.py` was written to replace it but the old file was never deleted. **This is registered as a new endpoint users could hit.** |

---

## Part 2: Hardening Audit — Nothing Fixed

### ❌ All 9 Categories Still Open

| # | Category | Severity | Status | Evidence |
|---|----------|----------|--------|----------|
| 1 | **TLS `verify=False`** | P0 | ❌ STILL PRESENT | 10 occurrences across 7 files. All MPTE, pentest, DAST, fuzzer HTTP calls disable TLS verification. |
| 2 | **In-Memory State** | P0 | ❌ STILL PRESENT | All 14 stores remain as plain Python dicts. Data lost on any restart. |
| 3 | **No RBAC** | P0 | ❌ STILL PRESENT | `_verify_api_key` in `app.py` checks key validity only. No role/scope extraction. Any valid API key = full admin access to all 640 endpoints. |
| 4 | **Rate Limiter Not Wired** | P1 | ❌ STILL PRESENT | `RateLimitMiddleware` exists in `rate_limiter.py` but is never imported or added in `app.py`. Zero rate limiting on any endpoint. |
| 5 | **SSRF in Workflows** | P0 | ❌ STILL PRESENT | `workflows_router.py` L264-271: `http_call` action accepts any URL without validation. Can reach internal networks, cloud metadata (169.254.169.254), localhost. |
| 6 | **Webhook Auth Missing** | P1 | ❌ PARTIALLY FIXED | Jira: ✅ HMAC-SHA256 verified. ServiceNow (L358): ❌ No auth. Azure DevOps (L1485): ❌ No auth. File moved to `suite-integrations/api/webhooks_router.py`. |
| 7 | **LLM Silent Fallback** | P1 | ❌ STILL PRESENT | Both providers silently fall back to `BaseLLMProvider` (deterministic heuristic) when API keys missing. No warning logged. Anthropic provider STILL broken — `system` role in `messages[]` array instead of top-level `system` param → API 400 → silent fallback. |
| 8 | **`datetime.utcnow()`** | P3 | ❌ STILL PRESENT | 61+ files, ~150+ occurrences. Deprecated since Python 3.12. |
| 9 | **`verify=False` in security scripts** | P1 | ❌ NEW | Found `verify=False` in generated pentest scripts (`agents_router.py` L1124) — scripts given to users contain TLS-disabled requests. |

---

### Detailed: In-Memory State (14 Stores — All Still Present)

| # | File | Variable | What's Lost on Restart |
|---|------|----------|----------------------|
| 1 | `copilot_router.py` L217-219 | `_sessions`, `_messages`, `_actions` | **All copilot conversations** |
| 2 | `agents_router.py` L437 | `_agent_tasks` | Agent task state & results |
| 3 | `inventory_router.py` L25, L351-352 | `_dependency_store`, `_service_store`, `_api_store` | Dependency maps, service catalog, API inventory |
| 4 | `policies_router.py` L26 | `_violation_store` | Policy violation records |
| 5 | `users_router.py` L58 | `_login_attempts` | **Brute-force rate limiting resets** — security bypass |
| 6 | `workflows_router.py` L26-28 | `_sla_store`, `_execution_steps`, `_paused_executions` | SLA configs, execution logs, paused workflows |
| 7 | `llm_router.py` L88 | `_settings` | LLM config reverts to defaults |
| 8 | `intelligent_engine_routes.py` L125-126 | `_sessions`, `_results` | ISE analysis sessions & results |
| 9 | `vuln_discovery_router.py` L282-284 | `_discovered_vulns`, `_contributions`, `_retrain_jobs` | **ALL pre-CVE intelligence** (irrecoverable) |
| 10 | `micro_pentest_router.py` L450-451 | `self._audit_logs`, `self._active_scans` | Audit trail & active scans |
| 11 | `nerve_center.py` L837-843 | Overlay config | Config accepted, returns success, **silently discarded** |
| 12 | `bulk_router.py` L107 | `_jobs` | Bulk operation progress & results |
| 13 | `new_backend/api.py` L57 | Decision feedback | Feedback accepted then **immediately discarded** |
| 14 | `copilot_router.py` L219 | `_actions` | Copilot action log |

**Highest risk**: #5 (security bypass), #9 (irrecoverable research data), #1 (user-facing data loss), #11 (silent discard).

---

### Detailed: TLS `verify=False` (All 10 Locations)

| # | File | Line | Context |
|---|------|------|---------|
| 1 | `suite-core/api/agents_router.py` | 998 | MPTE task call |
| 2 | `suite-core/api/agents_router.py` | 1124 | Generated pentest script (given to users) |
| 3 | `suite-attack/api/mpte_router.py` | 83 | `POST /mpte/verify` |
| 4 | `suite-attack/api/mpte_router.py` | 123 | `POST /mpte/scan` |
| 5 | `suite-attack/api/micro_pentest_router.py` | 73 | `GET /micro-pentest/health` |
| 6 | `suite-attack/api/micro_pentest_router.py` | 110 | `POST /micro-pentest/run` |
| 7 | `suite-core/core/intelligent_security_engine.py` | 321 | Internal ISE calls |
| 8 | `suite-core/core/api_fuzzer.py` | 220 | API fuzz testing |
| 9 | `suite-core/core/dast_engine.py` | 240 | DAST scanning |
| 10 | `suite-core/core/micro_pentest.py` | 1654 | CVE tester |

---

## Part 3: New Issues Found (Not in Original Audit)

| # | Severity | File | Issue |
|---|----------|------|-------|
| **NEW-1** | P0 | `intelligent_engine_routes.py` L566-596 | `/consensus/analyze` endpoint returns **hardcoded fake LLM confidence scores** (0.92, 0.88, 0.87). File should have been deleted when `mindsdb_router.py` replaced it. **Live endpoint returning fabricated AI consensus.** |
| **NEW-2** | P2 | `new_backend/api.py` | 85-line standalone FastAPI app (dead code). `/decisions/{id}/feedback` accepts feedback then discards it. Low risk but should be removed. |
| **NEW-3** | P2 | `marketplace_router.py` L128-210 | `_BUILTIN_*` data has inflated download counts (3842, 5631) and ratings (4.8, 4.7) that could mislead pilot/POC customers evaluating the marketplace. |

---

## Consolidated Fix Priority

### Tier 1 — Fix Before Any Demo/POC (security + trust)

| # | Issue | Effort | Files |
|---|-------|--------|-------|
| 1 | **SSRF in `http_call`** | 1 hour | `workflows_router.py` |
| 2 | **Wire rate limiter** | 5 min | `app.py` |
| 3 | **Delete `intelligent_engine_routes.py`** | 5 min | Dead file with live stub |
| 4 | **Webhook auth (ServiceNow + Azure DevOps)** | 1 hour | `webhooks_router.py` |
| 5 | **Fix Anthropic LLM call** (system param) | 5 min | `llm_providers.py` |
| 6 | **RBAC — `require_scope` on sensitive endpoints** | 3 hours | `app.py` + ~50 endpoints |
| 7 | **Marketplace fallback: add `"source": "builtin"`** | 15 min | `marketplace_router.py` |

### Tier 2 — Fix Before First Customer (data integrity)

| # | Issue | Effort | Files |
|---|-------|--------|-------|
| 8 | **In-memory → SQLite: `vuln_discovery_router`** (#9, irrecoverable data) | 4 hours | New `vuln_discovery_db.py` |
| 9 | **In-memory → SQLite: `copilot_router`** (#1, user-facing) | 3 hours | New `copilot_db.py` |
| 10 | **In-memory → SQLite: `users_router`** (#5, security bypass) | 2 hours | Use existing `user_db.py` |
| 11 | **In-memory → SQLite: `inventory_router`** (#3, 4 stores) | 4 hours | New `inventory_db.py` |
| 12 | **TLS `verify=False` → env-configurable** | 1 hour | 7 files, find/replace |
| 13 | **LLM fallback logging** (warn when deterministic) | 30 min | `llm_providers.py` |

### Tier 3 — Fix Before v1.0 (completeness)

| # | Issue | Effort | Files |
|---|-------|--------|-------|
| 14 | **In-memory → SQLite: remaining 9 stores** | 16 hours | 9 new `*_db.py` files |
| 15 | **AWS cloud analyzers** (#28, still `return []`) | 4 hours | `risk/runtime/cloud.py` |
| 16 | **Metrics summary** (#27, OTel descriptors only) | 2 hours | `risk/reachability/monitoring.py` |
| 17 | **Delete `new_backend/api.py`** (dead code) | 5 min | Standalone test app |
| 18 | **`datetime.utcnow()` → `datetime.now(timezone.utc)`** | 2 hours | 61 files, mechanical |

### Total Estimated Effort

| Tier | Hours | Timeline |
|------|-------|----------|
| Tier 1 (demo-ready) | ~6 hours | This week |
| Tier 2 (customer-ready) | ~15 hours | Next 2 weeks |
| Tier 3 (v1.0-ready) | ~25 hours | 4 weeks |
| **Total** | **~46 hours** | |

---

## Score vs. Previous Audit

| Metric | 2026-02-20 | 2026-02-23 | Delta |
|--------|-----------|-----------|-------|
| P0 stubs | 2 open | 1 open (+ 1 new) | -0 net |
| P1 stubs | 6 open | 1 open | -5 |
| P2 stubs | 20 open | 2 open | -18 |
| Hardening issues | 9 categories | 9 categories | **0 fixed** |
| In-memory stores | 14 | 14 | **0 migrated** |
| fake_make_it_real | 74/84 claimed | 82/84 verified | +8 |
| Dead code files | 5 | 2 | -3 |
| **Total open items** | **~56** | **~42** | **-14** |

**Progress**: Stub cleanup is 78% done. Hardening is 0% done. The codebase is significantly more real than 3 days ago, but has zero security hardening work applied.

---

*Generated: 2026-02-23 | Validated against live codebase | Supersedes BACKEND_STUB_AUDIT_2026-02-20.md*
