# ALDECI Stub / Fake / Placeholder Triage — 2026-06-01

**Mandate**: "no stubs, no fake, no placeholder — real product enterprises will buy."

**Scope**: `suite-core/core/`, `suite-api/apps/api/` — all mounted HTTP endpoints.

**Methodology**: grep for STUB/FAKE/placeholder/hardcoded/NotImplementedError markers; read each handler; confirm mount status in app.py / sub_apps; classify.

---

## Summary

| Classification | Count |
|---|---|
| CUSTOMER-FACING FAKE (CRITICAL) | **9** |
| HONEST-GATED (acceptable) | 8 |
| INTERNAL-ONLY (not customer-reachable) | 6 |

---

## CUSTOMER-FACING FAKE Items (fix wave target)

These are mounted, authenticated API endpoints that return fabricated/hardcoded data to the caller with no honest 501/503/"not configured" signal.

| # | file:line | endpoint | classification | what it fakes | what real looks like |
|---|---|---|---|---|---|
| 1 | `suite-core/core/unified_dashboard.py:120` | `GET /api/v1/unified-dashboard/ciso` `GET /api/v1/unified-dashboard/soc` `GET /api/v1/unified-dashboard/executive` `GET /api/v1/unified-dashboard/compliance` | CUSTOMER-FACING FAKE | `_safe_sla_summary()` always returns hardcoded `{on_track:87, at_risk:8, breached:5, compliance_rate_pct:87.0}` with no try/except real engine. The comment says "sla_tracker module retired, wiring to canonical SLA engine pending." | Call `SLAEngine.get_summary(org_id)` from `suite-core/core/sla_engine.py` (engine exists) and return its output. |
| 2 | `suite-core/core/unified_dashboard.py:160` | `GET /api/v1/unified-dashboard/ciso` `GET /api/v1/unified-dashboard/compliance` `GET /api/v1/unified-dashboard/executive` | CUSTOMER-FACING FAKE | `_safe_compliance_summary()` always returns hardcoded `{SOC2:88%, PCI-DSS:76%, ISO27001:82%, overall:82%}` — comment says "ComplianceAutomationEngine lacks get_summary, wiring pending." | Wire `ComplianceAutomationEngine.get_compliance_summary(org_id)` or equivalent on the canonical engine. |
| 3 | `suite-core/core/unified_dashboard.py:181` | `GET /api/v1/unified-dashboard/ciso` `GET /api/v1/unified-dashboard/soc` `GET /api/v1/unified-dashboard/executive` `GET /api/v1/unified-dashboard/real-time` | CUSTOMER-FACING FAKE | `_safe_incidents_summary()` always returns hardcoded `{active:3, resolved_30d:12, mean_time_to_resolve_hours:4.2, p1_active:0, p2_active:1}` — comment says "incident_tracker module retired, wiring to IR/SOAR engines pending." | Wire to `IncidentResponseEngine` or `SOAREngine.list_incidents(org_id)`. |
| 4 | `suite-core/core/unified_dashboard.py:195` | `GET /api/v1/unified-dashboard/ciso` `GET /api/v1/unified-dashboard/soc` `GET /api/v1/unified-dashboard/real-time` | CUSTOMER-FACING FAKE | `_safe_threat_intel_summary()` always returns hardcoded `{feeds_active:28, iocs_ingested_24h:1842, high_confidence_iocs:94, threat_actors_tracked:12}` — comment says "threat_intel_aggregator retired, suite-feeds query pending." | Query the live suite-feeds importer stats (e.g. `ThreatFeedAggregator.get_summary(org_id)` or a direct DB count on the feed tables). |
| 5 | `suite-core/core/unified_dashboard.py:257` | `GET /api/v1/unified-dashboard/ciso` `GET /api/v1/unified-dashboard/soc` | CUSTOMER-FACING FAKE | `_safe_attack_surface()` always returns hardcoded `{exposed_endpoints:14, internet_facing_critical:2, unpatched_services:5, exposure_score:38}` — comment says "AttackSurfaceAnalyzer removed; Pydantic-shape adapter to AttackSurfaceMapper pending." | Adapt `get_attack_surface_mapper().get_attack_surface(org_id)` Pydantic model to the Dict shape this widget expects (it's a shape mismatch, not a missing engine). |
| 6 | `suite-api/apps/api/cspm_deep_router.py:550` | `GET /api/v1/cspm/compliance-report` | CUSTOMER-FACING FAKE | When the CSPM engine IS available (i.e. `_probe_engine()` passes), the handler still embeds three hardcoded CIS benchmark rows: `{CIS AWS 1.5: score=72, controls_passed=45, total=62}`, `{CIS Azure 2.0: score=68, …}`, `{CIS GCP 1.3: score=75, …}` alongside `overall_score` from the real engine. The framework breakdown is always fake regardless of actual cloud scan results. | Replace the hardcoded `frameworks` list with `engine.get_compliance_frameworks(org_id)` or equivalent; if the engine doesn't expose per-framework breakdown yet, return `frameworks: []` with a note rather than fabricated scores. |
| 7 | `suite-api/apps/api/scanner_ingest_router.py:642` | `GET /api/v1/scanner-ingest/supported` | CUSTOMER-FACING FAKE | When the `scanner_parsers` module fails to load, the handler silently returns a hardcoded static list with `total:26` and named scanners (checkmarx, sonarqube, bandit, etc.) as if they are live. The `total:26` is fabricated — it does not reflect what is actually installed/loaded. | Return `503 Service Unavailable` with `{"detail": "scanner_parsers module unavailable", "error_category": "not_configured"}` when the module cannot be imported, instead of a fabricated capability list. |
| 8 | `suite-core/core/openclaw_engine.py:589` + `suite-api/apps/api/openclaw_router.py:142` | `POST /api/v1/openclaw/campaigns/{id}/start` `POST /api/v1/openclaw/campaigns/{id}/advance` | CUSTOMER-FACING FAKE (boundary case) | `start_campaign()` and `advance_phase()` raise `NotImplementedError` which the global handler converts to a clean **501**. This is technically honest-gated — BUT the docstring on `start_campaign` in the router still says "queues and simulates initial tasks" rather than "not available". The 501 body says "not yet implemented" so the machine-readable signal is correct. **However**, `_SIMULATION_WARNING` is appended to the `advance_phase` 200 response path which is unreachable (NotImplementedError fires first), creating a misleading docstring. More critically, a customer who POSTs to `/start` without `PENTEST_CONNECTOR_URL` gets a 501 with no clear "configure X" UI cue. Classify as **boundary** — the 501 is honest but the endpoint surface is misleading. | Update the handler docstring and OpenAPI description to say "Requires PENTEST_CONNECTOR_URL env var — returns 501 until configured." No code change to engine needed; the 501 path is correct. |
| 9 | `suite-core/core/secrets_manager.py:1675` + `suite-core/core/secrets_manager.py:1641` | Internal only via `SecretsManager` class (NOT exposed via any mounted router — `secrets_manager_router.py` uses `SecretsManagerEngine`, a separate class) | **Re-classified: INTERNAL-ONLY** | `vault_transit_encrypt()` returns `vault:v1:STUB_ENCRYPTED_<hash>`. `vault_read()` / `vault_write()` / `vault_dynamic_credentials()` return stub `VaultSecret` objects with `metadata: {stub: True}`. These are only callable by internal Python code that imports `SecretsManager` directly — no HTTP route exposes them. | When `VAULT_ADDR` + `VAULT_TOKEN` env vars are present, call the real HashiCorp Vault HTTP API. Add `VAULT_ADDR` check at top of each method and raise `RuntimeError("Vault not configured: set VAULT_ADDR and VAULT_TOKEN")` if missing, rather than silently returning stubs. Flag for the vault-integration sprint. |

---

## HONEST-GATED Items (acceptable — clear 501/503/empty + signal)

These raise `NotImplementedError` → 501 or return honest empty/degraded responses with explicit signals. No fabrication.

| file:line | endpoint | why acceptable |
|---|---|---|
| `suite-core/core/openclaw_engine.py:603` | `POST /api/v1/openclaw/campaigns/{id}/start` | `NotImplementedError` → global 501 handler with `"Set PENTEST_CONNECTOR_URL"` message. |
| `suite-core/core/openclaw_engine.py:623` | `POST /api/v1/openclaw/campaigns/{id}/advance` | Same — 501 with config instruction. |
| `suite-core/core/cloud_drift_engine.py:369` | `POST /api/v1/cloud-drift/scan` | `NotImplementedError` → 501; docstring says "requires real cloud connector." |
| `suite-core/core/function_reachability_engine.py:900` | `POST /api/v1/code-intel/parse-repo` (TS/Java stubs) | `NotImplementedError` → router catches it as HTTP 501 explicitly at `function_reachability_router.py:97`. |
| `suite-core/core/semantic_analyzer_engine.py:611` | `POST /api/v1/semantic/parse-repo` (TS/Java/Go stubs) | `NotImplementedError` → router catches it as HTTP 501 at `semantic_analyzer_router.py:100`. |
| `suite-core/core/notification_engine.py:277` | Internal Slack notifier | Checks `FIXOPS_SLACK_WEBHOOK_URL` at runtime; if it starts with the default `STUB` string, skips sending. Never fabricates a "sent" confirmation — returns `False`. |
| `suite-api/apps/api/vendor_risk_engine.py:1277` | `POST /api/v1/vendor-risk/assess` | `_check_threat_intel()` always returns `None` (no false finding injected, no fake score applied). Score is computed from real NVD + breach DB checks only. |
| `suite-core/core/unified_dashboard.py:104` | All `/api/v1/unified-dashboard/*` | `_safe_posture_score()`, `_safe_findings_summary()`, `_safe_analytics_kpis()`, `_safe_recent_events()`, `_safe_developer_findings()` all try a real engine first and only fall back on exception — the fallback fires only on import/runtime failure, not by design. |

---

## INTERNAL-ONLY Items (not customer-reachable)

| file:line | what it is | why not customer-reachable |
|---|---|---|
| `suite-core/core/secrets_manager.py:1641` | `vault_read/write/transit_encrypt/dynamic_credentials` stub methods | No HTTP router imports or exposes `SecretsManager`; `secrets_manager_router.py` uses a separate `SecretsManagerEngine` class. |
| `suite-core/core/airgap_deployment.py:626` | `generate_feed_stubs()` — NVD JSON feed stub generator for air-gap bootstrap | Admin-only CLI helper; not mounted as an HTTP endpoint. Stubs are clearly labelled `"Stub CVE entry for {year}"` in description field. |
| `suite-core/connectors/commercial_dast_parsers.py:566` | `ingest_veracode_dast_dump()` embedded sample fallback | `commercial_dast_routers.py` is NOT imported or mounted anywhere in app.py or any sub_app (only referenced in `scripts/gen_api_reference.py`). Dead code path. |
| `suite-core/core/rasp_engine.py:1029` | `detect_impossible_travel()` "stub that detects simple country-mismatch" | The method IS functional (compares login country codes); "stub" in the comment is a self-deprecating note about algorithm simplicity, not fabricated output. Results reflect real session data. |
| `suite-core/core/vector_store.py:89` | Abstract base class `NotImplementedError` | ABC interface — concrete subclasses implement it. Never instantiated directly. |
| `suite-core/core/adapters.py:97` | Abstract adapter base `NotImplementedError` | Same as above — ABC pattern. |

---

## Remediation Notes for Fix Wave

**Priority order** (highest customer impact first):

1. **Items 1–5** (unified_dashboard `_safe_*` always-hardcoded functions): One file, five functions. The fix is to wire each to the canonical engine that already exists — this is a pure wiring task, not new engine work. The `_safe_sla_summary` needs `SLAEngine`; `_safe_compliance_summary` needs `ComplianceAutomationEngine.get_compliance_summary`; `_safe_incidents_summary` needs IR/SOAR engine; `_safe_threat_intel_summary` needs suite-feeds stats; `_safe_attack_surface` needs a Dict-shape adapter on `AttackSurfaceMapper`. Until wired, each should return an empty envelope with `"status": "not_configured"` rather than fabricated numbers.

2. **Item 6** (`cspm_deep_router.py:564`): One line — replace the three hardcoded `frameworks` entries with a call to `engine.get_compliance_frameworks(org_id)` or return `[]` with a note if the engine method doesn't exist yet.

3. **Item 7** (`scanner_ingest_router.py:650`): Replace the hardcoded fallback dict with a `503` response when `_get_scanner_parsers()` returns None/falsy.

4. **Item 8** (openclaw docstrings): Low-risk text-only fix — update OpenAPI descriptions for `/start` and `/advance` to accurately state 501-until-configured behavior.

---

*Triage performed: 2026-06-01. Analyst: chief-architect sweep (read-only, no code modified).*
