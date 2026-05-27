# STUB / FABRICATION AUDIT — ALdeci

Living ledger of fabricated/stub/placeholder code (data presented as real when it isn't).
Oracle rule: every entry is grep/read-verified, with file:line evidence.

Legend: ❌ fabrication (production path returns fake data) · ⚠️ needs triage · ✅ fixed/real · 🟢 legitimate (simulation IS the real function)

## FIXED this session (verified real, committed — branch chore/ui-prune-plan-2026-05-24)
- ✅ security_scorecard — real coverage-aware scores from real findings (00b2df8d)
- ✅ config_benchmark / kubernetes_security / compliance_scanner — real checkov (c49bd189, c8c56e7d, 73b7c114)
- ✅ ccm — real conftest/OPA (4f488e88)
- ✅ LLM council wired into Brain Pipeline, real 5-vendor OpenRouter, fallback votes excluded, honest no-config (d14ea30d, 93034e26, 3c41b726, b008e526) — architect APPROVED
- ✅ TrustGraph correlates real findings (a4e3df3c)
- ✅ DPO learning loop: 5,207 fabricated $0 verdicts quarantined + cost>0 guard (048b8d11)
- ✅ ioc_enrichment — real abuse.ch feed (8192184c); vendor_scorecard — real TLS+HTTP (8192184c)
- ✅ azure_defender — honest not-configured, no _MOCK_ALERTS by default (committed this session)
- ✅ cloud_discovery — honest not-configured, no fabricated cloud assets (committed this session)
- ✅ material_change_detector — consumes real verdict (was getattr-on-dict→0.5) (6c5df6e7)
- ✅ 9 honesty-floor engines raise NotImplementedError instead of hash-derived scores (8ab435e6)

## NEWLY FOUND (this recon) — production fabrication, NOT yet fixed
- ❌ **integration_health** `_simulate_check` (suite-core/core/integration_health.py:242, def :539) — run_health_check() ALWAYS simulates latency/status from a heuristic; never performs a real HTTP/TCP probe. Reports fake service health. FIX: real reachability probe (httpx/socket, like vendor_scorecard TLS probe); honest "unknown" when unreachable. Real, no creds needed.
- ❌ **secret_scanner_engine** `_simulate_scan` (suite-core/core/secret_scanner_engine.py:291, def :310) — start_scan() ALWAYS runs deterministic template-based fake results (_SCAN_TEMPLATES). FIX: real secret scanning (regex/entropy over a real target path, like the github-connector pattern scanner) OR honest not-configured; never templates as real findings.
- ⚠️ **council_enhanced** `_mock_vote` (suite-core/core/council_enhanced.py:514, def :596) — falls back to mock votes when "real council not available" (note :239). FIX: route to the now-real OpenRouter council OR honest-fail; no mock votes as real consensus.
- ⏳ **ai_orchestrator** `_mock_llm_response` (default FIXOPS_LLM_BACKEND=mock) — fix IN PROGRESS (agent ac54d8e0): default to real OpenRouter when key present, honest otherwise.

## NEEDS DEEPER TRIAGE (hypothesis pending read)
- ⚠️ intelligent_security_engine `_simulate_phase` (:1016) — likely no-MPTE fallback (MPTE_BASE_URL real); confirm gate. If silent fabrication when MPTE absent → honest-fail.
- ⚠️ security_playbook_engine `_simulate_step` (:482, caller :418) — SOAR; confirm whether "simulate" is a legitimate dry-run mode or the only (fabricated) execution path.

## LEGITIMATE (simulation IS the product function — not fabrication)
- 🟢 attack_simulation_engine `_simulate_step_execution` (:790) — simulating attacks is the engine's real purpose (you model attacks, not really attack). Keep.
- 🟢 behavioral_analytics_engine, executive_dashboard — no fabrication signature on scan; verify during triage.

---

## AUDIT WAVE 2 (2026-05-27)

**Scope**: all `suite-core/core/*.py` engines not already resolved in STUB_AUDIT.md.
**Method**: grep for `import random` + `random.*()`, `def _simulate`, `def _mock`, `_MOCK_`, `_SAMPLE_`, `_TEMPLATE`, `hexdigest()`/`hash(...)` feeding scores, hardcoded identifiers in getter returns, `# TODO`/`# placeholder` near returns. Each hit read + caller traced to classify gate.
**Engines scanned**: 845 files in `suite-core/core/`. Fabrication signatures found in 13 distinct files; classified below.

### ❌ FABRICATION (production default — fake data presented as real) — 8 found

**Priority 1 — silent mock returns for configured external integrations**

- ❌ **gcp_scc** `get_findings` / `get_sources` / `get_assets`
  - File: `suite-core/core/gcp_scc.py:361,395,424`
  - Evidence: `if not self.is_configured(): return list(_MOCK_FINDINGS)` — no `is_mock` flag in response, no disclosure to caller that data is synthetic. `import_findings()` at :463 sets `is_mock = not self.is_configured()` but that field is internal and not surfaced in the normalized findings list.
  - Gate: `is_configured()` checks `GCP_PROJECT_ID` + `GOOGLE_APPLICATION_CREDENTIALS`. On any unconfigured deploy (the common case) the production code path returns hardcoded mock GCP findings silently.
  - Multica: **#9023**

- ❌ **github_security** `get_code_scanning_alerts` / `get_dependabot_alerts` / `get_secret_scanning_alerts`
  - File: `suite-core/core/github_security.py:309,322,335`
  - Evidence: `if not self.is_configured(): return list(_MOCK_CODE_SCANNING_ALERTS)` — mock data returned with no disclosure. `import_findings()` at :534 sets `is_mock` but only internally.
  - Gate: `is_configured()` checks `GITHUB_TOKEN` / `GH_TOKEN`. Silent mock on any unconfigured deploy.
  - Multica: **#9024**

- ❌ **pagerduty_integration** `create_incident` / `update_incident` / `list_incidents` / `get_incident` / `list_schedules` / `get_schedule` / `list_escalation_policies` / `get_escalation_policy` / `list_services` / `get_service`
  - File: `suite-core/core/pagerduty_integration.py:332,399,458,530,556,593,629,655,682,705`
  - Evidence: all 10 public methods fall back to `_MOCK_INCIDENTS` / `_MOCK_SCHEDULES` / `_MOCK_ESCALATION_POLICIES` / `_MOCK_SERVICES` when `not self.is_configured()`. No `is_mock` disclosure in returned dicts (except `create_incident` which does add `"is_mock": True` — the other 9 do not).
  - Gate: `is_configured()` checks `PAGERDUTY_API_TOKEN`. Silent mock for 9 of 10 methods on any unconfigured deploy.
  - Multica: **#9025**

- ❌ **semgrep_integration** `_run_semgrep`
  - File: `suite-core/core/semgrep_integration.py:154-160,175-176`
  - Evidence: `if not self.is_semgrep_available(): return dict(_MOCK_SEMGREP_OUTPUT)` — no `is_mock` field in returned dict. `normalize_results()` at :358 sets `is_mock = not self.is_semgrep_available()` but that is only on the summary, not on individual findings.
  - Gate: `is_semgrep_available()` = `shutil.which(self._bin)`. On any deployment without semgrep installed (air-gapped, minimal container) returns fake scan results silently.
  - Multica: **#9026**

- ❌ **trivy_integration** `_run_trivy` + **trivy_scan_engine** `_run_trivy`
  - File: `suite-core/core/trivy_integration.py:123,139` and `suite-core/core/trivy_scan_engine.py:191,207`
  - Evidence: both files return `dict(_MOCK_TRIVY_OUTPUT)` when `not self.is_trivy_available()` — no `is_mock` field in the returned dict. `trivy_scan_engine` log message at :189 says "returning deterministic mock output" but the dict itself has no disclosure flag.
  - Gate: `is_trivy_available()` = `shutil.which(trivy_bin)`. Silent mock on any deployment without trivy.
  - Multica: **#9027**

**Priority 2 — hash-derived numbers presented as real package intelligence**

- ❌ **supply_chain_intel** `_score_package` → `_mock_last_updated_days` / `_mock_maintainer_count` / `_mock_download_count` / `_mock_dependencies_count`
  - File: `suite-core/core/supply_chain_intel.py:321-324` (caller), `368,376,382,386` (mock methods)
  - Evidence: `_score_package()` docstring says "deterministic, no external calls" and calls all four `_mock_*` methods unconditionally — `last_updated_days = self._mock_last_updated_days(name)` etc. These hash-derived values (e.g. `abs(hash(name)) % 500` for days, `abs(hash(name+"d")) % 10_000_000` for download count) are then used to trigger real risk categories (ABANDONED, LOW_MAINTAINER, etc.) and compute the `risk_score`. There is no real PyPI/OSV/libraries.io lookup, no `is_mock` flag on `PackageRisk`, and the public `analyze_package()` method persists these fabricated metrics to SQLite as findings.
  - Gate: Unconditional — no env var gate, no binary check. Every call to `analyze_package()` uses hash-derived metadata.
  - Multica: **#9022**

**Priority 3 — synthetic data seeded as production history at module import**

- ❌ **executive_dashboard_router** `generate_synthetic_history` called at module import
  - File: `suite-api/apps/api/executive_dashboard_router.py:60`
  - Evidence: `_trend_analyser.generate_synthetic_history(weeks=12, seed=42)` is called unconditionally at module import time. `generate_synthetic_history()` (`executive_dashboard.py:695`) generates 12 weeks of random-walk risk scores, vuln counts, compliance %, MTTR using `random.Random(seed)`. The `GET /risk-trends` endpoint (`executive_dashboard_router.py:461`) calls `_trend_analyser.get_snapshots()` which returns these synthetic snapshots with no `is_synthetic` flag — they appear as real historical posture data to every API caller.
  - Gate: Unconditional — runs on every server start regardless of whether real snapshot data exists.
  - Multica: **#9028**

**Priority 4 — SOAR playbook execution is entirely simulated**

- ❌ **soar_engine** `_simulate_action` / `_run_playbook_actions`
  - File: `suite-core/core/soar_engine.py:372,401-420`
  - Evidence: `_execute_playbook_internal()` calls `_run_playbook_actions()` which calls `_simulate_action()` for every action. `_simulate_action()` fabricates `ticket_id`, `scan_id`, `evidence_id`, `rule_id` etc. using `uuid.uuid4().hex` without performing any real action (no HTTP call, no ticket API, no firewall rule). The execution is persisted to SQLite with `status="completed"` — indistinguishable from a real SOAR execution. Unlike `security_playbook_engine` (which was fixed with `EXECUTION_MODE="simulated"` labels), `soar_engine` has no honesty labels.
  - Gate: Unconditional — every `execute_playbook()` call goes through `_simulate_action`. No real dispatch path exists.
  - Multica: **#9029**

---

### 🟢 LEGITIMATE (simulation IS the function — not fabrication) — 8 confirmed

- 🟢 **breach_simulation** `random` usage — breach/attack simulation is the product; random outcomes are intentional.
- 🟢 **red_team_engine** `random` usage — red team scenario generation; random is the product.
- 🟢 **executive_dashboard** `FAIREngine.run_simulation` (`:541`) — FAIR Monte Carlo simulation. `random.Random(seed)` drives financial loss sampling. This IS the product function; stochastic modelling is correct. Seeded, reproducible.
- 🟢 **risk_quantification_engine** `run_monte_carlo_simulation` (`:281`) — Monte Carlo on user-supplied scenario parameters. Correct use of random for financial modelling.
- 🟢 **risk_quantifier** `_run_monte_carlo` / `_pert_sample` (`:296,258`) — PERT-Beta Monte Carlo on user-defined risk scenarios. Legitimate financial risk modelling.
- 🟢 **zero_gravity** `MinHashLSH.__init__` (`:227`) — `random.Random(42)` generates fixed MinHash coefficients. Correct algorithm implementation; deterministic seed is intentional.
- 🟢 **zero_gravity** `_weighted_choice` (`:1737`) — probabilistic routing for capacity planning forecasts. The function is a sampler by design.
- 🟢 **single_agent** `_bootstrap_confidence_interval` (`:1305`) — `random.choices` for bootstrap resampling of expert opinion confidence intervals. Correct statistical method.
- 🟢 **self_learning** `seed_demo_data` (`:1240`) — explicitly named demo seeder, gated behind `POST /demo/seed` endpoint with `_require_non_enterprise` dependency. Not on any production read path.
- 🟢 **integration_hub** `random.uniform` (`:1030`) — jitter on exponential backoff retry delay. Correct use of random.
- 🟢 **falkordb_client** `random.sample` (`:279`) — sampling node IDs for graph traversal health check. Correct use of random.
- 🟢 **intelligent_security_engine** `_simulate_phase` (`:1016`) — this is a dry-run path. `_execute_phase` (`:1026`) is the real path that calls MPTE via httpx. The caller routes: if guardrails block the phase → `_simulate_phase`; otherwise → `_execute_phase`. Dry-run is explicit and labeled `"dry_run": True`.
- 🟢 **openclaw_engine** `_simulate_tasks` (`:869`) — module docstring explicitly states "NOT PRODUCTION READY"; `start_campaign()` raises `NotImplementedError` at :604 — `_simulate_tasks` is unreachable in production. Module emits a WARNING log on import.
- 🟢 **stage_runner** hardcoded `CVE-2021-44228` (`:474-475`) — this is a fallback applied only when a `log4j` purl is detected in a real build report AND the live KEV/EPSS feeds return empty. It is a known-CVE sentinel, not fabricated data.
- 🟢 **executive_dashboard** `generate_synthetic_history` method itself — the method is legitimately named "synthetic" and used for demo/testing. The fabrication is in the **router** unconditionally seeding it at startup (covered by ❌ #9028 above).

---

### ⚠️ UNSURE — 0 found

---

## ENGINE SWEEP 3 (2026-05-27)

**Scope**: `suite-core/core/*.py`, `suite-attack/`, `suite-integrations/`, `suite-feeds/` (Python only).
**Already-fixed list honoured**: 40 engines listed in task brief skipped.
**Fresh signatures used** (not targeted by sweep 2):
1. Hardcoded fake domain values returned on customer-facing paths
2. `get_*/list_*/fetch_*/analyze_*` methods whose body is a hardcoded literal list/dict
3. Magic confidence/score constants not derived from inputs
4. Silent stubs with `# TODO/FIXME/stub/placeholder` comments near returns
5. `pass`-body or `return {}` masquerading as real integrations

**Files grepped**: ~950 Python files across four suites.
**Real fabrications found**: 3

---

### ❌ FABRICATION — 3 confirmed

| # | Severity | File:line | Function | What is fabricated | Suggested fix |
|---|----------|-----------|----------|--------------------|---------------|
| 1 | **HIGH** | `suite-core/core/mcp_gateway.py:811-833` | `_handle_get_threat_intel` (exception branch) | When `copilot_graphrag` raises any exception, the method silently returns two hardcoded CVE records (`CVE-2021-44228`, `CVE-2023-44487`) with fabricated `relevance` scores (0.95, 0.72) and `total_returned: 2`. This is on the live `call_tool("get_threat_intel", ...)` path — any MCP client query for threat intel gets fake Log4Shell + HTTP/2 Rapid Reset results whenever GraphRAG is unavailable. No `is_fallback` or `error` field is returned. | Replace the exception body with `{"query": query, "entity_type": entity_type, "total_returned": 0, "results": [], "error": "threat_intel_unavailable", "core_queried": "threat_intel"}`. The caller already handles empty results. |
| 2 | **HIGH** | `suite-core/core/self_learning.py:1240-1390` / `suite-api/apps/api/self_learning_router.py:523-539` and `562-614` | `seed_demo_data` (and the `/demo/seed`, `/demo/full-loop` endpoints) | `seed_demo_data()` generates 98 feedback records with deterministic `random.Random(42)`, hardcoded scanner names, hardcoded CVE IDs (`CVE-2024-3094`, `CVE-2023-44487`, `CVE-2024-21626`), and engineered accuracy progressions (60%→85%). The data is written to the **production learning database** (`data/self_learning.db`). Although the endpoint has a `_require_non_enterprise` guard (blocks when `FIXOPS_MODE=enterprise`), the guard is opt-in: any deployment that does not set this env var (the default) exposes the endpoint and allows demo data to corrupt real learning weights. The `/demo/full-loop` endpoint calls `seed_demo_data()` then immediately runs `compute_adjustments()` — so a single API call poisons the live learning loop. | (a) Promote the guard to default-deny: block the endpoint unless `FIXOPS_MODE=demo` is explicitly set (invert the gate). (b) Write `seed_demo_data` to an isolated `data/demo_self_learning.db`, never to the production DB. (c) Remove the inline `seed_demo_data()` call from `/demo/full-loop`. |
| 3 | **MEDIUM** | `suite-core/core/mcp_gateway.py:859-871` | `_handle_ask_copilot` (exception branch) | When `copilot_graphrag` raises any exception the method returns a fabricated generic security answer: `"Based on available security intelligence, this query relates to a known vulnerability pattern. Recommend reviewing findings in the ALDECI dashboard and applying the suggested mitigations."` with `confidence: 0.65` and `evidence_count: 0`. No `error` field, no indication to the caller that this is a fallback string rather than a real GraphRAG answer. Any MCP Copilot query silently gets a generic string when GraphRAG is down. | Replace with an honest error response: `{"question": question, "answer": None, "error": "graphrag_unavailable", "confidence": 0.0, "evidence_count": 0, "sources": [], "agent_type": agent_type}`. |

---

### 🟢 LEGITIMATE — items investigated and cleared

- `suite-core/core/cve_enrichment.py` `BUILT_IN_CVES` dict (lines 19-53): used only as a **network fallback** (`_from_builtin` is called only when `_fetch_from_network` returns `None`). The record carries `"source": "builtin"` so callers can distinguish it. Legitimate offline-safe reference data.
- `suite-core/core/vendor_risk_engine.py` `KNOWN_BREACHES` dict (lines 79-151): a static reference table of 9 well-known public breaches (SolarWinds, Log4j, Okta, etc.) used to enrich vendor assessments. All CVE IDs are real published CVEs. Legitimate reference data.
- `suite-core/core/mitre_mapper.py` CVE→MITRE mappings (lines 1306-1383): real published CVE-to-technique mappings (Log4Shell, ProxyLogon, EternalBlue, Heartbleed, etc.). Legitimate security knowledge base.
- `suite-core/core/dast_scanner.py` `confidence=0.85/0.95` constants (lines 1013-1574): each value is set **after** a real probe confirms an observable indicator (SQL error string detected, header absent, redirect not found, etc.). The constant expresses the scanner's classification confidence for that finding category, not a score injected before probing. Legitimate.
- `suite-core/core/autofix_templates.py` `confidence=0.80` (lines 195, 347, 772): these are per-template fix-confidence declarations — how confident the template author is that the suggested code transformation is correct and safe. They are static metadata on the template object, not scores computed from customer scan data. Legitimate.
- `suite-core/core/self_learning.py` `seed_demo_data` function: the function itself is legitimately named and documented as demo seeding. The fabrication finding (#2 above) is in the **gate design** of its router exposure, not in the function's internal correctness.
- `suite-core/core/deception_engine.py` `list_honeypot_endpoints` (line 374): returns data projected from SQLite rows, not a hardcoded literal. Legitimate.
- `suite-core/core/self_learning.py:1279,1305` `rng.uniform(0.5, 0.95)` confidence values: these are inside `seed_demo_data` (the demo seeder), not on any live scoring path. Legitimate demo construction.
- All `score >= 90` / `confidence >= 0.85` threshold comparisons: these are decision thresholds (grade boundaries, alert triggers, escalation cutoffs), not fabricated scores. Legitimate.
- `pass` in exception handlers (`except Exception: pass`): these are all error-swallowing patterns in non-return paths (event bus emission, optional TrustGraph emit). None masquerade as successful data returns.
- `return {}` occurrences: all inspected instances are error-path returns in parsers/adapters (e.g., `dast_scanner` HTTP parse failure, `configuration.py` missing-key lookup) — they signal absence of data, not fabricated data. Legitimate.
- `suite-core/core/intelligent_security_engine.py:995-1001` `_generate_compliance_checks`: returns templated strings **derived from a real input** (`len(cve_ids)` is used). Not domain data fabrication — it is a text formatter for a compliance annotation. Acceptable.

---

### Summary

| Category | Count |
|----------|-------|
| Files grepped | ~950 |
| Hits investigated (all 5 signatures) | 83 distinct locations |
| Real fabrications (new, not in prior sweeps) | **3** |
| Legitimate / cleared | 17 investigated, all cleared |
| Top priority | `mcp_gateway` exception fallbacks (#1, #3) — live MCP path returns fake data on GraphRAG failure |
| Second priority | `self_learning` demo seed gate (#2) — demo endpoint reachable on default deployments, writes to production DB |

**Top 5 by dispatch priority**:
1. `suite-core/core/mcp_gateway.py:811` — `_handle_get_threat_intel` exception branch returns hardcoded CVEs (HIGH)
2. `suite-api/apps/api/self_learning_router.py:523` — `/demo/seed` gate is opt-in not opt-out; demo data reaches production learning DB (HIGH)
3. `suite-core/core/mcp_gateway.py:859` — `_handle_ask_copilot` exception branch returns fabricated advisory text (MEDIUM)
4. Items #1–#8 from AUDIT WAVE 2 remain unresolved (not re-listed here — see wave 2 entries)
5. Sweep 3 found **zero new fabrications** in `suite-feeds/`, `suite-integrations/`, `suite-attack/` — those subsystems are clean for sweep 3 signatures.

No candidates remained unresolvable after reading caller + gate.

---

## ENGINE SWEEP 2 (2026-05-27)

**Scope**: `suite-core/core/*.py`, `suite-core/connectors/*.py`, `suite-feeds/`, `suite-evidence-risk/` (Python only).
**Method**: grepped for `import random`, `random\.`, `np\.random`, `uniform(`, `randint(`, `_simulate`, `_mock`, `_fake`, `MOCK_`, `placeholder`, `dummy`, `sample_data`, `FAKE_`, `hashlib.*% 100`, `hash.*% 100`, `% 100.*score`, `int(hashlib`. Every hit was opened and its call chain traced to the nearest customer-facing API route to classify gate.
**Files grepped**: ~430 Python files across the four directories. Fabrication signatures found in 8 distinct files; classified below.

---

### ❌ CRITICAL — hash-derived compliance metrics presented as real to board-level report endpoint

| severity | file:line | engine/function | what's fabricated | suggested fix |
|----------|-----------|-----------------|-------------------|---------------|
| CRITICAL | `suite-core/core/executive_reports.py:404` | `ExecutiveReportEngine._build_compliance_status` | Per-framework compliance scores generated as `70.0 + (hash(org_id + fw) % 30)` — a deterministic hash on the org_id string, not a count of real controls. Served via `GET /api/v1/reports/executive` (executive_report_router.py). Every customer gets a fake 70-100% score that never changes unless their org_id string changes. | Pull real framework scores from `ComplianceScannerEngine` or `CCMEngine` (already real) and return honest empty/null when no scans have run. |
| CRITICAL | `suite-core/core/executive_reports.py:426` | `ExecutiveReportEngine._build_compliance_status` | "Control pass/fail" totals derived as `50 + (hash(org_id + fw + "t") % 100)` — a hash-derived integer, not a count of real controls assessed. "Evidence collection status" (lines 445-452) cascades from these fake totals. Presented as authoritative compliance evidence counts in the board-level report. | Derive from real CCM/compliance scan results. Return zero-counts with an honest `"no_scans_run": true` flag if data absent. |
| HIGH | `suite-core/core/supply_chain_analyzer.py:158-161` | `SupplyChainAnalyzer.analyze_package` (step 4: abandonment detection) | `days_since_last_release` computed as `(md5(name) % 1000) + 1` — a hash of the package name, not a real registry lookup. Used to set `is_abandoned = True` and add a medium-severity risk finding. Result persisted to SQLite via `mlops_supply_chain_router.py:174` and `supply_chain_router.py:649`. A package named "cryptography" will always show the same fake staleness age. | Call PyPI JSON API (`https://pypi.org/pypi/{name}/json`) for `releases[-1].upload_time` or OSV `/query` to get real last-release date. On network error, omit the `abandoned` risk category rather than fabricating it. |

---

### ❌ HIGH — synthetic fallback injects fabricated security events into real findings/anomaly stores without disclosure

| severity | file:line | engine/function | what's fabricated | suggested fix |
|----------|-----------|-----------------|-------------------|---------------|
| HIGH | `suite-core/connectors/iam_sso_connector.py:721-728` | `IAMSSoConnector.sync` — Keycloak fallback | When Keycloak is unreachable (or not configured), `synth_events_for_realm()` generates completely random login/admin events with random IPs, auth methods, countries, and event types. These are then fed into `SecurityFindingsEngine.record_finding()` and `AnomalyDetector.record_event()` as real findings (lines 733-748). `result.fallback_synthetic = True` is set but never surfaces in the persisted findings themselves. A customer without Keycloak configured gets fake IAM security findings in their findings DB. | Gate on `fallback_synthetic=True`: skip `record_finding` / `record_event` writes entirely. Return an empty-but-honest result with a `"keycloak_not_configured"` status field. Never write synthetic events to the production findings store. |
| HIGH | `suite-core/connectors/siem_connector.py:1551-1575` + `suite-api/apps/api/siem_connector_router.py:137-165` | `generate_events()` + `POST /api/v1/siem-connector/generate` | `generate_events()` builds fully synthetic SIEM events (Splunk HEC, Datadog, Sentinel KQL, Wazuh, CEF, syslog, Suricata) with random IPs, hostnames, rule IDs, and alert signatures using a seeded RNG. The `/generate` route correctly labels the endpoint as fixture generation and does not ingest, so the route itself is honest. The risk is `generate_and_ingest()` (line 1578) which calls `generate_events()` then passes results straight through to the real `ingest()` pipeline including `findings_engine`. Any caller of `generate_and_ingest()` will write synthetic SIEM events as real findings. | `generate_and_ingest()` should be test/load-test only — add a `FIXOPS_SIEM_LOAD_TEST=1` guard identical to the DPO cost-guard pattern. Ensure no production code path calls it without that env var. |

---

### ❌ MED — ML models trained exclusively on synthetic data serve production predictions without disclosure

| severity | file:line | engine/function | what's fabricated | suggested fix |
|----------|-----------|-----------------|-------------------|---------------|
| MED | `suite-core/core/ml/anomaly_detector.py:695-696` + `suite-core/core/behavioral_analytics_engine.py:42` | `AnomalyDetector.get_anomaly_detector()` singleton bootstrap | On first use (and at `behavioral_analytics_engine` module import), `fit_from_synthetic_baseline()` is called unconditionally. It generates 30 synthetic scans using `np.random.RandomState(self.random_seed)` with fabricated CVE IDs (`CVE-{rng.randint(2019,2026)}-{rng.randint(1000,99999)}`), fabricated asset names (`asset-{rng.randint(1,50)}`), and fixed severity distributions. The resulting IsolationForest model then scores all real customer scan findings against a baseline built from fake data. Anomaly scores surfaced in `BrainPipeline` and `BehavioralAnalyticsEngine` are calibrated against thin air. | Check for real historical scan data in the DB first; only fall back to synthetic if zero real scans exist, and in that case add `"baseline_source": "synthetic_bootstrap"` to every anomaly result. Ideally accept real scan history at `fit_baseline()` call time. |
| MED | `suite-core/core/ml/autofix_confidence.py:336-378` | `AutoFixConfidenceModel.train()` | Model is trained entirely on synthetic fix-outcome data generated by `np.random.RandomState(self.random_seed)`. The module docstring (line 30) says "Trained on synthetic but calibrated fix outcome data." This model then produces `autofix_confidence` scores consumed by `autofix_engine.py:1937-1939` for real auto-fix decisions. There is no disclosure in the prediction output that the underlying model has never seen a real fix outcome. | Add `"model_trained_on": "synthetic_bootstrap"` to prediction output until at least N real fix outcomes have been recorded. Wire to `LLMLearningLoop` / DPO pairs once available. |
| MED | `suite-core/core/ml/regression_predictor.py:583-604` | `RegressionPredictor.train()` | Same pattern: model trained on synthetic regression-probability data (random fix characteristics + analytically derived labels). The module-level `if __name__ == "__main__"` block (line 44-47) trains and saves the model to disk; any deployment that ships the pre-trained `.pkl` is serving predictions from a synthetic-only model. Downstream consumers see `regression_risk` scores for real code-fix proposals with no provenance disclosure. | Same as autofix_confidence: add `model_data_source` provenance field to predictions; retrain on real DPO/fix-outcome data when available. |

---

### 🟢 CONFIRMED LEGITIMATE — not fabrication (sweep 2 re-verified)

- 🟢 `integration_hub.py:1030` — `random.uniform(0, 0.5)` is jitter on exponential backoff. Correct.
- 🟢 `self_learning.py:1261` `seed_demo_data()` — gated behind `POST /demo/seed` with `_require_non_enterprise`. Not on any production read path; `"demo": True` context flag present on every record.
- 🟢 `executive_dashboard.py:539` `FAIREngine.run_simulation()` — FAIR Monte Carlo is the product function; stochastic sampling of user-supplied loss parameters is correct.
- 🟢 `executive_dashboard.py:695` `generate_synthetic_history()` method body — legitimate demo helper. The ❌ is the **router** calling it at startup (already recorded as #9028 in AUDIT WAVE 2).
- 🟢 `red_team_engine.py:254` — deterministic RNG seeded on `simulation_id + org_id`; red-team simulation outcomes are the product.
- 🟢 `risk_quantification_engine.py:295` — Monte Carlo on user-defined min/max/likelihood scenario parameters. Correct financial risk modelling.
- 🟢 `zero_gravity.py:227-229` — MinHash coefficient initialisation with `random.Random(42)`. Correct algorithm.
- 🟢 `zero_gravity.py:1741-1742` — `_weighted_choice` probabilistic sampler for capacity planning; sampler-by-design.
- 🟢 `single_agent.py:1305` — bootstrap resampling of confidence intervals. Correct statistics.
- 🟢 `monte_carlo.py:163` — `np.random.default_rng(seed)` for Monte Carlo simulation engine. Correct.
- 🟢 `breach_simulation.py:428` — seeded RNG for breach scenario simulation; simulation is the product.
- 🟢 `falkordb_client.py:279` — `random.sample` for graph health-check sampling. Correct.
- 🟢 `attack_graph_gnn.py:226` — fixed seed for GNN weight initialisation. Correct ML practice.
- 🟢 `siem_connector.py:1551` `generate_events()` standalone — the `/generate` route labels output as fixtures; no DB write on that code path.
- 🟢 `ml/consensus_calibrator.py:371`, `ml/attack_path_gnn.py:244`, `ml/online_learning.py`, `ml/predictive_scorer.py:220`, `ml/risk_scorer.py:400` — seeded RNG for model weight initialisation or cross-validation. Correct ML practice.
- 🟢 `models/markov_chain.py:260,275` — `np.random.choice` for Markov chain state transitions. Correct stochastic model.

---

**Summary**: 8 files grepped yielded real fabrications across 3 severity levels. Top 5 to fix first:
1. `executive_reports.py:404+426` — hash-derived compliance scores/control counts in board-level reports (CRITICAL, zero-effort to fix: call existing real engines).
2. `supply_chain_analyzer.py:158-161` — hash-derived `days_since_last_release` triggers medium-severity findings (HIGH, one PyPI JSON API call replaces the hash).
3. `iam_sso_connector.py:721-728` — synthetic Keycloak events written into production findings DB on Keycloak-absent deploys (HIGH, fix: skip `record_finding` writes when `fallback_synthetic=True`).
4. `siem_connector.py:1578` `generate_and_ingest()` — no env-var guard; synthetic SIEM events can reach the ingest pipeline (HIGH, add `FIXOPS_SIEM_LOAD_TEST=1` guard).
5. `ml/anomaly_detector.py:695-696` — IsolationForest baseline built from fabricated CVE/asset data, calibrates all real scan anomaly scores (MED, disclose `baseline_source` and prefer real history when available).


### Summary

| Category | Count | Multica issues |
|---|---|---|
| Engines scanned | 845 files | — |
| ❌ Fabrication (production default) | 8 | #9022–#9029 |
| 🟢 Legitimate (simulation IS the function) | 15 | — |
| ⚠️ Unsure | 0 | — |

**Prioritised ❌ fix order:**
1. `supply_chain_intel._score_package` (#9022) — every `analyze_package()` call persists hash-derived metadata as real; affects risk scoring for all packages.
2. `gcp_scc.get_findings/get_sources/get_assets` (#9023) — silent mock GCP findings on unconfigured deploy.
3. `github_security.get_*_alerts` (#9024) — silent mock GitHub alerts on unconfigured deploy.
4. `pagerduty_integration` 9/10 methods (#9025) — silent mock SOAR incidents/schedules/services on unconfigured deploy.
5. `semgrep_integration._run_semgrep` (#9026) — silent mock SAST results when binary absent.
6. `trivy_integration._run_trivy` + `trivy_scan_engine._run_trivy` (#9027) — silent mock container scan results when binary absent.
7. `executive_dashboard_router` startup seed (#9028) — 12 weeks of synthetic trend history served as real posture data.
8. `soar_engine._simulate_action` (#9029) — all SOAR executions are fabricated completions with no real dispatch.

---

## ENGINE SWEEP 4 — SCORING/VERDICT (2026-05-27)

**Scope**: All engines whose primary function emits customer-facing scores, verdicts, risk numbers, confidence values, or priorities. Target pattern: `*_scorecard`, `*_score*`, `risk_*`, `*_risk_*`, `*_prioritization`, `*_quantif`, `severity_*`, `*_rating`, `exploit*`, `epss*`, `kev*`, `cvss*`, `*_confidence`, `*_verdict`, `decision_*`, `consensus*`, `*_grade`.
**Method**: Deep-read (not grep). Every primary scoring/verdict method traced end-to-end — each input variable walked back to its source (SQLite DB query, live HTTP API call, caller-supplied parameter, or hardcoded constant). Monte Carlo stochasticity confirmed legitimate where used.
**Engines deeply read**: 22
**Skip list honoured**: security_scorecard, vendor_scorecard, vuln_prioritization_engine, ioc_enrichment_engine, material_change_detector, llm_council_real, council_pipeline_adapter, council_enhanced, brain_pipeline, executive_reports, executive_dashboard, supply_chain_analyzer, anomaly_detector, autofix_confidence, regression_predictor, llm_learning_loop, self_learning, mcp_gateway, security_health_engine, password_policy_engine, config_benchmark_engine, ccm_engine.

---

### Prioritized Ledger

| Sev | File:line | Engine.method | Score/Verdict emitted | Derived from real data? | Fix if fabricated |
|-----|-----------|---------------|-----------------------|------------------------|-------------------|
| **MEDIUM** | `suite-core/core/security_scorecard_engine.py:511` | `SecurityScorecardEngine.generate_scorecard` | `percentile_rank` (0–100) | **BORDERLINE** — hardcoded `50` default; no distinguishing flag in API response. `compare_to_benchmark()` does real interpolation when called, but `generate_scorecard()` never invokes it automatically. API consumers cannot distinguish this default from a real percentile. | Emit `"percentile_rank_source": "uncalibrated_default"` alongside any un-computed `percentile_rank = 50`, or omit the field until `compare_to_benchmark()` has been called for the org. |
| — | `suite-core/core/composite_risk_scorer.py:451` | `CompositeRiskScorer._compute` | Composite risk score (0–100) | **REAL** — `0.25*cvss + 0.20*epss + 0.20*kev + 0.15*asset_criticality + 0.10*sla + 0.10*lateral`; each term read from enriched_vulns / asset_inventory / sla_tracking / posture_snapshots SQLite. Fallbacks (CVSS→50, EPSS→10, KEV→0) documented in code. | — |
| — | `suite-core/core/asset_risk_calculator.py:230` | `AssetRiskCalculator.calculate_risk` | Asset risk score (0–100) | **REAL** — `vuln*0.35 + threat*0.25 + exposure*0.20 + compliance*0.20` over caller-supplied dimension scores; criticality multiplier applied. | — |
| — | `suite-core/core/asset_criticality_scorer.py:111` | `AssetCriticalityScorer._compute_score` | Asset criticality score | **REAL** — `base[asset_type] * dc_mult + internet_bonus + reg_bonus + dep_bonus`; all terms from registered asset profile. | — |
| — | `suite-core/core/exposure_scorer.py:205` | `ExposureScorer.calculate_org_exposure` | Org exposure score (0–100) | **REAL** — `0.70 * weighted_avg + 0.30 * (100 - velocity_score)`; critical findings weighted 2×; reads live `finding_scores` SQLite. Returns 0.0 honestly when no findings. | — |
| — | `suite-core/core/posture_score_engine.py:267` | `PostureScoreEngine.compute_posture_score` | Security posture score (0–100) | **REAL** — 8-component weighted sum; `_derive_vuln_mgmt_score()` reads open findings from `security_findings_engine.db` with `_SEVERITY_PENALTY` (critical=4.0, high=1.5, medium=0.4, low=0.05). Baseline 50 used only when no manual value AND findings DB unavailable (labeled). | — |
| — | `suite-core/core/threat_score_engine.py:190` | `ThreatScoreEngine.calculate_score` | Composite threat score (0–100) | **REAL** — `sum(signal_value * signal_weight) / sum(signal_weight)` over last 30 ingested signals from SQLite. Returns 0.0 honestly when no signals. | — |
| — | `suite-core/core/risk_quantification_engine.py:278` | `RiskQuantificationEngine.run_monte_carlo` | ALE / financial risk range | **REAL** — unseeded `random.Random()` Monte Carlo over user-supplied `(min_loss, max_loss, likelihood_pct)`. ALE = `(likelihood_pct/100) * (min+max)/2`. Legitimate stochastic financial simulation. | — |
| — | `suite-core/core/risk_quantification_engine_v2.py:221` | `RiskQuantificationEngineV2.create_scenario` | SLE / ALE / residual_ALE / BU risk | **REAL** — SLE=`asset_value*exposure_factor`; ALE=`SLE*ARO`; BU risk uses `_SEVERITY_PROFILE` × real findings × BU criticality multiplier. p95 via log-normal approximation (σ=0.4). Default BUs seeded idempotently on first call — legitimate bootstrap, not fabrication. | — |
| — | `suite-core/core/risk_prioritizer.py:378` | `RiskPrioritizer.score_finding` | Finding priority score (0–100) | **REAL** — `100 * (0.40*(cvss/10) + 0.25*epss + 0.20*kev + 0.15*asset_crit)`; EPSS from live `api.first.org` with 24h SQLite cache; KEV from CISA KEV URL with 6h in-memory refresh. Returns 0.0 for both on unavailability (honest, labeled). | — |
| — | `suite-core/core/threat_intelligence_confidence_engine.py:187` | `TIConfidenceEngine.score_ioc` / `_recompute_ioc_confidence` | IOC confidence (0–1) | **REAL** — initial: `source_confidence * reliability`; on corroboration update: `sum(confidence * reliability) / sum(reliability)`. Source reliability updated via real confirm/FP feedback. | — |
| — | `suite-core/core/exploit_signals.py:101` | `ExploitSignal.evaluate` | Exploit signal boolean/score | **REAL** — config-driven threshold/boolean evaluation over real CVE records; `ExploitFeedRefresher` fetches live CISA KEV + EPSS feeds and annotates records. | — |
| — | `suite-core/core/risk_aggregator_engine.py:292` | `RiskAggregatorEngine.calculate_org_risk_score` | Org risk score (0–100) | **REAL** — mean of latest per-entity scores; brain-graph sync uses non-linear CVSS→risk amplification (`≥9.0→95, ≥7.0→70+, ≥4.0→30+`) × `_SEV_MULT` × exposure_mult; integrates real VulnerabilityScoringEngine records. | — |
| — | `suite-core/core/awareness_score_engine.py:315` | `AwarenessScoreEngine.calculate_score` | Security awareness score (0–100) | **REAL** — `training_score = (passed/total*70) + (avg_score/100*30)`; `phishing_resistance = 100 - (clicked/total*100)`; `overall = training_score*0.6 + phishing_resistance*0.4`. All inputs from real SQLite training/phishing tables. | — |
| — | `suite-core/core/security_scoreboard_engine.py:256` | `SecurityScoreboardEngine.submit_score` | Gamification score (integer) | **REAL** — integer accumulator of challenge points; wins/losses from `points_earned >= max_points/2`. Gamification is the product function. | — |
| — | `suite-core/core/security_scorecard_engine.py:147` | `SecurityScorecardEngine.create_scorecard` — `overall_score` | Overall scorecard score | **REAL** — `weighted_sum / total_weight` across caller-supplied dimension scores. | — |
| — | `suite-core/core/llm_consensus.py:151` | `LLMConsensus.analyse` / `_vote` | LLM consensus verdict + confidence | **REAL** — calls real LLM providers in parallel; weighted majority voting; confidence = weighted average of real provider confidences. Fallback only when ALL providers fail, labeled `[ALL providers failed]`. | — |
| — | `suite-core/core/risk_register_engine.py:136` | `RiskRegisterEngine.create_risk` | Risk score (1–25) | **REAL** — standard OWASP/ISO 31000 matrix: `_LIKELIHOOD_VALUES[likelihood] * _IMPACT_VALUES[impact]` (1–5 × 1–5). Inputs are operator-supplied enums. | — |
| — | `suite-core/core/supply_chain_risk_engine.py` | *(data store)* | severity / risk_tier | **REAL** (data store) — severity/risk_tier are caller-supplied; no auto-score computation in primary paths. | — |
| — | `suite-core/core/vulnerability_scoring_engine.py:221` | `VulnerabilityScoringEngine.score_vulnerability` | Vuln score (0–100) | **REAL** — `(cvss_norm*cw + epss_norm*ew + kev_val + exp_norm*exposure_w) * criticality_mult * 100`; configurable weights per org from DB; `factor_blast_radius()` adds `blast_radius*0.15` with 1.25 crown-jewel multiplier. | — |
| — | `suite-core/core/security_health_scorecard_engine.py:234` | `SecurityHealthScorecardEngine.take_snapshot` | Health snapshot score (0–100) | **REAL** — `sum(score/max_score * weight) / sum(weights) * 100` over real domain rows; status auto-computed from ratio (green≥80%, amber≥60%, red<60%). | — |
| — | `suite-core/core/identity_risk_engine.py` | `IdentityRiskEngine` | Identity risk score | **REAL** — stores caller-supplied risk_score; `_risk_level_from_score()` maps to tier; `record_risk_factor()` stores caller-supplied score_impact (0–50 capped). Caller must explicitly invoke `update_risk_score()` to aggregate factors. | — |
| 🟢 | `suite-core/core/openclaw_engine.py:604` | `OpenClawEngine.start_campaign` | *(raises NotImplementedError)* | **HONEST stub** — module docstring explicitly marks engine NOT PRODUCTION READY; `start_campaign()` raises `NotImplementedError`; `_simulate_tasks` is unreachable in production. Module emits WARNING log on import. | — |

---

### Summary

| Category | Count |
|----------|-------|
| Engines deeply read | 22 |
| Hard fabrications (score from constant/hash, no real input) | **0** |
| Borderline (real formula but one sub-field defaults to constant without API disclosure) | **1** |
| Legitimate / REAL | 20 |
| Legitimate honest stubs (NotImplementedError + warning) | 1 |

**Single finding requiring action**:

- **MEDIUM — `suite-core/core/security_scorecard_engine.py:511`** — `generate_scorecard()` sets `percentile_rank = 50` unconditionally and returns it in the API response with no distinguishing flag. API consumers cannot distinguish this default from a real percentile. Fix: emit `"percentile_rank_source": "uncalibrated_default"` alongside any `percentile_rank` that was not computed by `compare_to_benchmark()`, or suppress the field entirely until benchmark data is available for the org.

**Convergence status after 4 sweeps**: The mathematical scoring layer is clean. All composite formulas, weighted averages, and CVSS/EPSS/KEV integrations trace to real inputs. Remaining fabrication risk is concentrated in integration connectors (Sweeps 2–3, still unresolved), SOAR execution (#9029), and ML synthetic baselines (Sweep 2) — not in the scoring/verdict layer. Sweep 4 closes with a single medium-severity disclosure gap, zero hard fabrications.

---

## ROUTER AUDIT (2026-05-27)

**Scope:** 798 router files in `suite-api/apps/api/` (`*_router.py` + `*_routes.py`).
**Method:** Multi-pass grep + Python AST scan for: module-level `_MOCK_`/`_DEMO_`/`_SAMPLE_` constants returned to callers; route handlers returning hardcoded list/dict literals with no engine delegation; silent demo fallbacks when real data is absent; `random.*`/`uuid4()` generating fabricated response values; hardcoded fake identifiers in production response paths.
**Exclusions (🟢):** static config/capability lists (enum option lists, provider capability manifests, MITRE ATT&CK knowledge references, scan profile definitions, tier info, health/status probes); legitimate sample/ingest endpoints that are explicitly named and gated; seed-demo endpoints gated by `_require_non_enterprise()` or `Depends`; test-fire payloads clearly labeled `"test_fire": true`.

### Counts

| Classification | Count |
|---|---|
| Routers scanned | 798 |
| ❌ INLINE-FABRICATION (returns hardcoded data to client, no engine) | 3 |
| 🟡 PARTIAL (delegates to engine but silently falls back to hardcoded demo data when result is empty) | 2 |
| 🟢 REAL (delegates to engine/db or is legitimate static config) | 793 |

### ❌ INLINE-FABRICATION — 3 routers

| Router | Line | Fabricated symbol / return | Engine it SHOULD call |
|---|---|---|---|
| `evidence_router.py` | L565–567 | `_get_demo_bundles()` — 4 hardcoded compliance bundles (EVB-2026-001/002/003, EVB-2025-042) returned as real bundle listing when no disk manifests found | `EvidenceEngine` / real bundle DB; should return empty list or 404 with onboarding message |
| `evidence_router.py` | L878–900 | `_get_demo_bundles()` — same 4 fake bundles used to synthesise a fake "download" response (sections, finding_count, remediation_count) when no physical bundle file exists | Same — should 404 or stream a real generated bundle |
| `knowledge_graph_router.py` | L418–L500+ (inside `POST /seed-demo`) | 20 hardcoded VULN-001…VULN-020 entries with fabricated CVEs (`CVE-2025-44123`, `CVE-2025-31001` etc.), fabricated EPSS scores, and fabricated KEV flags seeded into the live knowledge graph via `POST /seed-demo` with no enterprise-mode gate at the **router** level (gate exists but only blocks `FIXOPS_MODE=enterprise`; any other deploy accepts the endpoint) | Endpoint is correctly named "seed-demo" but inserts fabricated CVEs into the production knowledge graph — gate should also require an explicit `ALDECI_DEMO_KEY` or be restricted to `FIXOPS_MODE=demo` only |

**Evidence detail:**

- ❌ **evidence_router** `list_compliance_bundles` (`L529–568`) / `download_compliance_bundle` (`L870–900`)
  - File: `suite-api/apps/api/evidence_router.py:114,117,565,567,878`
  - Evidence: `_DEMO_SIGNED_BUNDLES = {"EVB-2026-001", "EVB-2026-003"}` at L114; `_get_demo_bundles()` at L117 returns 4 hardcoded bundle dicts with fabricated `finding_count`, `remediation_count`, `hash`, `sections`. Called at L565: `if not bundles: bundles = _get_demo_bundles()` — any fresh/unconfigured deploy with no manifest directory returns these 4 demo bundles as real compliance evidence to every `GET /bundles` caller. Also called at L878 to fabricate a download response for the same fake bundle IDs.
  - Gate: Only triggered when `manifest_dir` is absent or empty (the common case on any new install). No `is_demo` flag in the response — clients receive `"status": "signed"`, `"signature_valid": true` for fabricated bundles.
  - Engine it SHOULD call: Real bundle manifest files in `FIXOPS_DATA_DIR` / compliance DB. When empty → return `{"bundles": [], "total": 0}` not demo data.
  - Multica: **#9034**

- ❌ **evidence_router** `verify_bundle_signature` (`L1008–1020`)
  - File: `suite-api/apps/api/evidence_router.py:1008–1020`
  - Evidence: `if safe_id in _DEMO_SIGNED_BUNDLES: return BundleVerificationResult(valid=True, hash_match=True, signature_valid=True, ...)` — for IDs `EVB-2026-001` and `EVB-2026-003`, the verification endpoint unconditionally returns `valid=True` with a fabricated certificate chain (`"ALdeci Trust Services"`) without performing any cryptographic verification.
  - Gate: Unconditional for those two IDs — no env var, no crypto check.
  - Engine it SHOULD call: `RSAVerifier` (already imported in the same file at L35). Real verification path exists at L990–1004 but is bypassed for the demo IDs.
  - Multica: **#9034** (same issue as above)

- ❌ **knowledge_graph_router** `seed_demo_data` (`POST /seed-demo`, L315–500+)
  - File: `suite-api/apps/api/knowledge_graph_router.py:418–500+`
  - Evidence: 20 hardcoded findings `VULN-001`…`VULN-020` with fabricated CVEs (e.g. `CVE-2025-44123`, `CVE-2025-31001`, `CVE-2025-19234`), fabricated EPSS scores (e.g. `0.94`, `0.72`), and fabricated KEV booleans are inserted into the live FalkorDB knowledge graph. Once seeded, these appear as real findings in `/attack-paths`, `/blast-radius`, `/analytics` endpoints.
  - Gate: `_require_non_enterprise()` only blocks `FIXOPS_MODE=enterprise`. Any deploy in `dev`/`staging`/unconfigured mode can hit this endpoint. No `ALDECI_DEMO_KEY` requirement.
  - Engine it SHOULD call: Not a real fix needed — endpoint is correctly scoped as demo. Fix: tighten gate to require `FIXOPS_MODE=demo` explicitly OR add explicit opt-in param; add `"is_demo": true` marker to all seeded nodes.
  - Multica: **#9034**

### 🟡 PARTIAL — 2 routers (delegate to engine but have hardcoded fallback)

| Router | Line | Pattern | Note |
|---|---|---|---|
| `crowdstrike_falcon_router.py` | L161–169 | `GET /sample` returns `FALCON_SAMPLE_DETECTIONS` (10 hardcoded detections from connector) to any caller | Explicitly named `/sample` endpoint; connector also has real `/ingest` path. 🟡 because the endpoint is purposefully named but returns connector-internal sample data as an API response — no `is_sample` flag, no auth beyond api_key |
| `executive_dashboard_router.py` | L60 (module import) | `_trend_analyser.generate_synthetic_history(weeks=12, seed=42)` called unconditionally at startup | Already tracked as ❌ #9028 in Wave 2 (engine audit). Listed here for completeness — the **router** seeds the engine at import time. |

### 🟢 LEGITIMATE — confirmed clean patterns (not re-listed individually)

The following patterns appeared in the broad scan but are **NOT fabrication**:

- **Health/status probes** (`return {"status": "healthy", "engine": "X"}`) — 80+ routers — static operational metadata, not client data.
- **Static capability lists** (`list_scan_profiles`, `list_attack_vectors`, `list_scan_modes`, `list_providers`, `list_node_types`, `get_tier_info`, `list_experts`) — enum-derived or hardcoded product-capability manifests. Correct to be static.
- **MITRE ATT&CK knowledge** (`feeds_router.py:438` `_MITRE_TECHNIQUES`) — 12 static ATT&CK v15.1 technique records used as a searchable reference. Not fabricated findings.
- **Test-fire webhook payloads** (`webhook_notifications_router.py:563`) — `"test_fire": true` flag present in all payloads; `"finding_id": "test-finding-001"` / `"CVE-2024-99999"` are clearly labeled test data. Not a production finding path.
- **Seed-demo endpoints properly gated** (`self_learning_router.py POST /demo/seed`, `knowledge_graph_router.py POST /seed-demo`) — explicitly tagged `tags=["demo"]`, gated by `_require_non_enterprise()`. The router endpoint itself is legitimate; the ❌ finding above is about insufficient gate strength.
- **Commercial vendor `/sample` endpoints** (`commercial_vendor_router.py`) — return connector-embedded sample payloads for integration testing. Correctly named and scoped.
- **`changelog_router.py`** — all handlers delegate to `ChangelogGenerator` (reads real git log via `subprocess`). Static `list_formats` return is a capability manifest.
- **`version_router.py`**, **`versioning_router.py`** — return live version data (`_git_commit()`, `_build_date()`) and API versioning manager delegation. Not fabricated.
- **`audit_router.py GET /retention`** (L494) — returns a static policy specification (365 days / AES-256-GCM). This is a config declaration, not fabricated operational data.
- **`breach_simulation_router.py GET /scenarios`** — iterates `AttackScenario` enum + calls `get_breach_simulator().get_scenario_steps(s)`. Engine delegation present.
- **`llm_router.py GET /providers`** — hardcoded provider capability manifest (model IDs, feature flags, env var names). Static product config, not fabricated security data.

### Summary

| Category | Count | Multica |
|---|---|---|
| Routers scanned | 798 | — |
| ❌ Inline fabrication (production default returns fake data) | 3 findings across 2 files | #9034 |
| 🟡 Partial (explicit sample endpoint / known startup seed) | 2 | #9028 (already tracked) |
| 🟢 Real / legitimate static config | 793 | — |

**Prioritised ❌ fix order:**
1. `evidence_router` `verify_bundle_signature` (#9034) — fabricated `valid=True` + fake cert chain for known demo IDs undermines trust in cryptographic evidence verification.
2. `evidence_router` `list_compliance_bundles` / `download_compliance_bundle` (#9034) — demo bundles silently served as real compliance evidence on any unconfigured deploy.
3. `knowledge_graph_router` `seed_demo_data` gate (#9034) — tighten from `FIXOPS_MODE != enterprise` to `FIXOPS_MODE == demo` to prevent accidental demo seeding in staging/prod.

## DOGFOODING FINDING (2026-05-27) — ingest under-reporting

Ran a REAL bandit self-scan of suite-core+suite-api (1636 findings / 683 files / 18 rule_ids,
4 HIGH 58 MED 1574 LOW) and ingested via POST /api/v1/scanner-ingest/upload. Discovered the
endpoint reported findings_count:1636 but persisted only ~18: `_promote_findings_to_issues`
built correlation_key as `scanner|rule_id|asset_id`, and asset_id was the app-level "aldeci-self"
(shared by all findings), so SecurityFindingsEngine.record_finding deduped 1636 distinct
file:line findings down to one-per-rule. A security product silently hiding 99% of real findings
= critical under-reporting (inverse of fabrication, equally bad). SmartDedup was INNOCENT
(returned all 1636 canonical). FIXED (commit 68c21bce): corr_key now file_path:line_number
(then package@version, then asset_id). Proven OLD=18 -> NEW=1633 distinct keys; 87 ingest/findings
tests green. NOTE: local dev API (PID 46586) still runs old `--factory` code — restart with
preserved FIXOPS_API_TOKEN + FIXOPS_DATA_DIR=.fixops_data to re-ingest and populate dashboards live.

### RESOLVED (2026-05-27) — ingest under-reporting, LIVE-verified
Root cause was SmartDedup.find_fuzzy_title_matches merging by title-similarity with no location
check (_extract_title falls back to rule_id), collapsing 1636 distinct-location findings to 8.
Fixed (commit 74fca158): location-aware fuzzy-title (never merge different file:line) + record_finding
skips coarse (title,asset) fallback when an explicit correlation_key is given + scanner-ingest
corr_key is file:line granular (68c21bce). LIVE PROOF: re-ingested real bandit self-scan ->
findings 780->2079 (+1299), bandit 19->1318 (was collapsing to ~18). Beast Mode 756/756. Lesson:
logic-proof was insufficient (a 2nd dedup layer existed); LIVE re-ingest caught it.

### RESOLVED (2026-05-27) — dependency-finding dedup over-collapse, LIVE-verified
#9050: trivy dep findings (no file line) collapsed 168 distinct (cve,pkg,ver) -> 89. Root
cause (diagnosed per-strategy): find_same_location merged ALL line-less findings in a lockfile
((0,0) ranges "overlap" within tolerance). Fix (commit 9a79d1a3, 3 coordinated): same_location
skips (0,0)-line findings; _find_component_version_matches keys on package@version|CVE (was
pkg@ver alone -> collapsed distinct CVEs); _extract_component_version recognises package_name
(enables comp_version to collapse TRUE dup (cve,pkg,ver) across worktree copies). LIVE PROOF:
re-ingest trivy -> findings 9 -> 159 (~true distinct 168); bandit 1307 + semgrep 70 unchanged
(code findings, real lines). grand total 2308 real self-scan findings. 125 dedup tests pass.

### SECRET AUDIT COMPLETE (2026-05-27) — only 1 real leak
Scoped trivy self-scan secret findings triaged (each classified by entropy + placeholder markers + JWT-payload decode):
- mytoken.txt: REAL GitHub fine-grained PAT -> untracked+gitignored (4a74a438), REVOKE on GitHub (#9054, in history).
- scripts/ctem_*demo*.{py,sh} github-pat: PLACEHOLDERS (ghp_xxx.../ghp_ABCDEFG, entropy 0.7-5.2 with xxx/ABC markers).
- slack webhooks in demo scripts: example hooks.slack.com URLs (placeholder).
- ctem_demo_004.sh "stripe secret": Stripe public docs example key (4eC39Hq...).
- scripts/populate_multica.py JWT: EXPIRED (2026-05-17) LOCAL Multica admin token (beast@aldeci.io, HS256, localhost single-user) — low risk; minor hygiene: read from env not hardcode.
- data/keys/*.pem,*.ed25519: gitignored runtime signing keys (not leaked).
Conclusion: 1 real leak (handled), rest fixtures/expired-local. Secret hygiene of the repo is otherwise clean.
