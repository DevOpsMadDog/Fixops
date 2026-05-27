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

No candidates remained unresolvable after reading caller + gate.

---

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
