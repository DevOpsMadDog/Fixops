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
