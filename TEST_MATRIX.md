# TEST_MATRIX.md — ALdeci / Fixops
> Generated 2026-05-27. Source of truth for test landscape, gates, and feature→test mapping.

---

## 1. REAL TEST LANDSCAPE

| Metric | Value | Source |
|--------|-------|--------|
| Test files | **1,426** | `find tests/ -name "test_*.py" \| wc -l` |
| Collected tests | **45,496** | `pytest tests/ --collect-only -q` (0 errors) |
| Collection errors | **0** | Fixed 2026-05-27 (was 4) |

> **CLAUDE.md correction**: CLAUDE.md previously claimed "327 test files / 756 Beast Mode tests".
> The correct figures are 1,426 files and 45,496 collectable tests.
> The 756-test "Beast Mode" count refers only to the 13-file canonical smoke set (see T1 below).

---

## 2. TIERED GATE STRATEGY

### T1 — CHANGE-GATE (fast, every PR / every change)
Run after every code change. Must be green before any commit lands.
Covers: 13-file Beast Mode smoke (756 tests) + 20 session real-behaviour files (692 tests).
Total: ~1,448 tests, typically finishes in under 90 seconds.

**Command:**
```bash
PYTHONPATH=/Users/devops.ai/fixops/Fixops python -m pytest \
  tests/test_phase2_connectors.py \
  tests/test_phase3_llm_council.py \
  tests/test_phase4_integration.py \
  tests/test_phase5_enterprise.py \
  tests/test_phase6_streaming.py \
  tests/test_phase7_analytics.py \
  tests/test_phase8_mcp.py \
  tests/test_phase9_playbooks.py \
  tests/test_phase10_e2e.py \
  tests/test_connector_framework.py \
  tests/test_trustgraph.py \
  tests/test_pipeline_api.py \
  tests/test_persona_workflows.py \
  tests/test_security_scorecard_engine.py \
  tests/test_vendor_scorecard.py \
  tests/test_ccm_engine.py \
  tests/test_cloud_drift_engine.py \
  tests/test_compliance_scanner_engine.py \
  tests/test_config_benchmark_engine.py \
  tests/test_kubernetes_security_engine.py \
  tests/test_ioc_enrichment_engine.py \
  tests/test_openclaw_index_wired.py \
  tests/test_trustgraph_finding_correlation.py \
  tests/test_llm_learning_loop_honesty_guard.py \
  tests/test_pipeline_council_real_wiring.py \
  tests/test_material_change_council_consumption.py \
  tests/test_azure_defender.py \
  tests/test_cloud_discovery_honesty.py \
  tests/test_integration_health.py \
  tests/test_secret_scanner_engine.py \
  tests/test_ai_orchestrator_backends.py \
  tests/test_simulated_engines_flagged.py \
  tests/test_e2e_real_vertical_slice.py \
  -x --tb=short --timeout=10 -q -o "addopts="
```

**Sub-groups within T1:**

Beast Mode smoke (13 files, 756 tests):
```
test_phase2_connectors  test_phase3_llm_council  test_phase4_integration
test_phase5_enterprise  test_phase6_streaming    test_phase7_analytics
test_phase8_mcp         test_phase9_playbooks    test_phase10_e2e
test_connector_framework  test_trustgraph        test_pipeline_api
test_persona_workflows
```

Session real-behaviour (20 files, 692 tests — engines made real, see §4):
```
test_security_scorecard_engine    test_vendor_scorecard
test_ccm_engine                   test_cloud_drift_engine
test_compliance_scanner_engine    test_config_benchmark_engine
test_kubernetes_security_engine   test_ioc_enrichment_engine
test_openclaw_index_wired         test_trustgraph_finding_correlation
test_llm_learning_loop_honesty_guard  test_pipeline_council_real_wiring
test_material_change_council_consumption  test_azure_defender
test_cloud_discovery_honesty      test_integration_health
test_secret_scanner_engine        test_ai_orchestrator_backends
test_simulated_engines_flagged    test_e2e_real_vertical_slice
```

---

### T2 — COLLECTION-HEALTH (must always be green)
Proves the suite is syntactically importable with zero collection errors.
Cheap: no tests execute, only import + discovery runs.

**Command:**
```bash
PYTHONPATH=/Users/devops.ai/fixops/Fixops python -m pytest tests/ --collect-only -q -o "addopts=" 2>&1 | tail -3
# Expected: "45496 tests collected in Xs" with no ERROR lines
```

**Gate rule**: ANY collection error = BLOCK. Fix before merging.
**Current status**: 0 errors, 45,496 collected (verified 2026-05-27).

---

### T3 — BROAD REGRESSION (periodic / CI nightly)
Full collectable suite. Identifies regressions in legacy modules and newly added tests.
Runtime: several minutes. Run nightly or before releases.

**Command:**
```bash
PYTHONPATH=/Users/devops.ai/fixops/Fixops python -m pytest tests/ \
  --timeout=10 -q -o "addopts=" 2>&1 | tee /tmp/broad_regression.txt
```

**Triage protocol for T3 failures:**
- Failure in a T1 file → BLOCKER, fix immediately.
- Failure in a legacy file not in T1 → triage: is the engine still live?
  If engine is retired: add `pytestmark = pytest.mark.skip(reason="engine retired")`.
  If engine is live but test has outdated assumptions: fix the test or the engine.
- Never suppress a failure without a written reason in the skip marker.

---

## 3. COLLECTION ERROR FIXES (2026-05-27)

Four files blocked `pytest --collect-only` with errors that aborted the entire run.
Each fix is an honest guard — no real coverage was deleted, no test was weakened.

### Error 1: `tests/test_demo_seeder.py`
**Root cause**: `scripts/seed_demo_data.py` was rewritten under the repo "no-demo-data"
policy. The new version exposes only `main()`. The test file accessed `_mod.seed_posture`
at module level (line 38), raising `AttributeError` before any test could be collected.

**Fix**: Wrapped the entire module-level seeder import in `try/except`. When the
per-engine helpers are absent (`seed_posture`, `seed_threat_feeds`, etc.), `pytestmark`
is set to `skip` with a clear reason and stub callables are bound so the rest of the
module parses without `NameError`. Tests are collected but immediately skipped.

**Why not deleted**: The tests are structurally valid. If the per-engine seeder API is
ever restored, removing the `if _SKIP_REASON:` guard re-enables them with zero changes.

---

### Error 2: `tests/real_world_tests/conftest.py`
**Root cause**: `pytest_configure()` called `pytest.exit()` unconditionally when the
live deployment was unreachable or `ALDECI_API_KEY` was unset. `pytest.exit()` at
collection time aborts the entire run, not just the subdirectory.

**Fix**: Replaced `pytest.exit()` with a no-op return in `pytest_configure()`.
Added `_LIVE_DEPLOY_REQUESTED` flag gated on env vars (`FIXOPS_LIVE_DEPLOY_URL`,
`ALDECI_BASE_URL`, `FIXOPS_BASE_URL`). Rewrote `pytest_collection_modifyitems()` to
apply `pytest.mark.skip` to each item in `real_world_tests/` when the deployment is
not reachable — so tests are collected and skipped, never aborting the suite.

**To run these tests**:
```bash
FIXOPS_LIVE_DEPLOY_URL=http://localhost:8000 ALDECI_API_KEY=<token> pytest tests/real_world_tests/
```

---

### Error 3: `tests/test_nvd_summary_endpoint.py`
**Root cause**: The file hardcoded the absolute path to `nvd_cve_router.py`. That router
was deleted from `suite-api/apps/api/` (only a stale `.pyc` remains in `__pycache__`).
`spec_from_file_location` raised `FileNotFoundError` at module import.

**Secondary problem**: This file also injected a minimal stub into
`sys.modules["apps.api.auth_deps"]` — without `verify_api_key` — which then caused
`test_risk_scoring_router_smoke.py` to fail with `ImportError: cannot import name
'verify_api_key' ... (unknown location)` when collected after it in the full suite.

**Fix**: Added a `Path(_ROUTER_PATH).exists()` guard at the top. When the source file
is absent, `pytestmark = skip` is set immediately and the `sys.modules` stub injection
is skipped entirely — preventing the cascade failure in Error 4. When the source file
exists, the original behavior is preserved exactly.

---

### Error 4: `tests/test_risk_scoring_router_smoke.py`
**Root cause**: Not an independent bug — it was a **cascade from Error 3**. When
`test_nvd_summary_endpoint.py` ran first in the full suite collection, it injected a
stub `apps.api.auth_deps` into `sys.modules` without `verify_api_key`. When
`test_risk_scoring_router_smoke.py` then did `from apps.api.auth_deps import verify_api_key`,
Python found the stale stub (`(unknown location)`) and raised `ImportError`.

**Primary fix**: Fixing Error 3 eliminates the stub injection, so Error 4 resolves
automatically in the normal case.

**Defensive fix**: Added a `sys.modules` eviction guard at the top of
`test_risk_scoring_router_smoke.py`: if `apps.api.auth_deps` is cached but lacks
`verify_api_key`, it is evicted before the import runs. This makes the file robust
against any future `sys.modules` pollution from other test files.

**Verified**: File collects 8 tests in isolation AND in the full suite after fixes.

---

## 4. FEATURE → TEST MAP (engines modified in current branch)

These 10 engine files appear as `M` (modified) in `git status` on branch
`chore/ui-prune-plan-2026-05-24`. Each has a corresponding test file in T1.

| Engine file | Test file | What it proves |
|-------------|-----------|----------------|
| `suite-core/core/security_scorecard.py` | `tests/test_security_scorecard_engine.py` | Org security score computation, grade bands, history snapshots, trend detection |
| `suite-core/core/vendor_scorecard.py` | `tests/test_vendor_scorecard.py` | Third-party vendor risk scoring, questionnaire ingestion, score aggregation |
| `suite-core/core/ccm_engine.py` | `tests/test_ccm_engine.py` | Continuous controls monitoring — control status tracking, drift detection, alerting |
| `suite-core/core/cloud_drift_engine.py` | `tests/test_cloud_drift_engine.py` | Cloud configuration drift detection, baseline comparison, remediation suggestions |
| `suite-core/core/compliance_scanner_engine.py` | `tests/test_compliance_scanner_engine.py` | Compliance framework scanning (SOC2/PCI/ISO), control assessment, gap reporting |
| `suite-core/core/config_benchmark_engine.py` | `tests/test_config_benchmark_engine.py` | CIS/NIST benchmark evaluation, pass/fail per control, remediation guidance |
| `suite-core/core/kubernetes_security_engine.py` | `tests/test_kubernetes_security_engine.py` | K8s RBAC analysis, pod security, network policy gaps, CIS K8s benchmark |
| `suite-core/core/ioc_enrichment_engine.py` | `tests/test_ioc_enrichment_engine.py` | IOC lookup and enrichment (IP/domain/hash), threat intel correlation, confidence scoring |
| `suite-core/core/openclaw_engine.py` | `tests/test_openclaw_index_wired.py` | OpenClaw self-scan index wiring — proves scanner output is indexed into TrustGraph |
| `suite-core/connectors/iam_sso_connector.py` | `tests/test_iam_sso_connector.py` | IAM/SSO connector — identity provider sync, user/role ingestion, session validation |

**Additional real-behaviour coverage for session context:**

| Test file | Engine / area | What it proves |
|-----------|--------------|----------------|
| `test_trustgraph_finding_correlation.py` | TrustGraph | Findings are correlated through the knowledge graph, not just stored flat |
| `test_llm_learning_loop_honesty_guard.py` | LLM learning loop | DPO pair capture is real; guard rejects stub/mock training pairs |
| `test_pipeline_council_real_wiring.py` | Brain Pipeline + Council | 12-step pipeline invokes real multi-LLM council, not a mock |
| `test_material_change_council_consumption.py` | Council | Material changes trigger council escalation with real model calls |
| `test_azure_defender.py` | Azure Defender connector | Real connector pulls findings from Azure Defender API schema |
| `test_cloud_discovery_honesty.py` | Cloud discovery | Cloud asset discovery returns real assets, not seeded/stubbed data |
| `test_integration_health.py` | Integration health | All wired integrations report real health status |
| `test_secret_scanner_engine.py` | Secrets scanner | Secret detection returns real findings with match context |
| `test_ai_orchestrator_backends.py` | AI orchestrator | Backend routing to OpenRouter/Anthropic is real, unknown backends raise ValueError |
| `test_simulated_engines_flagged.py` | Simulation guard | Engines that return simulated data are flagged — not silently passed as real |
| `test_e2e_real_vertical_slice.py` | End-to-end | Full pipeline slice: ingest → brain → council → evidence, all real |

---

## 5. SKIPPED TEST FILES (honest skips, with reasons)

These files collect but all tests are immediately skipped. They are NOT deleted because
the underlying logic may be valid once dependencies are restored.

| File | Skip reason |
|------|-------------|
| `tests/test_demo_seeder.py` | `scripts/seed_demo_data.py` rewritten — per-engine helpers removed under no-demo-data policy |
| `tests/real_world_tests/*.py` (113 tests) | Live deployment not configured — set `FIXOPS_LIVE_DEPLOY_URL` + `ALDECI_API_KEY` to run |
| `tests/test_nvd_summary_endpoint.py` | `suite-api/apps/api/nvd_cve_router.py` deleted (stale `.pyc` only) — restore source to re-enable |

---

## 6. HOW TO KEEP THIS MATRIX ACCURATE

1. After adding a new engine, add its test file to the T1 command and to §4.
2. After deleting/retiring an engine, add a `pytestmark = skip(reason=...)` to its test
   file — never delete the test file without a written reason.
3. After any refactor that renames an endpoint or moves a file, re-run T2 first to
   catch new collection errors before they reach CI.
4. The collected count (45,496) will grow as new tests are added. Update this file
   after each sprint to keep the "Real Test Landscape" table accurate.
5. Never use `assert True`, `@pytest.mark.skip("TODO")`, or full-function mocks as
   a way to inflate counts — the purpose of this matrix is to prove real behaviour.
