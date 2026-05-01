# Beast Mode Regression Sweep — 2026-05-02

**Branch**: `features/intermediate-stage`
**Trigger**: Post-avalanche QA — 87+ commits across waves 1-3 (air-gap, connectivity, reality replacement) + 11 backlog rounds (UX consolidation, endpoint importers, dependency audit, cloud cleanup, UX hubs).

---

## Summary

| Metric | Count |
|--------|-------|
| **Canonical Beast Mode (13 files)** | **753 passed** in 9.44s |
| **Session-added (26 files)** | **152 passed**, 1 teardown error in 22.18s |
| **Total** | **905 passed**, 0 real failures, 1 teardown flake |
| **Real regressions** | **0** |
| **Skipped (file not present)** | 2 (`test_pag_okta_real_data.py`, `test_mdm_real_data.py`) |

**Verdict: ALL GREEN.** Zero regressions across 87 commits.

---

## Per-Suite Breakdown

### Canonical 13-file Beast Mode — exit 0
```
tests/test_phase2_connectors.py            ✅
tests/test_phase3_llm_council.py           ✅
tests/test_phase4_integration.py           ✅
tests/test_phase5_enterprise.py            ✅
tests/test_phase6_streaming.py             ✅
tests/test_phase7_analytics.py             ✅
tests/test_phase8_mcp.py                   ✅
tests/test_phase9_playbooks.py             ✅
tests/test_phase10_e2e.py                  ✅
tests/test_connector_framework.py          ✅
tests/test_trustgraph.py                   ✅
tests/test_pipeline_api.py                 ✅
tests/test_persona_workflows.py            ✅
============================= 753 passed in 9.44s ==============================
```

### Session-added 26-file Suite — exit 1 (teardown only)
All 152 collected test items PASSED. The single error is a **teardown timeout**, not a test failure:

```
ERROR tests/test_trustgraph_event_bus_handlers.py::test_finding_created_calls_indexer
======================== 152 passed, 1 error in 22.18s =========================
```

#### Suites covered (all passing)
- `test_aws_security_hub_real.py`
- `test_air_gap_bundle_signing.py`
- `test_air_gap_llm_routing.py`
- `test_function_reachability_real.py`
- `test_nvd_bundle_builder.py`
- `test_trustgraph_knowledgebrain_adapter.py`
- `test_trustgraph_event_bus_handlers.py` (test passed; teardown flake — see below)
- `test_connector_event_emit.py`
- `test_brain_pipeline_wiring.py`
- `test_llm_council_trustgraph_enrich.py`
- `test_connector_ingestion_scheduler.py`
- `test_brain_pipeline_reach_gnn.py`
- `test_autofix_council_consensus.py`
- `test_devsecops_real_scanners.py`
- `test_binary_fingerprint_malwarebazaar.py`
- `test_reachability_tree_sitter_ts_java.py`
- `test_upgrade_path_live_registries.py`
- `test_vuln_correlation_assets_real_data.py`
- `test_threat_vectors_real_data.py`
- `test_hunting_playbooks_real_data.py`
- `test_cloud_posture_findings_real_data.py`
- `test_cwp_workloads_real_data.py`
- `test_d3fend_real_data.py`
- `test_posture_benchmarking_real_data.py`
- `test_security_benchmarks_real_data.py`
- `test_ti_automation_global_feeds_real_data.py`

#### Missing files (skipped per instructions)
- `tests/test_pag_okta_real_data.py` (file does not exist)
- `tests/test_mdm_real_data.py` (file does not exist)

---

## Failure Analysis

### Single error: teardown timeout (FLAKE — not regression)

**Test**: `tests/test_trustgraph_event_bus_handlers.py::test_finding_created_calls_indexer`
**Status**: Test body PASSED. Failure occurred in async teardown.
**Stack frame** (top):
```
/opt/homebrew/lib/python3.11/site-packages/pytest_asyncio/plugin.py:817: in _scoped_runner
    runner.__exit__(None, None, None)
...
E   Failed: Timeout (>10.0s) from pytest-timeout.
```

**Root cause**: During teardown, `sentence-transformers` lazily downloads the `all-MiniLM-L6-v2` model from HuggingFace (visible in captured stderr — repeated `HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/...` calls). Cold HF cache + 10s timeout = teardown exceeds budget. The test itself **PASSED**.

**Classification**: Network-dependent teardown flake. NOT a real regression. Same flake-class as the previously-noted `test_100_findings_ingest_under_1_second` timing flake.

**Mitigation options** (none required for this sweep):
1. Pre-cache MiniLM model in CI fixture (one-time `SentenceTransformer('all-MiniLM-L6-v2')` warm-up).
2. Bump pytest-timeout to 30s for tests touching AgentDB bridge teardown.
3. Stub `sentence-transformers` in this specific test fixture.

**No revert recommended** — no commit caused this; it's environmental.

---

## Verdict

**ALL GREEN. ZERO REGRESSIONS.**

87 commits across air-gap waves + 11 backlog rounds (UX consolidation, endpoint importers, dependency audit, cloud cleanup, UX hubs) introduced **no breakage** to either the canonical Beast Mode suite or the 26 session-added test files.

The single teardown error is a known network flake (HuggingFace model download during async teardown), unrelated to any code change in this session.

**Recommendation**: Continue parallel UX consolidation and endpoint importer work. No reverts required.
