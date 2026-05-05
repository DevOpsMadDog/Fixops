# ALDECI Test Markers

Pytest markers registered in `pyproject.toml` under `[tool.pytest.ini_options] markers`.

## Marker Definitions

| Marker | Meaning |
|--------|---------|
| `integration` | Touches a real database, subprocess, or network socket. May be slow. |
| `slow` | Any test expected to take >1s wall time. Applied in addition to other markers. |
| `perf` | Performance benchmark / regression guard. Asserts timing contracts (e.g., "must complete in <200ms"). CI perf gate runs `pytest -m perf`. |
| `benchmark` | Micro-benchmark measuring raw throughput or latency with explicit timing loops. Subset of `perf`. |
| `security` | Tests that verify security properties (auth, crypto, RBAC enforcement). |
| `requires_network` | Needs live external network access (e.g., threat intel feeds, CVE APIs). |
| `requires_docker` | Needs a running Docker daemon (container scans, sandbox verifier). |
| `requires_k8s` | Needs a live Kubernetes cluster. |
| `asyncio` | Async tests using pytest-asyncio (auto-mode enabled globally). |
| `owasp` | OWASP regression lockdown tests — 7 hardening commits, real source inspection + TestClient HTTP calls. CI runs `pytest -m owasp`. |

## CI Usage Examples

```bash
# Run only perf benchmark tests (CI perf gate)
pytest -m perf

# Run everything except slow tests (fast CI gate)
pytest -m "not slow"

# Run integration tests only
pytest -m integration

# Skip network-dependent tests (air-gapped / offline CI)
pytest -m "not requires_network"

# Run perf tests but skip ones that also need Docker
pytest -m "perf and not requires_docker"

# Run OWASP regression lockdown tests
pytest -m owasp
```

## Perf-Tagged Files (26 files)

All files below carry `pytestmark = pytest.mark.perf` at module level.

| File | What it guards |
|------|---------------|
| `test_brain_pipeline_perf.py` | ThreadPoolExecutor singleton; 50-finding dedup <50ms |
| `test_risk_scorer_batch_predict.py` | Batch risk scoring correctness + throughput |
| `test_crypto_manager_singleton.py` | RSA-4096 keygen pays once; second call <50ms |
| `test_llm_council_perf.py` | Parallel provider voting; top-5 AgentDB lookup <360ms |
| `test_connector_perf.py` | bulk_push concurrency; endpoint cache O(1) |
| `test_duckdb_perf.py` | DuckDB aggregation pushdown; no Python materialisation |
| `test_sast_perf.py` | Per-file language pre-filter; pre-compiled taint patterns |
| `test_cspm_perf.py` | CSPM hotspot fixes wall-clock budget |
| `test_sbom_perf.py` | executemany bulk insert; single-JOIN list_sboms |
| `test_threat_enricher_perf.py` | EPSS cache skip; parallel batch EPSS fetch |
| `test_compliance_perf.py` | Single-commit collect_evidence; single-SELECT framework status |
| `test_mpte_attack_perf.py` | Pre-index phase lookup O(1); asyncio.gather parallel phases |
| `test_edr_siem_perf.py` | Single-pass normalize+count; batch TrustGraph event list |
| `test_reachability_perf.py` | O(1) set-dedup for call-graph edges |
| `test_streaming_perf.py` | severity_order module constant; SSE result cache |
| `test_playbook_perf.py` | O(1) step lookup; parallel step execution |
| `test_mcp_perf.py` | deque(maxlen) for call_log and execution_history |
| `test_rbac_perf.py` | get_user_scopes in-process cache |
| `test_soar_perf.py` | WAL mode; SQL GROUP BY stats (no full table scan) |
| `test_asset_inventory_perf.py` | O(1) dict lookup; bulk_import single executemany |
| `test_ctem_perf.py` | Batch ingest faster than per-row loop baseline |
| `test_evidence_perf.py` | Persistent SQLite connection; detect_tampering reuse |
| `test_webhook_perf.py` | deliver_to_all parallelised fan-out |
| `test_risk_normalization_perf.py` | 500 findings under 2s; no per-finding dict copy |
| `test_onboarding_perf.py` | WAL + thread-local connection cache; 100 idempotent calls <500ms |
| `test_misc_perf.py` | executemany for secret_scanner; asyncio.gather for decision_engine |

## Counts (approximate — run `pytest --collect-only -m <marker>` for live count)

| Marker | Approximate test count |
|--------|----------------------|
| `owasp` | 47 |
| `perf` | 182 |
| `unit` | varies (not yet mass-tagged) |
| `integration` | varies (not yet mass-tagged) |
| `slow` | varies (not yet mass-tagged) |

To get exact counts:
```bash
pytest tests/ --collect-only -q -m perf -o "addopts=" 2>&1 | tail -2
pytest tests/ --collect-only -q -m unit -o "addopts=" 2>&1 | tail -2
pytest tests/ --collect-only -q -m integration -o "addopts=" 2>&1 | tail -2
```
