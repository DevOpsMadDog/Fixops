# Enterprise Architect Memory

## Key Architecture Patterns

### Self-Learning Engine (V8)
- Engine: `suite-core/core/self_learning.py` (1,359 LOC)
- Router: `suite-core/api/self_learning_router.py` (551 LOC)
- 5 feedback loops: decision_outcome, mpte_result, false_positive, remediation_success, policy_violation
- Weights stored in SQLite `weights` table, clamped to [0.2, 1.5]
- Score integration: multiplier on Brain Pipeline's deterministic formula
- Demo endpoint: GET /api/v1/self-learning/demo/full-loop runs complete demo in one call
- ADR-005 documents architecture decisions

### Brain Pipeline Scoring Formula
```python
risk = min((cvss/10 * 0.4 + epss * 0.3 + 0.3) * kev_boost * asset_crit, 1.0)
```
- kev_boost = 1.5 if in_kev else 1.0
- This is the deterministic fallback in brain_pipeline.py:893-905
- ML path uses GBT model from core.ml.risk_scorer (preferred when trained)
- Memory leak FIXED: MAX_RUNS_HISTORY=1000 + eviction at line 247-253

### Brain Pipeline Reliability (ADR-008)
- 12-step pipeline with global 300s timeout
- Step-level exception handling: catches Exception, logs with exc_info, continues
- Error messages sanitized: `f"{type(e).__name__}: pipeline step failed"` — no PII leakage
- Graceful degradation: every external dependency has a fallback chain
- Memory bounds: _runs(1000), _metrics(100), findings(50K), assets(10K), strings(10K chars)
- LLM batch cap: top 100 findings by risk score
- Async: run_async() offloads to thread pool, step_micro_pentest handles event loop correctly

### Scanner Ingest Architecture
- 15 parsers in `suite-core/core/scanner_parsers.py` (1,224 LOC)
- Router: `suite-api/apps/api/scanner_ingest_router.py` (466 LOC)
- 5 enterprise-critical: Checkmarx, SonarQube, Snyk, Fortify, Veracode
- Auto-detection via confidence scoring across all parsers
- Honest connector count: 7 outbound + 10 security + 15 inbound = 32 total
- XML parsing hardened with defusedxml

### API Gateway Security (ADR-007)
- Multi-strategy auth: token (X-API-Key), JWT (Bearer), dev mode (no auth)
- Scope-based authorization: admin:all, attack:execute, write:*, read:*
- All 769 routes authenticated (except health probes + HMAC webhook receivers)
- Rate limiting: 120 req/min, burst 20, per-IP
- JWT: HS256, 120min expiry, ephemeral secret for dev

### Import Mechanism
- `sitecustomize.py` auto-prepends all suite dirs to sys.path
- Cross-suite imports work without pip install -e
- Tests add sys.path manually: `sys.path.insert(0, os.path.join(...))`
- E402 ruff warnings (77) are caused by this pattern — architectural, not bugs

### File Organization
- Engine code: `suite-core/core/` (business logic)
- Router code: `suite-core/api/` (REST endpoints)
- App wiring: `suite-api/apps/api/app.py` (34 router mounts, 2742 LOC)
- Tests: `tests/` (flat directory)
- Demo scripts: `scripts/`
- ADRs: `.claude/team-state/architecture/adrs/` (8 ADRs)

### Team State Protocol
- Status: `.claude/team-state/{agent-name}-status.md`
- Decisions: `.claude/team-state/decisions.log` (append-only)
- Sprint: `.claude/team-state/sprint-board.json`
- Metrics: `.claude/team-state/metrics.json`
- Context: `context_log.md` (append-only)
- ADRs: `.claude/team-state/architecture/adrs/`
- Tech debt: `.claude/team-state/architecture/tech-debt.json`
- Roadmap: `.claude/team-state/architecture/roadmap.md`

## Testing
- pytest with --timeout=10 by default (30 for slow tests)
- Tests use tmp_path fixture for isolated SQLite databases
- 73 self-learning tests (42 unit + 31 demo)
- 288 core tests passing (brain pipeline + self-learning + scanner parsers)
- Test files: test_brain_pipeline.py, test_self_learning_unit.py, test_self_learning_demo.py, test_scanner_parsers_unit.py, test_scanner_parsers.py
- Always run existing tests before writing new ones to verify no breakage

## Quality Metrics (2026-03-02 evening, verified)
- Bandit (core files): 0 HIGH, 1 MEDIUM (test-only), 8 LOW ✅
- Bandit (full suite): 456 issues (0 HIGH, 63 MEDIUM, 393 LOW)
- Top findings: B101(185), B110(101), B105(34), B608(27), B603(26)
- Ruff: 87 warnings (10 actionable, 77 E402 architectural pattern)
- Test coverage: 5.09% (gate: 25%)
- Core tests: 288/288 PASS

## Reliability Patterns (from Run 5 review)
- SQLite connections: MUST use try/finally (history.py was leaking, now fixed)
- Circuit breaker: exists in universal_connector.py, missing in Brain Pipeline
- Retries: exist in exploit_signals.py (urllib3) and playbook_runner.py
- Bare except count: 71 in core (30 files), 72 in API (20 files)
- Worst offenders: playbook_runner(19), single_agent(16), dast_engine(16)
- EventBus: fire-and-forget, no delivery guarantee (OK for Phase 1)

## Key Decisions Made
- Score-with-learning uses multiplicative weights (not additive) for composability
- compute_adjustments uses exponential moving average (0.7*old + 0.3*new) for stability
- Demo seed uses random.Random(42) for deterministic reproducibility
- Min samples default is 10 (3 for tests) to prevent premature adjustments
- Brain Pipeline _runs capped at 1000 to prevent memory leaks
- Scanner parsers are inbound normalizers, NOT full _BaseConnector subclasses
- ADR-006: scanner ingest architecture and honest connector counts
- ADR-007: API gateway security architecture
- ADR-008: reliability patterns (graceful degradation, DB safety, circuit breaker)
- XML parsing uses defusedxml.defuse_stdlib() + defusedxml.ElementTree.fromstring
- CORS wildcard *.devinapps.com flagged as TD-016 for production removal
- history.py connection leak FIXED (5 methods, try/finally pattern)
