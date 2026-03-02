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
- This is the deterministic fallback in brain_pipeline.py (Step 7)
- ML path uses GBT model from core.ml.risk_scorer (preferred when trained)
- Memory leak FIXED: MAX_RUNS_HISTORY=1000 + eviction

### Brain Pipeline Performance (Run 7 review)
- Overall: O(12n) for n findings — each step is O(n) except LLM O(1) and MPTE O(1)
- Bottleneck at scale: Step 4 (Dedup) creates N DB connections — TD-020
- Steps 9+10 independent but sequential — could save 60-120s if parallelized — TD-021
- AutoFixEngine was created per-finding in Step 11 — FIXED (hoisted outside loop) — TD-022
- All memory bounds enforced: findings 50K, assets 10K, strings 10K, runs 1K, metrics 100
- Pipeline timeout 300s, step timeouts: dedup 60s, LLM 60s, MPTE 120s
- Peak memory: ~300MB at 50K findings (well-bounded)
- Thread safety: _cancelled set read without lock is benign (Python GIL + cooperative cancellation)
- Parallelization blueprint: steps 6-8 parallel, then steps 9+10 parallel → 50% I/O improvement

### Brain Pipeline Reliability (ADR-008)
- 12-step pipeline with global 300s timeout
- Step-level exception handling: catches Exception, logs with exc_info, continues
- Error messages sanitized: `f"{type(e).__name__}: pipeline step failed"` — no PII leakage
- Graceful degradation: every external dependency has a fallback chain
- LLM batch cap: top 100 findings by risk score
- Async: run_async() offloads to thread pool, step_micro_pentest handles event loop correctly

### Scanner Ingest Architecture
- 15 parsers in `suite-core/core/scanner_parsers.py` (1,238 LOC)
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
- E402 ruff warnings (77) are caused by this pattern — architectural, not bugs

### File Organization
- Engine code: `suite-core/core/` (business logic)
- Router code: `suite-core/api/` (REST endpoints)
- App wiring: `suite-api/apps/api/app.py` (34 router mounts, 2742 LOC)
- Tests: `tests/` (flat directory)
- Demo scripts: `scripts/`
- ADRs: `.claude/team-state/architecture/adrs/` (9 ADRs)

### Team State Protocol
- Status: `.claude/team-state/{agent-name}-status.md`
- Decisions: `.claude/team-state/decisions.log` (append-only)
- Sprint: `.claude/team-state/sprint-board.json`
- Metrics: `.claude/team-state/metrics.json`
- Context: `context_log.md` (append-only)
- ADRs: `.claude/team-state/architecture/adrs/`
- Tech debt: `.claude/team-state/architecture/tech-debt.json`
- Roadmap: `.claude/team-state/architecture/roadmap.md`
- Reviews: `.claude/team-state/architecture/reviews/`

## Testing
- pytest with --timeout=10 by default (30 for slow tests)
- Tests use tmp_path fixture for isolated SQLite databases
- 73 self-learning tests (42 unit + 31 demo)
- 288 core tests passing (brain pipeline + self-learning + scanner parsers)
- Test files: test_brain_pipeline.py, test_self_learning_unit.py, test_self_learning_demo.py, test_scanner_parsers_unit.py, test_scanner_parsers.py
- Always run existing tests before writing new ones to verify no breakage

### AutoFix Engine Architecture (Run 8 review, V3)
- Engine: `suite-core/core/autofix_engine.py` (1,534 LOC)
- Router: `suite-core/api/autofix_router.py` (276 LOC)
- 10 fix types, 8 fix statuses, 3 confidence levels
- 13 REST endpoints (5 POST, 8 GET)
- LLM-powered generation with deterministic rule-based fallback
- ML confidence model (AutoFixConfidenceModel) with fallback
- 7-point safety gate: dangerous patterns (55+), path traversal, imports, size
- MAX_FIXES_STORED=5000 with eviction (FIXED Run 8)
- MAX_HISTORY_ENTRIES=10000 with eviction (FIXED Run 8)
- CWE → category mapping: 20+ CWEs across 9 vulnerability classes
- Known weakness: prompt injection in LLM calls (mitigated by safety gate) — TD-024
- Private method access from router (_validate_fix) — code smell, not security

## Quality Metrics (2026-03-03 Run 8, verified)
- Bandit (core files): 0 HIGH, 2 MEDIUM (bind-all + xml.etree), 9 LOW
- Bandit (full suite): 458 issues (0 HIGH, 64 MEDIUM, 394 LOW)
- Ruff: 77 warnings (0 actionable, all E402 architectural pattern)
- Test coverage: 19.23% (gate: 25%, per agent-doctor)
- Core tests: 288/288 PASS (28.46s)
- AutoFix tests: 556/556 PASS (58.88s)
- ADRs: 9/9 validated (1 broken ref FIXED in ADR-009)
- Tech debt: 26 items (7 done)

## Reliability Patterns
- SQLite connections: MUST use try/finally (history.py + deduplication.py both fixed)
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
- ADR-009: MCP auto-discovery (two subsystems, startup-time catalog, self-referential)
- XML parsing uses defusedxml.defuse_stdlib() + defusedxml.ElementTree.fromstring
- CORS wildcard *.devinapps.com flagged as TD-016 for production removal
- history.py connection leak FIXED (5 methods, try/finally pattern)
- deduplication.py connection leak FIXED (process_finding, try/finally)
- AutoFixEngine loop hoist FIXED (brain_pipeline.py Step 11, O(n)→O(1))
- 5 F401 unused imports FIXED (enterprise service files)
- 2 F821 undefined-name FIXED (eventbus_integration.py, TYPE_CHECKING import)
- AutoFix _fixes unbounded FIXED (MAX_FIXES_STORED=5000, eviction logic)
- AutoFix _history unbounded FIXED (MAX_HISTORY_ENTRIES=10000, tail eviction)
- ADR-009 broken path reference FIXED (suite-integrations→suite-core)

### MCP Auto-Discovery Architecture (ADR-009, V7)
- Two subsystems: Auto-Discovery Router (/api/v1/mcp/*) + Protocol Engine (/api/v1/mcp-protocol/*)
- Router: `suite-api/apps/api/mcp_router.py` (977 LOC) — startup-time catalog generation
- Engine: `suite-core/core/mcp_server.py` (979 LOC) — JSON-RPC 2.0 MCP 2024-11-05
- 705 tools from 769 routes (self-discovered, not manually maintained)
- Name deduplication: method suffix + counter for conflicts
- Honesty note: self-referential discovery (ALdeci's own endpoints, not external)

## Review History
1. 2026-03-01: Self-learning architecture review
2. 2026-03-02: API gateway security review (ADR-007)
3. 2026-03-02: Brain pipeline data flow review
4. 2026-03-02: Reliability review (ADR-008, Grade B-)
5. 2026-03-02: Performance & data flow review (Grade B, updated Run 7)
6. 2026-03-03: AutoFix engine architecture review (Grade B+)
