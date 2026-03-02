# Enterprise Architect Memory

## Key Architecture Patterns

### Self-Learning Engine (V8)
- Engine: `suite-core/core/self_learning.py` (1,363 LOC)
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
- This is the deterministic fallback in brain_pipeline.py:786-797
- ML path uses GBT model from core.ml.risk_scorer (preferred when trained)
- Memory leak FIXED (2026-03-02): MAX_RUNS_HISTORY=1000 + eviction at line 224-230

### Scanner Ingest Architecture
- 15 parsers in `suite-core/core/scanner_parsers.py` (1,089 LOC)
- Router: `suite-api/apps/api/scanner_ingest_router.py` (388 LOC)
- 5 enterprise-critical: Checkmarx, SonarQube, Snyk, Fortify, Veracode
- Auto-detection via confidence scoring across all parsers
- Honest connector count: 7 outbound + 10 security + 15 inbound = 32 total

### Import Mechanism
- `sitecustomize.py` auto-prepends all suite dirs to sys.path
- Cross-suite imports work without pip install -e
- Tests add sys.path manually: `sys.path.insert(0, os.path.join(...))`
- E402 ruff warnings (75) are caused by this pattern — architectural, not bugs

### File Organization
- Engine code: `suite-core/core/` (business logic)
- Router code: `suite-core/api/` (REST endpoints)
- App wiring: `suite-api/apps/api/app.py` (34 router mounts, 2742 LOC)
- Tests: `tests/` (flat directory)
- Demo scripts: `scripts/`
- ADRs: `.claude/team-state/architecture/adrs/` (6 ADRs)

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
- pytest with --timeout=10 by default
- Tests use tmp_path fixture for isolated SQLite databases
- 73 self-learning tests (42 unit + 31 demo)
- 67/69 brain pipeline tests pass (2 KEV enrichment tests are pre-existing failures)
- Always run existing tests before writing new ones to verify no breakage

## Quality Metrics (2026-03-02, updated)
- Bandit (core files): 0 HIGH, 1 MEDIUM, 8 LOW ✅
- Bandit (full suite): 194 issues (0 HIGH, 51 MEDIUM, 143 LOW)
- Top risk: 26 SQL injection vectors (B608) — parameterize queries
- 89 bare except:pass (B110) — add specific exception handling
- Ruff: 174 warnings (99 actionable, 75 E402 architectural pattern)
- Test coverage: 19.19% (gate: 25%)
- Scanner parser tests: 129/129 PASS (91 unit + 38 integration)

## Scanner Parser Bug Fixes (2026-03-02)
- Fixed 8 normalizer bugs in scanner_parsers.py and ingestion.py
- SonarQube/Veracode: `can_handle` was too permissive (matched plain text)
- Nmap: Added info-level findings for open ports without vuln scripts
- Prowler: JSON array support (not just JSONL)
- Checkov: Nested `results.failed_checks` path
- ingestion.py `_map_severity`: UNKNOWN → MEDIUM for unknown severity strings

## Key Decisions Made
- Score-with-learning uses multiplicative weights (not additive) for composability
- compute_adjustments uses exponential moving average (0.7*old + 0.3*new) for stability
- Demo seed uses random.Random(42) for deterministic reproducibility
- Min samples default is 10 (3 for tests) to prevent premature adjustments
- Brain Pipeline _runs capped at 1000 to prevent memory leaks
- Scanner parsers are inbound normalizers, NOT full _BaseConnector subclasses
- ADR-006 documents the scanner ingest architecture and honest connector counts
