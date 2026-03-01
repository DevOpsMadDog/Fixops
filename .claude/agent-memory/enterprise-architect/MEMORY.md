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
- This is the deterministic fallback in brain_pipeline.py:686-694

### Import Mechanism
- `sitecustomize.py` auto-prepends all suite dirs to sys.path
- Cross-suite imports work without pip install -e
- Tests add sys.path manually: `sys.path.insert(0, os.path.join(...))`

### File Organization
- Engine code: `suite-core/core/` (business logic)
- Router code: `suite-core/api/` (REST endpoints)
- App wiring: `suite-api/apps/api/app.py` (router mounting)
- Tests: `tests/` (flat directory)
- Demo scripts: `scripts/`

### Team State Protocol
- Status: `.claude/team-state/{agent-name}-status.md`
- Decisions: `.claude/team-state/decisions.log` (append-only)
- Sprint: `.claude/team-state/sprint-board.json`
- Metrics: `.claude/team-state/metrics.json`
- Context: `context_log.md` (append-only)
- ADRs: `.claude/team-state/architecture/adrs/`

## Testing
- pytest with --timeout=10 by default
- Tests use tmp_path fixture for isolated SQLite databases
- 73 self-learning tests (42 unit + 31 demo)
- Always run existing tests before writing new ones to verify no breakage

## Key Decisions Made
- Score-with-learning uses multiplicative weights (not additive) for composability
- compute_adjustments uses exponential moving average (0.7*old + 0.3*new) for stability
- Demo seed uses random.Random(42) for deterministic reproducibility
- Min samples default is 10 (3 for tests) to prevent premature adjustments
