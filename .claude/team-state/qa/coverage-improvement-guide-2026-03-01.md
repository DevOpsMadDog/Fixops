# Coverage Improvement Guide — 2026-03-01

> **Author**: agent-doctor (run18)
> **For**: qa-engineer (SPRINT1-008)
> **Current coverage**: 16.99% (plateaued x5)
> **Target**: 40% CI gate (P0), 80% north-star
> **Gap**: ~23 percentage points

## Strategy: Maximum Impact Test Files

### Tier 1 — Highest Impact (create new test files)

These files have **no test coverage** and high LOC. Writing tests for them would immediately boost coverage.

| File | LOC | Priority | Recommended Test Approach |
|------|-----|----------|--------------------------|
| `core/security_connectors.py` | 641 | P0 | Mock external APIs, test connector methods individually |
| `core/real_scanner.py` | 632 | P0 | Mock subprocess calls, test scan result parsing |
| `core/stage_runner.py` | 629 | P0 | Test each stage function independently with mock pipeline |
| `core/cve_tester.py` | 563 | P1 | Mock NVD responses, test CVE matching logic |

**Estimated coverage gain**: +4-6% from these 4 files alone

### Tier 2 — Existing Test Files Need More Tests

These files have test files but show 0% coverage — the tests exist but don't exercise the main code paths.

| File | LOC | Test File | Issue |
|------|-----|-----------|-------|
| `core/cli.py` | 2,459 | `test_cli.py` | Tests may only test imports, not commands |
| `core/connectors.py` | 1,165 | `test_connectors.py` | Needs connector method tests with mocked HTTP |
| `core/autofix_engine.py` | 518 | `test_autofix_engine_unit.py` | 64 tests exist but may not hit all code paths |

**Estimated coverage gain**: +3-5% from expanding these test suites

### Tier 3 — Low-Hanging Fruit (model/schema files)

Files with 0% coverage that are purely data models — trivial to test:

| File | LOC | What to Test |
|------|-----|-------------|
| `core/analytics_models.py` | 46 | Instantiation, serialization |
| `core/audit_models.py` | 45 | Instantiation, defaults |
| `core/auth_models.py` | 67 | Instantiation, validation |

**Estimated coverage gain**: +0.5-1%

### Recommended Priority Order

1. Create `test_security_connectors.py` (P0, +2%)
2. Create `test_real_scanner.py` (P0, +1.5%)
3. Create `test_stage_runner.py` (P0, +1.5%)
4. Expand `test_cli.py` with command tests (P0, +2%)
5. Expand `test_connectors.py` (P1, +1.5%)
6. Create `test_cve_tester.py` (P1, +1%)
7. Test model files (P2, +0.5%)

**Total estimated gain: ~10-12% → targeting 27-29%**

### To Hit 40% Gate

In addition to the above, consider:
- Testing router files (currently 0% for most routers) — each router is 40-200 LOC
- Testing `core/configuration.py` more thoroughly (593 LOC, has test file)
- Adding integration tests for `core/scanner_parsers.py` (535 LOC, 15 normalizers)

## Test Writing Tips

1. **Always mock external dependencies** — no network calls, no Docker, no LLM APIs
2. **Use `pytest.mark.timeout(10)`** — enforce 10s max per test
3. **Follow existing patterns** — see `test_brain_pipeline.py` for mock structure
4. **Use fixtures from `conftest.py`** — shared test data is already set up
5. **Run tests with `--cov` flag** — verify your tests actually improve coverage
