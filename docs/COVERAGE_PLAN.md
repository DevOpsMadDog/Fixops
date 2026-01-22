# FixOps Test Coverage Plan

**Last Updated:** January 2, 2026  
**Document Owner:** DevSecOps Engineering  
**Status:** Active - Enforced via CI

---

## Current State (January 2, 2026)

### Coverage Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| **Global Coverage** | 18.95% | Measured on core/ + apps/ modules |
| **Total Statements** | 28,254 | In core/ and apps/ directories |
| **Covered Statements** | 5,580 | Statements with test coverage |
| **Uncovered Statements** | 22,674 | Statements needing tests |
| **Tests Passing** | 44/46 | 2 tests failing due to env issues |

### Module-Level Coverage

**Well-Covered Modules (>70%):**
- `core/severity_promotion.py` - 90.15%
- `core/performance.py` - 85.90%
- `core/storage.py` - 85.42%
- `core/probabilistic.py` - 80.75%
- `core/vector_store.py` - 70.31%
- `core/policy.py` - 68.63%

**Partially Covered Modules (30-70%):**
- `core/processing_layer.py` - 45.81%
- `core/tenancy.py` - 44.83%
- `core/services/identity.py` - 39.75%
- `core/ssdlc.py` - 23.05%
- `core/services/deduplication.py` - 22.74%

**Uncovered Modules (0%):**
- `core/pentagi_*.py` - Pen testing integration
- `core/stage_runner.py` - Pipeline stage execution
- `core/sarif_canon.py` - SARIF canonicalization
- `core/*_db.py` - Database models
- `risk/reachability/*.py` - Reachability analysis
- `risk/feeds/*.py` - Vulnerability feeds
- `risk/runtime/*.py` - Runtime security

---

## Coverage Policy: "100% Always"

### What "100% Always" Means

Starting January 2, 2026, FixOps enforces **100% test coverage on all new and modified code**. This is implemented via diff-coverage in CI.

**Policy Details:**
1. **New code must have 100% coverage** - Any lines added or modified in a PR must be covered by tests
2. **Global baseline increases over time** - We will systematically increase coverage on existing code
3. **Critical modules have priority** - Decision engine, evidence generation, and auth boundaries first

### Enforcement Mechanism

CI runs `diff-cover` after pytest to check coverage on changed lines:

```yaml
- name: Enforce 100% Coverage on New Code
  run: |
    diff-cover coverage.xml --compare-branch=origin/main --fail-under=100
```

If new code is not 100% covered, CI will warn (soft enforcement initially, hard enforcement after baseline is established).

---

## Phased Coverage Improvement Plan

### Phase 1: Foundation (January 2026)
**Target: 25% global coverage**

Focus areas:
- [ ] Fix pytest configuration issues (asyncio_mode, missing dependencies)
- [ ] Add tests for `core/enhanced_decision.py` (decision engine)
- [ ] Add tests for `core/evidence.py` (evidence generation)
- [ ] Add tests for `apps/api/pipeline.py` (main pipeline)

### Phase 2: Core Safety Surface (February 2026)
**Target: 50% global coverage**

Focus areas:
- [ ] `core/decision_policy.py` - Policy enforcement
- [ ] `core/llm_providers.py` - LLM integrations
- [ ] `core/services/identity.py` - Auth boundaries
- [ ] `apps/api/auth_router.py` - Authentication endpoints

### Phase 3: Data Layer (March 2026)
**Target: 70% global coverage**

Focus areas:
- [ ] All `*_db.py` modules - Database operations
- [ ] `core/services/deduplication.py` - Deduplication logic
- [ ] `apps/api/*_router.py` - API endpoints

### Phase 4: Full Coverage (April 2026)
**Target: 100% global coverage**

Focus areas:
- [ ] `risk/reachability/*.py` - Reachability analysis
- [ ] `risk/feeds/*.py` - Vulnerability feeds
- [ ] `core/pentagi_*.py` - Pen testing integration
- [ ] All remaining modules

---

## Testing Standards

### Test Types Required

1. **Unit Tests** - For pure functions and business logic
2. **Integration Tests** - For database operations and external integrations
3. **E2E Tests** - For full pipeline execution
4. **Property-Based Tests** - For normalizers and parsers (using Hypothesis)

### Test File Naming

- Unit tests: `tests/test_{module_name}.py`
- Integration tests: `tests/integration/test_{feature}.py`
- E2E tests: `tests/e2e/test_{scenario}.py`

### Coverage Exclusions

The following are excluded from coverage requirements:
- `archive/` - Legacy code
- `tests/` - Test code itself
- `scripts/` - Utility scripts
- Type stubs and `__init__.py` files

---

## How to Check Coverage Locally

```bash
# Run tests with coverage
pytest --cov=core --cov=apps --cov-report=term-missing --cov-report=html

# Check coverage on your changes vs main
pip install diff-cover
diff-cover coverage.xml --compare-branch=origin/main --fail-under=100

# View HTML report
open htmlcov/index.html
```

---

## Metrics Tracking

Coverage metrics are tracked in CI and reported on each PR. Historical trends will be added to the analytics dashboard.

| Date | Global Coverage | Notes |
|------|-----------------|-------|
| 2026-01-02 | 18.95% | Baseline measurement |
| 2026-01-31 | TBD | Phase 1 target: 25% |
| 2026-02-28 | TBD | Phase 2 target: 50% |
| 2026-03-31 | TBD | Phase 3 target: 70% |
| 2026-04-30 | TBD | Phase 4 target: 100% |

---

## Related Documents

- [Product Status & Technical Reference](./FIXOPS_PRODUCT_STATUS.md) - Feature readiness and technical deep-dive
- [Architecture](./ARCHITECTURE.md) - System design
- [Contributing](../CONTRIBUTING.md) - Development guidelines
