# Code Quality Report — 2026-03-03 (Run 8)

- **Date**: 2026-03-03
- **Reviewer**: enterprise-architect (Run 8)
- **Scope**: suite-core/, suite-api/, suite-attack/
- **Pillar**: V3 (Decision Intelligence), V7 (MCP), V10 (CTEM)
- **Session Focus**: AutoFix engine review, memory bounds fixes, quality scans

---

## 1. Linting (ruff)

```
Total errors: 77 (stable from Run 7)
- E402 (module-import-not-at-top): 77  — systemic, caused by sitecustomize.py pattern
- F401 (unused-import): 0              — ALL FIXED (Run 6)
- F821 (undefined-name): 0             — ALL FIXED (Run 7)
- E701/F841: 0                         — resolved
```

**Verdict**: GREEN — 77 total, ALL architectural E402. Zero actionable issues.

## 2. Security (bandit)

### Core Files (brain_pipeline, scanner_parsers, autofix_engine, app.py, scanner_ingest_router, self_learning)
```
HIGH severity: 0
MEDIUM severity: 2  (B104 bind-all-interfaces in autofix_engine, B314 xml.etree in scanner_parsers)
LOW severity: 9
```

### Full Suite (suite-core/ + suite-api/)
```
Total: 458 issues (+2 from Run 7)
HIGH severity: 0
MEDIUM severity: 64  (+1 from Run 7)
LOW severity: 394  (+1 from Run 7)

Top findings by ID:
  B101: 185  (assert — test/dev artifacts)
  B110: 102  (bare except:pass — code smell, not vulnerability)
  B105:  34  (hardcoded passwords — mostly false positives on defaults)
  B608:  27  (SQL injection — verified parameterized, f-string syntax trigger)
  B603:  26  (subprocess — needs input audit)
```

**Verdict**: GREEN for core files. WARN for full suite (64 MEDIUM, 0 HIGH).

**Change from Run 7**: +2 total issues (1 MEDIUM, 1 LOW). Likely from new code added by other agents (brain_pipeline +130 LOC, autofix_engine +87 LOC, etc.). No HIGH severity introduced.

## 3. Tests

### Core Pipeline Tests (288 tests)
```
pytest tests/test_brain_pipeline.py tests/test_self_learning_unit.py \
       tests/test_self_learning_demo.py tests/test_scanner_parsers_unit.py \
       tests/test_scanner_parsers.py -x -q --timeout=30

Result: 288 passed in 28.46s (Run 8 verified)
```

### AutoFix Tests (556 tests)
```
pytest tests/ -k "autofix" -x -q --timeout=30

Result: 556 passed in 58.88s (Run 8 verified)
```

### Full Test Suite
```
Tests collected: ~13,674
Coverage: 19.23% (measured with all suites, per agent-doctor)
Gate: 25% — FAILING (gap 5.77pp)
```

## 4. Bug Fixes Applied This Session (3 fixes)

### Fix 1: TD-023 — AutoFix _fixes Dict Unbounded
**File**: `suite-core/core/autofix_engine.py`
**Change**: Added `MAX_FIXES_STORED = 5000` constant and eviction logic after fix storage. When _fixes exceeds 5K entries, oldest entries are deleted.
**Impact**: Prevents memory leak in long-running processes. At 50KB per fix, caps at ~250MB max.
**Verification**: 288 core + 556 autofix tests pass.

### Fix 2: TD-025 — AutoFix _history List Unbounded
**File**: `suite-core/core/autofix_engine.py`
**Change**: Added `MAX_HISTORY_ENTRIES = 10000` constant and tail eviction after each history append.
**Impact**: Caps history at 10K entries. At ~200 bytes per entry, max ~2MB.
**Verification**: 288 core + 556 autofix tests pass.

### Fix 3: ADR-009 Broken File Path
**File**: `.claude/team-state/architecture/adrs/ADR-009-mcp-auto-discovery.md`
**Change**: Fixed 2 references from `suite-integrations/api/mcp_protocol_router.py` to `suite-core/api/mcp_protocol_router.py`.
**Impact**: ADR file references now 100% accurate.
**Verification**: Path verified with Glob tool.

## 5. AutoFix Engine Review

New review written: `.claude/team-state/architecture/reviews/2026-03-03-autofix-engine-review.md`

**Overall Grade: B+** (Good for demo, production hardening needed)

Key findings:
| Finding | Severity | Status |
|---------|----------|--------|
| _fixes dict unbounded (TD-023) | MEDIUM | FIXED this session |
| _history list unbounded (TD-025) | LOW | FIXED this session |
| No prompt injection protection (TD-024) | MEDIUM | Logged (Phase 2) |
| Bulk request unbounded (TD-026) | LOW | Logged (Phase 2) |
| Private method access from router | LOW | Logged (Phase 2) |
| No endpoint-level auth | MEDIUM | Mitigated by global middleware |

Strengths:
- 7-point safety gate for LLM-generated code (55+ dangerous patterns)
- ML confidence model with deterministic fallback
- 10 fix types, 8 fix statuses
- Event bus integration for lifecycle notifications
- Error handling prevents secret leakage in logs

## 6. ADR Validation

All 9 ADRs validated (Run 8):
- **9/9 fully valid** — all file references verified on disk
- **1 broken path FIXED** in ADR-009 (suite-integrations → suite-core)
- **0 remaining stale references**

## 7. Architecture Quality

| Check | Status | Details |
|-------|--------|---------|
| All routes authenticated | Global middleware | 769 routes |
| Memory bounds enforced | AutoFix added | Brain Pipeline + AutoFix both bounded |
| DB connection safety | history + dedup | try/finally pattern |
| Graceful degradation | All external deps | Fallback chains for LLM, graph, MPTE |
| Error sanitization | No PII leakage | type(exc).__name__ pattern |
| Thread safety | Double-checked lock | Singleton |
| Pipeline timeout | 300s global | Step-level: 60s dedup/LLM, 120s MPTE |
| AutoFix safety gate | 7 checks | Dangerous patterns, traversal, imports, size |

## 8. Key Metrics Summary

| Metric | Value | Status | Change (Run 8) |
|--------|-------|--------|--------|
| Core tests | 288/288 PASS | GREEN | Verified (28.46s) |
| AutoFix tests | 556/556 PASS | GREEN | NEW: first dedicated run |
| Ruff warnings | 77 (0 actionable) | GREEN | Stable |
| Bandit HIGH (core) | 0 | GREEN | Stable |
| Bandit MEDIUM (core) | 2 | GREEN | Stable |
| Bandit total (full) | 458 | WARN | +2 from Run 7 |
| ADRs written | 9 | GREEN | 1 ref FIXED |
| ADRs validated | 9/9 | GREEN | 100% file refs valid |
| Tech debt items | 26 (7 done) | WARN | +4 new, +2 FIXED |
| Bugs fixed (Run 8) | 3 | GREEN | _fixes, _history, ADR path |
| Bugs fixed (cumulative) | 7 | GREEN | All sessions combined |
| Reviews completed | 6 total | GREEN | +1 AutoFix engine review |

---

*Generated by enterprise-architect on 2026-03-03 (Run 8). Serves pillars: V3, V5, V7, V10.*
