# Swarm Task swarm-110 — Lint Check suite-api/

## Summary
- **Total warnings/errors**: 74
- **Fixable issues**: 7 (with --fix), 6 additional fixable with --unsafe-fixes
- **Top 3 categories**:
  1. E402 (module-import-not-at-top-of-file): 60 issues
  2. F841 (unused-variable): 6 issues
  3. F401 (unused-import): 8 issues

## Files with Most Issues (Top 3)
1. **suite-api/apps/api/pipeline.py**: 29 issues
2. **suite-api/apps/api/app.py**: 28 issues
3. **suite-api/apps/api/marketplace_router.py**: 4 issues

## Issue Breakdown by Category

### E402: Module-level import not at top of file (60 issues)
These are imports that appear after other code or inside conditional blocks. Primary locations:
- **suite-api/apps/api/app.py**: 24 instances (lines 51-72, 536-571)
- **suite-api/apps/api/pipeline.py**: 29 instances (lines 13-21 and others)

The app.py file uses conditional imports with try/except blocks, which causes imports to appear after non-import code. The pipeline.py file has many imports that are conditionally placed.

**Root Cause**: Exception handling with logging before router imports in app.py (lines 49-50):
```python
logging.getLogger(__name__).warning("Connectors router not available: %s", e)

from apps.api.inventory_router import router as inventory_router  # E402
```

### F841: Local variable assigned but never used (6 issues)
- **suite-api/apps/api/analytics_router.py**: 4 instances
  - Line 749: `decisions` variable
  - Line 752: `false_positives` variable
  - Line 755: `resolved` variable
  - Line 758: `open_count` variable

All four variables are assigned but the values are never referenced in the function.

### F401: Unused import (8 issues)
- **suite-api/apps/api/connectors_router.py**: 2 instances (line 26)
- **suite-api/apps/api/fail_router.py**: 2 instances (lines 25-26)
- **suite-api/apps/api/marketplace_router.py**: 4 instances (lines 19-22)
- **suite-api/apps/api/rate_limiter.py**: 1 instance
- **suite-api/apps/api/mcp_router.py**: 1 instance (line 649)

## Files with Issues (Complete List)
- suite-api/apps/api/pipeline.py (29 issues)
- suite-api/apps/api/app.py (28 issues)
- suite-api/apps/api/marketplace_router.py (4 issues)
- suite-api/apps/api/analytics_router.py (4 issues)
- suite-api/apps/api/system_router.py (3 issues)
- suite-api/apps/api/fail_router.py (2 issues)
- suite-api/apps/api/connectors_router.py (2 issues)
- suite-api/apps/api/rate_limiter.py (1 issue)
- suite-api/apps/api/mcp_router.py (1 issue)

## Recommendations

### Critical (E402 - E402)
The E402 issues in **app.py** and **pipeline.py** can be resolved by:
1. Moving all imports to the top of the files
2. Removing try/except around imports in app.py (or moving the error handling after imports)
3. These represent architectural decisions around conditional imports that may require review

### Medium Priority (F841)
The unused variables in analytics_router.py should be:
1. Either removed if no longer needed
2. Or used in the function logic
3. Can be auto-fixed with `ruff check --fix`

### Low Priority (F401)
Unused imports should be removed. These are straightforward fixes.

## Auto-Fix Capability
- 7 issues can be auto-fixed with `ruff check --fix`
- 6 additional issues can be auto-fixed with `--unsafe-fixes` (requires manual review)
- E402 issues require manual restructuring (not auto-fixable)

## Command to Auto-Fix (DO NOT APPLY - per task instruction)
```bash
ruff check suite-api/ --fix          # Fixes 7 issues
ruff check suite-api/ --fix --unsafe-fixes  # Fixes additional 6 issues
```
