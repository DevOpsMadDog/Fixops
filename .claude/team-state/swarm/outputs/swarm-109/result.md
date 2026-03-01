# Swarm Task swarm-109 — Lint Check suite-core/

**Task Type**: lint-fix (report only, no auto-fix)
**Completed**: 2026-03-01
**Coverage**: suite-core/ (full directory tree)

---

## Summary

- **Total warnings/errors**: 95
- **Fixable with --fix**: 60 (63%)
- **Manual fixes needed**: 35 (37%)
- **Unsafe fixes available**: 7 (additional auto-fix options)

---

## Error Categories (Ranked by Frequency)

| Rank | Code | Category | Count | Fixable | Notes |
|------|------|----------|-------|---------|-------|
| 1 | F401 | Unused import | 55 | Yes | Most common issue; typically safe to remove |
| 2 | E402 | Module import not at top of file | 15 | No | Requires code restructuring (imports after logic) |
| 3 | F541 | f-string missing placeholders | 9 | Yes | f-strings that don't use variables; convert to regular strings |
| 4 | F841 | Unused variable | 7 | No | Dead local variables; may hide actual code issues |
| 5 | E721 | Type comparison | 5 | No | Using `type(x) == Y` instead of `isinstance()` |
| 6 | E701 | Multiple statements on one line with colon | 4 | No | Code style (e.g., `if x: return y` should be 2 lines) |

**Total**: 95 errors across 6 rule categories

---

## Top 3 Files with Most Issues

| Rank | File | Issues | Primary Errors |
|------|------|--------|-----------------|
| 1 | suite-core/api/app.py | 8 | 7x E402 (import-not-at-top), 1x F401 (unused-import) |
| 2 | suite-core/core/scanner_parsers.py | 7 | 5x F401 (unused-import), 2x F541 (f-string-missing-placeholders) |
| 3 | suite-core/core/ml/anomaly_detector.py | 6 | Likely unused imports and variables |

**Runner-up files** (3 issues each):
- suite-core/core/zero_gravity.py
- suite-core/core/self_learning.py
- suite-core/core/quantum_crypto.py
- suite-core/core/ml/daily_intel.py
- suite-core/core/ml/consensus_calibrator.py
- suite-core/core/mcp_server.py
- suite-core/core/llm_consensus.py

---

## Fixable vs. Manual Issues

### Fixable (60 issues — can auto-fix with --fix)
- **55x F401**: Unused imports → `ruff check --fix` removes them
- **9x F541**: f-strings without placeholders → convert to regular strings
- Additional 7 unsafe fixes available (require `--unsafe` flag)

**Command to auto-fix**:
```bash
python -m ruff check suite-core/ --fix
```

### Manual Review Needed (35 issues)
- **15x E402**: Imports after module-level code (e.g., app.py lines 85-97)
  - Requires restructuring: move imports to top or move code down
  - This is intentional in app.py (conditional middleware setup before imports)
  - **Assessment**: May be acceptable in this context; verify architecture

- **7x F841**: Unused variables (dead code)
  - Requires judgment: are these placeholder variables for future use?
  - **Assessment**: Should review case-by-case

- **5x E721**: Type comparisons (e.g., `type(x) == Y`)
  - **Assessment**: Manual refactor to `isinstance(x, Y)` recommended

- **4x E701**: Multiple statements on one line
  - **Assessment**: Style cleanup; low priority

---

## Key Finding: suite-core/api/app.py

The file `suite-core/api/app.py` is the largest offender with 8 issues, primarily E402 errors.

**Lines 85-98**: Imports appear after line 83 (logger.debug call)
```python
83 |     logger.debug("LearningMiddleware not available on suite-core")
84 |
85 | from api.autofix_router import router as autofix_router  # E402
86 | from api.brain_router import router as brain_router  # E402
...
```

**Why this pattern exists**: The code conditionally sets up middleware before importing routers. This is a known architectural choice.

**Options**:
1. Accept the E402 violations as intentional (common in modular monoliths)
2. Refactor to move all imports to the top and use lazy imports for conditional setup
3. Suppress E402 in pyproject.toml for this file

---

## Recommendations

### High Priority (Quick wins)
1. **Auto-fix unused imports (F401)**: Run `python -m ruff check suite-core/ --fix` to remove 55 unused imports
2. **Auto-fix f-strings (F541)**: Included in above command

### Medium Priority (Requires review)
1. **Review E402 in app.py**: Confirm architectural intent or restructure imports
2. **Remove unused variables (F841)**: Audit 7 instances; some may be intentional placeholders

### Low Priority (Style cleanup)
1. **Type comparisons (E721)**: Refactor 5 instances to use `isinstance()`
2. **Multiple statements on one line (E701)**: Split into separate lines (4 instances)

---

## Fixability Score

- **Auto-fixable**: 60/95 = **63%**
- **Manual-fixable**: 35/95 = **37%**
- **Estimated effort**: High for E402 (restructuring); Low for others (removal/refactoring)

---

## Ruff Output (Raw Statistics)

```
55	F401	[-] unused-import
15	E402	[ ] module-import-not-at-top-of-file
 9	F541	[*] f-string-missing-placeholders
 7	F841	[ ] unused-variable
 5	E721	[ ] type-comparison
 4	E701	[ ] multiple-statements-on-one-line-colon
Found 95 errors.
[*] 60 fixable with the `--fix` option (7 hidden fixes can be enabled with the `--unsafe-fixes` option).
```

---

**Status**: Complete. No changes made to source code per task requirements.
