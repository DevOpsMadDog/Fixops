# swarm-210: Fix E721 Type-Comparison Warnings in suite-core/

## Summary

Fixed all 5 E721 (type-comparison) lint warnings in `suite-core/core/mcp_server.py`.
All 127 regression tests pass with no regressions introduced.

## What Was Found

Running `ruff check suite-core/ --select E721 --output-format=full` found **5 errors**,
all in a single file:

**File**: `suite-core/core/mcp_server.py` (lines 261–270)

The code compared type hint objects (e.g., `hint == int`) against built-in type
literals using `==`. This is flagged by E721 because `==` triggers `__eq__` which
may have unintended behavior; identity comparison (`is`) is the correct and more
explicit way to compare type objects to type literals.

### Before
```python
if hint == int:
    prop = {"type": "integer"}
elif hint == float:
    prop = {"type": "number"}
elif hint == bool:
    prop = {"type": "boolean"}
elif hint == list or (hasattr(hint, "__origin__") and hint.__origin__ is list):
    prop = {"type": "array", "items": {"type": "string"}}
elif hint == dict:
    prop = {"type": "object"}
```

### After
```python
if hint is int:
    prop = {"type": "integer"}
elif hint is float:
    prop = {"type": "number"}
elif hint is bool:
    prop = {"type": "boolean"}
elif hint is list or (hasattr(hint, "__origin__") and hint.__origin__ is list):
    prop = {"type": "array", "items": {"type": "string"}}
elif hint is dict:
    prop = {"type": "object"}
```

## Why `is` (not `isinstance`)?

The variable `hint` is itself a **type object** (a class), not an instance of a class.
It holds values like `int`, `float`, `bool`, `list`, `dict` directly — these are
singletons in CPython. Using `hint is int` is semantically correct: it checks whether
`hint` is exactly the `int` type object. Using `isinstance(hint, int)` would be wrong
here because it would check if `hint` (a type object) is an instance of `int`, which
is False.

## Verification

### Lint check after fix
```
ruff check suite-core/ --select E721
All checks passed!
```
(0 errors, down from 5)

### Regression tests
```
python -m pytest tests/test_brain_pipeline.py tests/test_autofix_engine_unit.py -q --timeout=15 --no-cov
127 passed in 14.61s
```

## Files Modified

- `suite-core/core/mcp_server.py` — 5 type comparisons changed from `==` to `is`
  (lines 261, 263, 265, 267, 269)
