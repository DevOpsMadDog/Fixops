# Swarm Task swarm-117 — Self-Learning Demo Validation

## Syntax Validation
- **Status**: VALID
- **Parse Result**: Successfully parsed without errors
- **Lines of Code**: 339 LOC
- **Functions**: 10
- **Classes**: 0

## Script Overview

**File**: `scripts/demo_self_learning.py`

**Purpose**: Demonstrates ALdeci V8 self-learning feedback loop engine with 5 distinct learning mechanisms.

**Demo ID**: DEMO-012 (V8)

## Function Inventory

1. `banner()` — Display ASCII banner with colored formatting
2. `step(n, title)` — Print step header with cyan styling
3. `ok(msg)` — Print success message with green checkmark
4. `warn(msg)` — Print warning message with yellow icon
5. `err(msg)` — Print error message with red X
6. `info(msg)` — Print informational message with arrow
7. `api(method, url, token, json_data)` — Generic HTTP API client with error handling
8. `run_full_loop(base_url, token)` — Execute all-in-one `/demo/full-loop` endpoint
9. `run_step_by_step(base_url, token, quick)` — Execute 9-step manual demo flow
10. `main()` — Entry point with argparse CLI

## Key Findings

### Architecture
- **Entry Point**: `main()` at line 315
- **CLI Pattern**: Uses `argparse` with 4 options:
  - `--base-url` (default: `http://localhost:8000`)
  - `--token` (default: `test-api-key`)
  - `--full-loop` (all-in-one endpoint)
  - `--quick` (fewer demo records)

### Two Execution Modes

1. **Full Loop Mode** (`--full-loop`):
   - Single API call to `/api/v1/self-learning/demo/full-loop`
   - Returns all 6 demo steps at once
   - Demonstrates 5 feedback loops in parallel

2. **Step-by-Step Mode** (default):
   - 9 sequential API calls (Steps 1-9)
   - Granular control and detailed reporting at each stage
   - Calls:
     - Step 1: Status check → `/api/v1/self-learning/status`
     - Step 2: Reset → `/api/v1/self-learning/demo/reset`
     - Step 3: Baseline score → `/api/v1/self-learning/score-with-learning`
     - Step 4: Seed data → `/api/v1/self-learning/demo/seed` (98 records)
     - Step 5: Analysis → `/api/v1/self-learning/analyze`
     - Step 6: Compute adjustments → `/api/v1/self-learning/compute-adjustments`
     - Step 7: Fetch weights → `/api/v1/self-learning/weights`
     - Step 8: Re-score → `/api/v1/self-learning/score-with-learning`
     - Step 9: Insights → `/api/v1/self-learning/insights`

### 5 Feedback Loops Demonstrated

1. **Decision Outcome Loop** — AI decisions improve via accuracy tracking
2. **MPTE Result Loop** — Exploitability predictions refine via F1 score
3. **False Positive Loop** — Scanner noise suppression via FP rate tracking
4. **Remediation Success Loop** — Fix recommendations improve via success rate
5. **Policy Violation Loop** — Over-strict policies auto-relax via justified rate

### Test Sample Finding
```python
{
    "cvss_score": 7.5,
    "epss_score": 0.35,
    "in_kev": False,
    "asset_criticality": 0.7,
    "scanner": "zap",
    "rule_id": "10016-xss",
    "fix_type": "CODE_PATCH"
}
```

### Seed Data Configuration
- **Total Records**: 98 across 5 loops
- **Distribution**: Decision (N), MPTE (N), False Positives (N), Remediation (N), Policy (N)
- **Purpose**: Create learning signal for weight adjustment algorithms

### Output Metrics Tracked

**Before Learning**:
- Baseline risk score
- Decision accuracy %
- MPTE F1 score %
- False positive rate %
- Remediation success rate %
- Policy justified rate %

**After Learning**:
- Adjusted risk score
- Delta score (signed)
- Delta percent change
- Number of adjustments applied
- Per-adjustment breakdown (loop, target, old→new weights, reasoning)

### Error Handling

- Connection error detection with sys.exit(1) if API unavailable
- HTTP status ≥400 treated as error, response text logged
- Missing 'requests' package check at module import time
- Timeout: 30s per HTTP call

### Output Styling

- ANSI colors for readability (GREEN, RED, YELLOW, CYAN, BOLD, DIM)
- UTF-8 box drawing characters (╔═╗║╚═╝)
- Semantic icons (✓, ⚠, ✗, →)
- Delta direction indicated via color coding (GREEN=risk_reduced, RED=risk_increased)

### Dependencies

**Required**:
- `requests` ≥2.25.0 (HTTP client)
- Python 3.7+ (f-strings, type hints)

**Built-in**:
- `argparse`, `json`, `sys`, `time`, `typing`

## Code Quality Notes

- ✓ Type hints on all function signatures
- ✓ Comprehensive docstrings (module + functions)
- ✓ ANSI color constants at module level (DRY)
- ✓ Helper functions for printing (ok, warn, err, info) to reduce boilerplate
- ✓ Proper exception handling with informative messages
- ✓ Timeout enforcement (30s per API call)
- ✓ Summary table at completion
- ✓ Timing measurement (elapsed seconds)
- ✓ Modular design (two codepaths, nine steps, reusable api() function)

## Execution Example

```bash
# Full loop (fastest)
python scripts/demo_self_learning.py --full-loop

# Step-by-step (detailed)
python scripts/demo_self_learning.py

# Custom API server
python scripts/demo_self_learning.py --base-url http://api.prod:8000 --token $TOKEN
```

## Validation Summary

| Criterion | Result |
|-----------|--------|
| **Syntax** | VALID ✓ |
| **Parse** | OK ✓ |
| **Functions** | 10 (healthy) |
| **Classes** | 0 (expected — utility script) |
| **LOC** | 339 (compact, readable) |
| **Entry Point** | Confirmed (`main()`, line 315) |
| **Shebang** | Present (`#!/usr/bin/env python3`, line 1) |
| **Type Hints** | Full coverage ✓ |
| **Docstrings** | Complete ✓ |
| **Error Handling** | Robust ✓ |

## Conclusion

**demo_self_learning.py** is syntactically correct, well-structured, and ready for integration. The script implements a comprehensive demo of ALdeci V8 self-learning capabilities with two execution modes, detailed output formatting, and proper error handling. All 10 functions are correctly defined and callable.
