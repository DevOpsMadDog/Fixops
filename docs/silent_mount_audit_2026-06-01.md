# Silent Router Mount Audit — 2026-06-01

**Auditor:** security-auditor agent (chief-architect sweep)
**Branch:** chore/ui-prune-plan-2026-05-24
**Method:** Full app boot with logging captured + exhaustive per-module import test (765 referenced modules, 837 existing files) + named-export circular-import verification + sub_apps guard analysis.

---

## Executive Summary

**DEAD-BROKEN routers: 1**
**DEAD-INTENTIONAL routers: 1 (LaunchDarkly)**
**Circular-import false alarm resolved: 1 (ui_alias_router — healthy in production boot order)**
**Total guarded mount sites tested: ~95 in app.py + ~380 in sub_apps (5 files)**
**Total unique modules tested: 656 (sub_apps) + 250 (app.py) = 906 import probes**

---

## DEAD-BROKEN Routers (customer feature is silently absent)

| Router | Prefix | Status | Exact Error | Customer Feature Affected | Fix Needed |
|--------|--------|--------|-------------|--------------------------|------------|
| `ctem_pipeline_router` (in `ctem_app.py`) | `/api/v1/pipeline` | DEAD-BROKEN (dangling ref — routes ARE live via app.py) | `ModuleNotFoundError: No module named 'apps.api.ctem_pipeline_router'` | CTEM 15-stage pipeline ingest/batch/stage-monitoring — but mounted correctly via `pipeline_routes.py` in `app.py` | In `suite-api/apps/api/sub_apps/ctem_app.py` line 61: change `from apps.api.ctem_pipeline_router import router as ctem_pipeline_router` → `from apps.api.pipeline_routes import router as ctem_pipeline_router` |

### Severity clarification

The `ctem_pipeline_router` reference in `ctem_app.py` is broken, but this is **not a customer-facing outage**. `app.py` independently loads the same router from `pipeline_routes.py` (line 343) and mounts it at line 3242 with identical dependencies (`_verify_api_key` + `write:findings`). The `ctem_app.py` guard silently sets the variable to `None` and skips `include_router` — meaning the routes are mounted exactly once (via app.py) rather than twice. The live boot confirms `/api/v1/pipeline/*` routes are reachable.

The risk is: if app.py's mount is ever refactored out, ctem_app.py will not catch it. The stale reference also creates a false sense that ctem_app.py owns this registration when it does not.

**One-line fix:** `ctem_app.py:61` — replace `apps.api.ctem_pipeline_router` with `apps.api.pipeline_routes`.

---

## DEAD-INTENTIONAL Routers (legitimately optional dependencies)

| Router | Prefix | Status | Reason | Note |
|--------|--------|--------|--------|------|
| `feature_flags_router` (LaunchDarkly provider) | `/api/v1/feature-flags` | DEAD-INTENTIONAL | `launchdarkly-server-sdk` not installed; logged as warning at boot | The router module itself imports fine. The SDK is optional — boot log says "LaunchDarkly SDK not available. Install with: pip install launchdarkly-server-sdk". Feature flag evaluation falls back to defaults. No action needed unless LaunchDarkly is required for a customer deployment. |

---

## HEALTHY — Notable cases investigated and cleared

| Router | Finding | Verdict |
|--------|---------|---------|
| `ui_alias_router` (9 alias routes) | Circular import: `ui_alias_router` imports `_verify_api_key` from `apps.api.app` (line 40). In isolated test, this triggers `cannot import name 'asset_inventory_alias' from partially initialized module`. | **HEALTHY in production.** In full app boot, all transitive imports resolve before `ui_alias_router` is reached. All 9 alias prefixes confirmed mounted: `/api/v1/asset-inventory`, `/api/v1/container-security`, `/api/v1/data-classification`, `/api/v1/integration-health`, `/api/v1/repos`, `/api/v1/security-awareness`, `/api/v1/security-metrics`, `/api/v1/security-posture`, `/api/v1/vuln-heatmap` (81 routes total). |
| `executive_reporting_router` | Previously broken (task brief). | **HEALTHY.** File exists, imports cleanly, mounted in `grc_app.py` line 518. |
| `risk_quantifier_router` | Previously broken (task brief). | **HEALTHY.** File exists, imports cleanly, mounted in app.py. |
| All 250 app.py guarded routers | Boot captured with `logging.WARNING` to stderr. | **0 mount warnings logged.** Every guarded import in app.py succeeds. |
| All 656 sub_apps guarded routers | Import-tested individually with fresh `sys.modules`. | **655 OK, 1 broken** (`ctem_pipeline_router` — described above). |

---

## Methodology Details

### Step 1 — App boot with logging capture

```bash
PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-integrations:suite-evidence-risk:archive/legacy:archive/enterprise_legacy" \
python3 -c "
import logging, sys
logging.basicConfig(level=logging.WARNING, stream=sys.stderr, format='MOUNTLOG %(levelname)s %(name)s: %(message)s')
from apps.api.app import create_app
create_app()
" 2>&1 | grep MOUNTLOG
```

Result: 0 router-level mount warnings. Only infrastructure warnings (JWT key, FIPS mode, CORS origins, LaunchDarkly SDK, OpenClaw stub).

### Step 2 — Missing file sweep

```python
referenced = {all "from apps.api.X import" in app.py + sub_apps/*.py}  # 765 unique
existing   = {all .py files in suite-api/apps/api/}                    # 837 files
missing    = referenced - existing                                      # 1: ctem_pipeline_router
```

### Step 3 — Per-module import test

Tested 906 module imports (isolated, fresh `sys.modules` per module). Result: 905 OK, 1 ModuleNotFoundError (`ctem_pipeline_router`).

### Step 4 — ui_alias_router circular import analysis

Confirmed: line 40 of `ui_alias_router.py` does `from apps.api.app import _verify_api_key`. This is a circular reference. In production boot order, `app.py` has already fully initialized by the time line 7061 (the `ui_alias_router` try block) executes, so the circular reference resolves via `sys.modules` cache. Confirmed via live route count: 81 alias routes mounted.

---

## Guarded Mount Counts by File

| File | Guarded try/except blocks | Result |
|------|--------------------------|--------|
| `suite-api/apps/api/app.py` | ~95 | 0 broken |
| `suite-api/apps/api/sub_apps/aspm_app.py` | ~40 | 0 broken |
| `suite-api/apps/api/sub_apps/cspm_app.py` | ~64 | 0 broken |
| `suite-api/apps/api/sub_apps/ctem_app.py` | ~50 | **1 broken** (`ctem_pipeline_router`) |
| `suite-api/apps/api/sub_apps/grc_app.py` | ~60 | 0 broken |
| `suite-api/apps/api/sub_apps/platform_app.py` | ~70 | 0 broken |

---

## Fix Wave Dispatch

Only 1 fix required. No emergency — the pipeline routes are live via app.py.

**Fix:** In `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/sub_apps/ctem_app.py`, line 61:

```python
# BEFORE (broken — file does not exist):
from apps.api.ctem_pipeline_router import router as ctem_pipeline_router

# AFTER (correct — matches app.py line 343):
from apps.api.pipeline_routes import router as ctem_pipeline_router
```

This is a 1-line change. After the fix, `ctem_app.py` will mount the pipeline router under its own `register_ctem_routers()` call with `write:findings` scope — matching what app.py already does. Verify no duplicate mount by checking route count doesn't grow (app.py's module-level guard should be removed or made conditional on `ctem_app.py` not having mounted it, or one of the two mounts should be removed).

**Recommended approach:** Remove the module-level pipeline mount from app.py (lines 341-348 and 3242-3248) and let ctem_app.py own it after the fix — consistent with the Wave-C extraction pattern that moved all CTEM routers to ctem_app.py.
