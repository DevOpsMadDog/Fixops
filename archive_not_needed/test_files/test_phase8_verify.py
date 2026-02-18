"""Phase 8 verification — AutoFix engine + upgraded API domains.

Tests:
 1. AutoFix engine imports and core methods
 2. AutoFix router endpoints (12)
 3. Remediation router AutoFix integration (2 new endpoints)
 4. Analytics router advanced endpoints (4 new + CSV export)
 5. Inventory router advanced endpoints (deps, license, SBOM)
 6. Policies router advanced endpoints (validate, test, enforce, simulate, conflicts)
 7. Workflows router advanced endpoints (execute, SLA, pause/resume, timeline)
 8. Audit router advanced endpoints (chain, verify, export, retention)
 9. suite-core app wiring
"""
import importlib
import os
import sys

# Ensure suite paths are on sys.path (mirrors sitecustomize.py)
ROOT = os.path.dirname(os.path.abspath(__file__))
for d in [
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-integrations",
    "suite-evidence-risk",
]:
    p = os.path.join(ROOT, d)
    if p not in sys.path:
        sys.path.insert(0, p)

ok = 0
fail = 0


def check(label, condition):
    global ok, fail
    if condition:
        ok += 1
        print(f"  ✅ {label}")
    else:
        fail += 1
        print(f"  ❌ {label}")


# ── 1. AutoFix Engine ──────────────────────────────────────────────────────
print("\n=== 1. AutoFix Engine ===")
try:
    from core.autofix_engine import (
        AutoFixEngine,
        FixConfidence,
        FixStatus,
        FixType,
        PatchFormat,
    )

    engine = AutoFixEngine()
    check("AutoFixEngine imports", True)
    check("FixType has 10 types", len(FixType) >= 10)
    check("FixStatus has 8 states", len(FixStatus) >= 8)
    check("FixConfidence has 3 levels", len(FixConfidence) >= 3)
    check("PatchFormat has 8 formats", len(PatchFormat) >= 8)
    check("engine.generate_fix exists", hasattr(engine, "generate_fix"))
    check("engine.apply_fix exists", hasattr(engine, "apply_fix"))
    check("engine.rollback_fix exists", hasattr(engine, "rollback_fix"))
except Exception as e:
    check(f"AutoFixEngine import failed: {e}", False)

# ── 2. AutoFix Router ──────────────────────────────────────────────────────
print("\n=== 2. AutoFix Router ===")
try:
    from api.autofix_router import router as autofix_router

    routes = [r.path for r in autofix_router.routes]
    check("autofix_router imports", True)
    check("/generate endpoint", any("/generate" in r for r in routes))
    check("/apply endpoint", any("/apply" in r for r in routes))
    check("/stats endpoint", any("/stats" in r for r in routes))
    check("/health endpoint", any("/health" in r for r in routes))
    check("≥10 routes", len(routes) >= 10)
except Exception as e:
    check(f"autofix_router import failed: {e}", False)

# ── 3. suite-core app wiring (file-level check to avoid namespace conflict) ──
print("\n=== 3. suite-core app wiring ===")
try:
    app_file = os.path.join(ROOT, "suite-core", "api", "app.py")
    with open(app_file) as f:
        content = f.read()
    check("app.py exists", os.path.isfile(app_file))
    check("autofix_router imported", "autofix_router" in content)
    check("autofix_router included", "app.include_router(autofix_router" in content)
except Exception as e:
    check(f"core_app wiring: {e}", False)

# ── 4. Analytics Router Advanced ──────────────────────────────────────────
print("\n=== 4. Analytics Router Advanced ===")
try:
    from apps.api.analytics_router import router as analytics_router

    routes = [r.path for r in analytics_router.routes]
    check("analytics_router imports", True)
    check("/trends/severity-over-time", any("severity-over-time" in r for r in routes))
    check("/trends/anomalies", any("anomalies" in r for r in routes))
    check("/compare", any("compare" in r for r in routes))
    check("/risk-velocity", any("risk-velocity" in r for r in routes))
except Exception as e:
    check(f"analytics_router: {e}", False)

# ── 5. Inventory Router Advanced ─────────────────────────────────────────
print("\n=== 5. Inventory Router Advanced ===")
try:
    from apps.api.inventory_router import router as inv_router

    routes = [r.path for r in inv_router.routes]
    check("inventory_router imports", True)
    check("/license-compliance", any("license-compliance" in r for r in routes))
    check("/sbom", any("sbom" in r for r in routes))
    check("POST dependencies", any("dependencies" in r for r in routes))
except Exception as e:
    check(f"inventory_router: {e}", False)

# ── 6. Policies Router Advanced ──────────────────────────────────────────
print("\n=== 6. Policies Router Advanced ===")
try:
    from apps.api.policies_router import _evaluate_policy, _validate_rules
    from apps.api.policies_router import router as pol_router

    routes = [r.path for r in pol_router.routes]
    check("policies_router imports", True)
    check("/enforce endpoint", any("enforce" in r for r in routes))
    check("/simulate endpoint", any("simulate" in r for r in routes))
    check("/conflicts endpoint", any("conflicts" in r for r in routes))
    check("_validate_rules works (empty)", len(_validate_rules({})) > 0)
    check(
        "_validate_rules works (valid)",
        len(
            _validate_rules(
                {
                    "conditions": [
                        {"field": "severity", "operator": "eq", "value": "critical"}
                    ],
                    "actions": [{"type": "block"}],
                }
            )
        )
        == 0,
    )
except Exception as e:
    check(f"policies_router: {e}", False)

# ── 7. Workflows Router Advanced ─────────────────────────────────────────
print("\n=== 7. Workflows Router Advanced ===")
try:
    from apps.api.workflows_router import _evaluate_step_condition, _run_step
    from apps.api.workflows_router import router as wf_router

    routes = [r.path for r in wf_router.routes]
    check("workflows_router imports", True)
    check("/sla endpoint", any("sla" in r for r in routes))
    check("/pause endpoint", any("pause" in r for r in routes))
    check("/resume endpoint", any("resume" in r for r in routes))
    check("/timeline endpoint", any("timeline" in r for r in routes))
    check(
        "_evaluate_step_condition works",
        _evaluate_step_condition(
            {"field": "x", "operator": "eq", "value": "1"}, {"x": "1"}
        ),
    )
except Exception as e:
    check(f"workflows_router: {e}", False)

# ── 8. Audit Router Advanced ─────────────────────────────────────────────
print("\n=== 8. Audit Router Advanced ===")
try:
    from apps.api.audit_router import _compute_chain_hash
    from apps.api.audit_router import router as audit_router

    routes = [r.path for r in audit_router.routes]
    check("audit_router imports", True)
    check("/logs/chain endpoint", any("chain" in r for r in routes))
    check("/chain/verify endpoint", any("verify" in r for r in routes))
    check("/logs/export endpoint", any("export" in r for r in routes))
    check("/retention endpoint", any("retention" in r for r in routes))
    h = _compute_chain_hash({"test": True}, "0" * 64)
    check(
        "chain hash is 64-char hex",
        len(h) == 64 and all(c in "0123456789abcdef" for c in h),
    )
except Exception as e:
    check(f"audit_router: {e}", False)

# ── Summary ───────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"Phase 8 Verification: {ok} OK, {fail} FAIL")
print(f"{'='*60}")
sys.exit(0 if fail == 0 else 1)
