"""
Perf assertions for the misc hotspot fixes:
  1. secret_scanner_engine  — executemany replaces per-row execute loop
  2. decision_engine         — asyncio.gather for independent fallback awaits
  3. intelligent_security_engine — parallel _validate_findings
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import asyncio
import sys
import time
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure suite-core/core is on path (mirrors sitecustomize.py)
_SUITE_CORE = Path(__file__).resolve().parents[1] / "suite-core"
if str(_SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(_SUITE_CORE))

_ENTERPRISE = _SUITE_CORE / "core" / "services" / "enterprise"
if str(_ENTERPRISE.parent) not in sys.path:
    sys.path.insert(0, str(_ENTERPRISE.parent))


# ---------------------------------------------------------------------------
# 1. SecretScannerEngine — executemany
# ---------------------------------------------------------------------------

def test_secret_scanner_simulate_uses_executemany():
    """_simulate_scan must call executemany once, not execute N times for INSERT."""
    pytest = __import__("pytest")
    SecretScannerEngine = pytest.importorskip(
        "core.secret_scanner_engine", reason="secret_scanner_engine not importable"
    ).SecretScannerEngine

    engine = SecretScannerEngine.__new__(SecretScannerEngine)
    engine.org_id = "perf-test-org"
    engine._lock = threading.RLock()

    execute_calls: list = []
    executemany_calls: list = []

    fake_conn = MagicMock()
    fake_conn.__enter__ = lambda s: s
    fake_conn.__exit__ = MagicMock(return_value=False)
    fake_conn.execute = lambda *a, **kw: execute_calls.append(a)
    fake_conn.executemany = lambda *a, **kw: executemany_calls.append(a)

    job = {"id": "job-1", "target_type": "git_repo", "org_id": "perf-test-org"}

    with patch.object(engine, "_conn", return_value=fake_conn):
        engine._simulate_scan("perf-test-org", job)

    insert_executes = [c for c in execute_calls if "INSERT INTO secret_findings" in str(c)]
    assert len(insert_executes) == 0, (
        f"execute() called {len(insert_executes)} times for INSERT — should use executemany"
    )
    assert len(executemany_calls) == 1, (
        f"executemany() called {len(executemany_calls)} times — expected 1"
    )


# ---------------------------------------------------------------------------
# 2. DecisionEngine fallback — asyncio.gather for independent awaits
# ---------------------------------------------------------------------------

def test_decision_engine_fallback_uses_gather():
    """The four independent fallback awaits must run concurrently via asyncio.gather."""
    import pytest as _pytest

    decision_mod = _pytest.importorskip(
        "core.services.enterprise.decision_engine",
        reason="decision_engine enterprise deps not available",
    )
    DecisionEngine = decision_mod.DecisionEngine
    DecisionContext = decision_mod.DecisionContext
    DecisionOutcome = decision_mod.DecisionOutcome

    call_log: list[str] = []

    async def fake_enrichment(ctx):
        call_log.append("enrichment")
        return {"sources": []}

    async def fake_vdb(ctx, enriched):
        call_log.append("vdb")
        await asyncio.sleep(0.02)
        return {"status": "ok", "confidence": 0.8, "patterns_matched": 0}

    async def fake_regression(ctx):
        call_log.append("regression")
        await asyncio.sleep(0.02)
        return {
            "status": "no_coverage", "confidence": 0.5, "validation_passed": False,
            "matched_cases": [], "counts": {}, "failures": [], "coverage": {},
        }

    async def fake_policy(ctx, enriched):
        call_log.append("policy")
        await asyncio.sleep(0.02)
        return {
            "status": "evaluated", "overall_decision": True, "confidence": 0.9,
            "decision_type": "allow", "rationale": "ok",
        }

    async def fake_criticality(ctx):
        call_log.append("criticality")
        await asyncio.sleep(0.02)
        return {"status": "no_sbom", "criticality": "unknown", "tools_used": []}

    async def fake_consensus(vdb, reg, pol, crit):
        return {
            "confidence": 0.9, "threshold_met": True, "component_scores": {},
            "weights": {}, "oss_tools_used": [], "policy_evaluations": "ok",
        }

    async def fake_final(consensus):
        return {"outcome": DecisionOutcome.ALLOW, "reasoning": "ok", "confidence": 0.9}

    async def fake_evidence(ctx, decision, consensus):
        return "EVD-test-001"

    engine = DecisionEngine.__new__(DecisionEngine)
    engine.processing_layer = None

    ctx = DecisionContext(
        service_name="test-svc",
        environment="staging",
        business_context={},
        security_findings=[],
    )

    start = time.perf_counter()
    with (
        patch.object(engine, "_real_context_enrichment", side_effect=fake_enrichment),
        patch.object(engine, "_real_vector_db_lookup", side_effect=fake_vdb),
        patch.object(engine, "_real_golden_regression_validation", side_effect=fake_regression),
        patch.object(engine, "_real_policy_evaluation", side_effect=fake_policy),
        patch.object(engine, "_real_sbom_criticality_assessment", side_effect=fake_criticality),
        patch.object(engine, "_real_consensus_checking", side_effect=fake_consensus),
        patch.object(engine, "_real_final_decision", side_effect=fake_final),
        patch.object(engine, "_real_evidence_generation", side_effect=fake_evidence),
    ):
        asyncio.run(engine._make_production_decision(ctx, time.perf_counter()))

    elapsed = time.perf_counter() - start

    # Serial = ~0.08 s (4 × 0.02 s); parallel should be well under 0.07 s
    assert elapsed < 0.07, (
        f"Fallback awaits appear sequential ({elapsed:.3f}s >= 0.07s) — gather not applied"
    )
    assert set(call_log) == {"enrichment", "vdb", "regression", "policy", "criticality"}


# ---------------------------------------------------------------------------
# 3. IntelligentSecurityEngine._validate_findings — parallel gather
# ---------------------------------------------------------------------------

def test_validate_findings_runs_in_parallel():
    """_validate_findings must dispatch all findings concurrently, not serially."""
    import pytest as _pytest

    ise_mod = _pytest.importorskip(
        "core.intelligent_security_engine",
        reason="intelligent_security_engine deps not available",
    )
    IntelligentSecurityEngine = ise_mod.IntelligentSecurityEngine
    EngineConfig = ise_mod.EngineConfig

    engine = IntelligentSecurityEngine.__new__(IntelligentSecurityEngine)
    engine.config = EngineConfig()

    findings = [
        {"title": f"Finding {i}", "severity": "high", "description": "desc", "evidence": "ev"}
        for i in range(4)
    ]

    fake_result = MagicMock()
    fake_result.consensus = True
    fake_result.action = "confirm"
    fake_result.confidence = 0.9

    def slow_analyse(*args, **kwargs):
        time.sleep(0.02)  # 20 ms per finding — 4 × serial = 80 ms
        return fake_result

    mock_engine = MagicMock()
    mock_engine.analyse = slow_analyse

    with patch.object(ise_mod, "_get_consensus_engine", return_value=mock_engine):
        start = time.perf_counter()
        result = asyncio.run(engine._validate_findings(findings))
        elapsed = time.perf_counter() - start

    assert len(result) == 4
    # Serial ≈ 0.08 s; parallel should finish well under 0.07 s
    assert elapsed < 0.07, (
        f"_validate_findings appears serial ({elapsed:.3f}s >= 0.07s) — gather not applied"
    )
