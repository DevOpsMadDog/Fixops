"""Wave 3A+3B — Tests for FunctionReachability + AttackGraphGNN integration
into BrainPipeline (helpers `_apply_reachability_verdicts` step 6 post-fusion
and `_run_attack_graph_gnn` step 7).
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on path (sitecustomize already handles this in app run)
ROOT = Path(__file__).resolve().parents[1]
SUITE_CORE = ROOT / "suite-core"
if str(SUITE_CORE) not in sys.path:
    sys.path.insert(0, str(SUITE_CORE))

from core.brain_pipeline import BrainPipeline  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _bare_pipeline() -> BrainPipeline:
    """Return a BrainPipeline instance bypassing __init__ for unit-style tests."""
    return BrainPipeline.__new__(BrainPipeline)


def _mk_finding(**kw):
    base = {
        "id": "f-1",
        "cve_id": "CVE-2024-0001",
        "package_name": "requests",
        "severity": "high",
        "consensus_priority": 2,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Reachability tests
# ---------------------------------------------------------------------------

def test_reachability_marks_reachable():
    """When engine returns callers, finding is marked reachable=True."""
    bp = _bare_pipeline()
    fake_caller = {
        "cve_id": "CVE-2024-0001",
        "caller_fqn": "app.handler.do_thing",
        "caller_source_file": "app/handler.py",
        "target_fqn": "requests.Session.mount",
        "path": ["app.handler.do_thing", "requests.Session.mount"],
    }
    fake_engine = MagicMock()
    fake_engine.vulnerable_reachability.return_value = [fake_caller]
    fake_engine.record_finding_verdict.return_value = {"id": "v-1"}

    findings = [_mk_finding()]
    ctx = {"org_id": "org-x", "findings": findings}

    with patch("core.function_reachability_engine.get_engine", return_value=fake_engine):
        bp._apply_reachability_verdicts(ctx)

    f = findings[0]
    assert f["reachable"] is True
    assert f["reachable_callers"] == [fake_caller]
    assert f["reachability_verdict"] == "reachable"
    fake_engine.record_finding_verdict.assert_called_once()


def test_reachability_marks_unreachable_and_downgrades():
    """When engine returns no callers, finding is unreachable and priority bumped."""
    bp = _bare_pipeline()
    fake_engine = MagicMock()
    fake_engine.vulnerable_reachability.return_value = []
    fake_engine.record_finding_verdict.return_value = {"id": "v-2"}

    findings = [_mk_finding(consensus_priority=2)]
    ctx = {"org_id": "org-x", "findings": findings}

    with patch("core.function_reachability_engine.get_engine", return_value=fake_engine):
        bp._apply_reachability_verdicts(ctx)

    f = findings[0]
    assert f["reachable"] is False
    assert f["reachable_callers"] == []
    assert f["reachability_verdict"] == "unreachable"
    # Priority should be bumped from 2 → 3 (higher number = lower priority)
    assert f["consensus_priority"] == 3


def test_reachability_skips_findings_without_cve_or_pattern():
    """Findings without cve_id are skipped; engine never queried."""
    bp = _bare_pipeline()
    fake_engine = MagicMock()
    fake_engine.vulnerable_reachability.return_value = []

    findings = [
        {"id": "f-x", "package_name": "requests"},  # no cve_id
        {"id": "f-y", "cve_id": "CVE-X"},  # no package_name → empty pattern
    ]
    ctx = {"org_id": "org-x", "findings": findings}

    with patch("core.function_reachability_engine.get_engine", return_value=fake_engine):
        bp._apply_reachability_verdicts(ctx)

    fake_engine.vulnerable_reachability.assert_not_called()
    assert "reachable" not in findings[0]
    assert "reachable" not in findings[1]


# ---------------------------------------------------------------------------
# Attack Graph GNN tests
# ---------------------------------------------------------------------------

def test_attack_graph_gnn_builds_security_graph():
    """SecurityGraph built from assets + findings; ctx.attack_paths populated."""
    bp = _bare_pipeline()

    assets = [
        {"id": "a-1", "criticality_score": 0.9, "name": "api"},
        {"id": "a-2", "criticality_score": 0.4, "name": "db"},
    ]
    findings = [
        {"id": "f-1", "cve_id": "CVE-1", "asset_id": "a-1", "cvss_score": 8.5},
        {"id": "f-2", "cve_id": "CVE-2", "asset_id": "a-2", "cvss_score": 6.0},
        {"id": "f-3", "cve_id": "CVE-3", "asset_id": "a-1", "cvss": 7.0},
    ]
    ctx = {"org_id": "org-x", "assets": assets, "findings": findings}

    # Stub event bus to avoid heavy MiniLM/TrustGraph import on cold start
    fake_bus = MagicMock()

    async def _emit(*a, **kw):
        return None

    fake_bus.emit = MagicMock(side_effect=_emit)

    with patch("core.trustgraph_event_bus.get_event_bus", return_value=fake_bus):
        bp._run_attack_graph_gnn(ctx)

    assert "attack_paths" in ctx
    assert isinstance(ctx["attack_paths"], list)
    # 2 assets + 3 vulnerabilities = 5 nodes
    assert ctx["graph_nodes"] == 5
    # 3 AFFECTS edges between assets and vulns
    assert ctx["graph_edges"] == 3


def test_attack_graph_gnn_emits_threat_detected():
    """Top attack paths emit threat.detected events with engine='attack_graph_gnn'."""
    bp = _bare_pipeline()

    fake_path = MagicMock()
    fake_path.to_dict.return_value = {
        "summary": "a-1 → f-1",
        "entry": "a-1",
        "path": ["a-1", "f-1"],
        "probability": 0.8,
        "impact_score": 0.9,
    }

    fake_bus = MagicMock()

    async def _emit(*a, **kw):
        return None

    fake_bus.emit = MagicMock(side_effect=_emit)

    fake_predictor_cls = MagicMock()
    fake_predictor = MagicMock()
    fake_predictor.find_attack_paths.return_value = [fake_path, fake_path, fake_path, fake_path]
    fake_predictor_cls.return_value = fake_predictor

    assets = [{"id": "a-1", "criticality_score": 0.9}]
    findings = [{"id": "f-1", "cve_id": "CVE-1", "asset_id": "a-1", "cvss_score": 8.0}]
    ctx = {"org_id": "org-x", "assets": assets, "findings": findings}

    with patch("core.attack_graph_gnn.GraphNeuralPredictor", fake_predictor_cls), \
         patch("core.trustgraph_event_bus.get_event_bus", return_value=fake_bus):
        bp._run_attack_graph_gnn(ctx)

    # 3 emits for top 3 paths
    assert fake_bus.emit.call_count == 3
    # Verify event_type and engine kwarg
    call_args = fake_bus.emit.call_args_list[0]
    assert call_args[0][0] == "threat.detected"
    payload = call_args[0][1]
    assert payload["engine"] == "attack_graph_gnn"
    assert payload["entity_type"] == "attack_path"


def test_both_helpers_swallow_exceptions():
    """Both helpers must never raise — pipeline robustness invariant."""
    bp = _bare_pipeline()

    # Reachability helper: engine import fails by raising on get_engine
    findings = [_mk_finding()]
    ctx_r = {"org_id": "org-x", "findings": findings}
    with patch(
        "core.function_reachability_engine.get_engine",
        side_effect=RuntimeError("engine kaboom"),
    ):
        bp._apply_reachability_verdicts(ctx_r)  # must not raise
    # Findings should NOT have reachable annotations because engine blew up
    assert "reachable" not in findings[0]

    # GNN helper: predictor blows up
    ctx_g = {
        "org_id": "org-x",
        "assets": [{"id": "a-1", "criticality_score": 0.5}],
        "findings": [{"id": "f-1", "cve_id": "CVE-1", "asset_id": "a-1"}],
    }
    with patch(
        "core.attack_graph_gnn.GraphNeuralPredictor",
        side_effect=RuntimeError("gnn kaboom"),
    ):
        bp._run_attack_graph_gnn(ctx_g)  # must not raise
    # attack_paths should NOT be populated when GNN explodes early
    assert "attack_paths" not in ctx_g
