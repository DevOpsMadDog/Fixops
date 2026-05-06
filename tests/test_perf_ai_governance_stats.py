"""Perf test #22 — AIGovernanceEngine.get_governance_stats.

Validates that the 7→5 query collapse (Multica #4053) cuts wall-clock time
on realistic data sets.  Three cases:

  small  — 10 models / 5 assessments / 5 incidents
  medium — 100 models / 50 assessments / 50 incidents
  large  — 500 models / 200 assessments / 200 incidents

Correctness is asserted on every case; timing is printed and the large-case
must complete in < 0.5 s (SQLite, in-memory file, no network).
"""

from __future__ import annotations

import os
import tempfile
import time
import uuid

import pytest

from core.ai_governance_engine import AIGovernanceEngine


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_MODEL_TYPES = ["llm", "classification", "regression", "nlp", "recommendation"]
_RISK_LEVELS = ["critical", "high", "medium", "low"]
_STATUSES = ["development", "staging", "production", "retired"]


def _make_engine() -> tuple[AIGovernanceEngine, str]:
    """Return a fresh engine backed by a temp file (auto-deleted on test exit)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    eng = AIGovernanceEngine(db_path=tmp.name)
    return eng, tmp.name


def _seed(eng: AIGovernanceEngine, org_id: str,
          n_models: int, n_assessments: int, n_incidents: int) -> None:
    """Insert n_models models plus assessments + incidents for each."""
    model_ids: list[str] = []
    for i in range(n_models):
        mt = _MODEL_TYPES[i % len(_MODEL_TYPES)]
        rl = _RISK_LEVELS[i % len(_RISK_LEVELS)]
        ds = _STATUSES[i % len(_STATUSES)]
        rec = eng.register_model(org_id, {
            "model_name": f"model-{i}",
            "model_type": mt,
            "deployment_status": ds,
            "risk_level": rl,
            "vendor": "acme",
            "version": "1.0",
        })
        model_ids.append(rec["id"])

    for i in range(n_assessments):
        mid = model_ids[i % len(model_ids)]
        eng.record_assessment(org_id, {
            "model_id": mid,
            "assessment_type": "performance",
            "score": 75.0,
            "findings": [],
        })

    for i in range(n_incidents):
        mid = model_ids[i % len(model_ids)]
        eng.report_incident(org_id, {
            "model_id": mid,
            "incident_type": "drift",
            "severity": "medium",
            "description": f"incident-{i}",
        })


def _assert_stats_correct(stats: dict, n_models: int,
                           n_assessments: int, n_incidents: int) -> None:
    assert stats["total_models"] == n_models
    assert stats["total_assessments"] == n_assessments
    assert stats["total_incidents"] == n_incidents
    assert stats["open_incidents"] == n_incidents  # none resolved
    assert isinstance(stats["by_type"], dict)
    assert isinstance(stats["by_risk_level"], dict)
    assert sum(stats["by_type"].values()) == n_models
    assert sum(stats["by_risk_level"].values()) == n_models


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

class TestGovernanceStatsPerfSmall:
    """10 models / 5 assessments / 5 incidents."""

    def test_correctness_and_speed(self):
        eng, db_path = _make_engine()
        org_id = str(uuid.uuid4())
        _seed(eng, org_id, 10, 5, 5)

        t0 = time.perf_counter()
        stats = eng.get_governance_stats(org_id)
        elapsed = time.perf_counter() - t0

        print(f"\n[small] elapsed={elapsed*1000:.2f} ms")
        _assert_stats_correct(stats, 10, 5, 5)
        assert elapsed < 0.5, f"small case too slow: {elapsed:.3f}s"

        os.unlink(db_path)


class TestGovernanceStatsPerfMedium:
    """100 models / 50 assessments / 50 incidents."""

    def test_correctness_and_speed(self):
        eng, db_path = _make_engine()
        org_id = str(uuid.uuid4())
        _seed(eng, org_id, 100, 50, 50)

        t0 = time.perf_counter()
        stats = eng.get_governance_stats(org_id)
        elapsed = time.perf_counter() - t0

        print(f"\n[medium] elapsed={elapsed*1000:.2f} ms")
        _assert_stats_correct(stats, 100, 50, 50)
        assert elapsed < 0.5, f"medium case too slow: {elapsed:.3f}s"

        os.unlink(db_path)


class TestGovernanceStatsPerfLarge:
    """500 models / 200 assessments / 200 incidents — primary perf gate."""

    def test_correctness_and_speed(self):
        eng, db_path = _make_engine()
        org_id = str(uuid.uuid4())
        _seed(eng, org_id, 500, 200, 200)

        # warm-up (schema already init'd; this ensures no init overhead in timing)
        eng.get_governance_stats(org_id)

        t0 = time.perf_counter()
        stats = eng.get_governance_stats(org_id)
        elapsed = time.perf_counter() - t0

        print(f"\n[large] elapsed={elapsed*1000:.2f} ms")
        _assert_stats_correct(stats, 500, 200, 200)
        assert elapsed < 0.5, f"large case too slow: {elapsed:.3f}s"

        os.unlink(db_path)
