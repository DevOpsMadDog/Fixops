"""
tests/test_honest_compliance.py — AC-006-03 (SPEC-006)

Asserts that unconfigured / simulated-only controls are NEVER reported as
'passing' and that they do not inflate the compliance score.
"""
from __future__ import annotations

import sys
import os

# Ensure suite paths are on sys.path (mirrors sitecustomize.py for direct pytest runs)
for _d in ("suite-core", "suite-api", "suite-evidence-risk"):
    _p = os.path.join(os.path.dirname(__file__), "..", _d)
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, os.path.abspath(_p))

import pytest
from core.compliance_engine import (
    ComplianceAutomationEngine,
    ControlStatus,
    FRAMEWORKS,
    _check_rbac_config,
    _check_scan_results,
    _check_encryption_settings,
    _check_audit_logs,
    _check_config_snapshot,
    _check_policy_exists,
    _check_incident_reports,
    _check_training_records,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIMULATED_CHECKS = [
    ("_check_rbac_config",       _check_rbac_config),
    ("_check_scan_results",      _check_scan_results),
    ("_check_encryption_settings", _check_encryption_settings),
    ("_check_audit_logs",        _check_audit_logs),
    ("_check_config_snapshot",   _check_config_snapshot),
    ("_check_policy_exists",     _check_policy_exists),
    ("_check_incident_reports",  _check_incident_reports),
    ("_check_training_records",  _check_training_records),
]


# ---------------------------------------------------------------------------
# AC-006-01: no simulated check returns True (passing) when source is
#            not_configured / absent.  Every previously-simulated function
#            must return is_passing=False when real modules are unavailable.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,fn", _SIMULATED_CHECKS)
def test_no_simulated_pass(name, fn):
    """Previously-simulated checks must NOT return True when unconfigured."""
    is_passing, source_module, data = fn()
    # If source is not_configured the check has no real evidence → must not pass
    if data.get("source") == "not_configured":
        assert is_passing is False, (
            f"{name}: returned is_passing=True with source='not_configured' "
            f"— this is a Category-I misrepresentation (SPEC-006 REQ-006-01)"
        )


# ---------------------------------------------------------------------------
# AC-006-01 (explicit): "simulated" must never appear as source on a passing check
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,fn", _SIMULATED_CHECKS)
def test_simulated_source_never_passing(name, fn):
    """source='simulated' must never be paired with is_passing=True."""
    is_passing, _src, data = fn()
    if data.get("source") == "simulated":
        assert is_passing is False, (
            f"{name}: source='simulated' but is_passing=True — "
            f"fabricated passing result (SPEC-006 REQ-006-01)"
        )


# ---------------------------------------------------------------------------
# AC-006-02: SC-28 / encryption-at-rest specifically
#            When AppConfig is absent (fresh env), must NOT be 'passing'.
# ---------------------------------------------------------------------------

def test_encryption_check_not_passing_when_unconfigured():
    """_check_encryption_settings: returns False when config absent (SC-28)."""
    is_passing, _src, data = _check_encryption_settings()
    # In test env AppConfig is unavailable or lacks explicit flags → not passing
    if data.get("source") in ("not_configured", "simulated"):
        assert is_passing is False, (
            "SC-28 encryption-at-rest reported as passing without real config "
            "(REQ-006-02)"
        )


# ---------------------------------------------------------------------------
# AC-006-03: overall score must not be inflated by NOT_ASSESSED controls
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return ComplianceAutomationEngine(
        db_path=str(tmp_path / "honest_compliance.db"),
        org_id="test-org",
    )


def test_not_assessed_excluded_from_score(engine):
    """
    After evidence collection, NOT_ASSESSED controls must not count toward
    total_weight (denominator) so the score is not inflated.
    """
    framework = "NIST-800-53"
    engine.collect_evidence(framework)
    status = engine.get_framework_status(framework)

    not_assessed_count = status["status_breakdown"].get(
        ControlStatus.NOT_ASSESSED.value, 0
    )
    passing_count = status["status_breakdown"].get(
        ControlStatus.PASSING.value, 0
    )
    total_controls = status["total_controls"]
    score = status["score"]

    # If every assessable control is not_assessed, score must be 0
    assessable = total_controls - not_assessed_count
    if assessable == 0:
        assert score == 0.0, (
            f"All controls are not_assessed but score={score} — "
            f"denominator must be 0 → score 0 (REQ-006-03)"
        )
    else:
        # Score must be computed over assessable controls only
        max_possible = round(passing_count / assessable * 100, 2)
        assert score <= max_possible + 0.01, (
            f"score={score} exceeds max_possible={max_possible} given "
            f"passing={passing_count} assessable={assessable} — "
            f"NOT_ASSESSED must be excluded from denominator (REQ-006-03)"
        )


def test_unconfigured_control_is_not_passing_status(engine):
    """
    After evidence collection all controls with not_configured source must
    have status NOT_ASSESSED or FAILING — never PASSING.
    """
    framework = "FedRAMP"
    engine.collect_evidence(framework)
    status = engine.get_framework_status(framework)

    for ctrl in status["controls"]:
        assert ctrl["status"] != ControlStatus.PASSING.value or ctrl.get(
            "evidence_count", 0
        ) > 0, (
            f"Control {ctrl['id']} is PASSING but has no evidence — "
            f"simulated pass leak (REQ-006-01)"
        )


def test_collect_evidence_no_simulated_source_in_db(engine, tmp_path):
    """
    After collect_evidence, no stored evidence row should carry
    source='simulated' paired with is_passing=True.
    """
    framework = "SOC2"
    items = engine.collect_evidence(framework)
    for item in items:
        data = item.data if hasattr(item, "data") else {}
        if data.get("source") == "simulated":
            assert not item.is_passing, (
                f"Evidence item for {item.control_ids} has source='simulated' "
                f"and is_passing=True — fabricated pass (REQ-006-01)"
            )


# ---------------------------------------------------------------------------
# AC-006-03 addendum: overall_status score cannot exceed honest passing rate
# ---------------------------------------------------------------------------

def test_overall_status_score_honest(engine):
    """get_overall_status score must reflect only controls with real evidence."""
    for fw in FRAMEWORKS:
        engine.collect_evidence(fw)

    overall = engine.get_overall_status()
    # Score must be a valid percentage
    assert 0.0 <= overall["overall_score"] <= 100.0

    # Passing controls must be <= total assessable controls
    passing = overall["total_passing_across_all_frameworks"]
    total = overall["total_controls_across_all_frameworks"]
    assert passing <= total, (
        f"passing={passing} > total={total} — accounting error in score"
    )
