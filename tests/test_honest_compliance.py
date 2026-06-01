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


# ---------------------------------------------------------------------------
# SPEC-006 new findings — 3 fabricated-pass paths closed 2026-06-01
# ---------------------------------------------------------------------------

# --- Finding 1: _check_config_snapshot always-pass via `cfg is not None` ---

def test_config_snapshot_empty_db_is_not_passing():
    """
    _check_config_snapshot with no persisted app configs must NOT return True.
    A fresh env has no records in the DB; `AppConfig()` always constructs
    successfully so the old `cfg is not None` was structurally always True.
    """
    from core.compliance_engine import _check_config_snapshot  # type: ignore

    is_passing, source_module, data = _check_config_snapshot()
    # With no real apps in the DB the check has no real evidence
    if data.get("source") in ("not_configured", "measured") and data.get("app_count", 0) == 0:
        assert is_passing is False, (
            "_check_config_snapshot returned True with app_count=0 — "
            "constructor truthiness was used as a pass signal (SPEC-006 Finding 1)"
        )


def test_config_snapshot_source_is_not_simulated():
    """_check_config_snapshot must never return source='simulated'."""
    from core.compliance_engine import _check_config_snapshot  # type: ignore

    _is_passing, _src, data = _check_config_snapshot()
    assert data.get("source") != "simulated", (
        "_check_config_snapshot still reports source='simulated' — "
        "fabricated pass still present (SPEC-006 Finding 1)"
    )


# --- Finding 2: suite-evidence-risk score inflation via scan-CWE on non-technical controls ---

def test_scan_finding_does_not_satisfy_policy_control(tmp_path):
    """
    A single SAST scan finding mapped to a POLICY_CHECK control must NOT
    elevate that control to PARTIALLY_SATISFIED.  Policy/training/physical
    controls require their own evidence types; scan findings do not substitute.
    """
    import os as _os
    _er = _os.path.join(_os.path.dirname(__file__), "..", "suite-evidence-risk")
    if _os.path.isdir(_er) and _er not in sys.path:
        sys.path.insert(0, _os.path.abspath(_er))

    from compliance.compliance_engine import (  # type: ignore
        ComplianceEngine,
        ComplianceDB,
        Framework,
        ControlStatus,
        EvidenceType,
    )

    db = ComplianceDB(str(tmp_path / "score_inflation.db"))
    engine = ComplianceEngine(db=db)

    # Inject a single SCAN_RESULT evidence item for a POLICY_CHECK-only control.
    # SOC2 CC1.1 requires POLICY_CHECK + TRAINING_RECORD (automated=False) but
    # we use a manually-chosen control known to require only POLICY_CHECK.
    # We target PCI 12.1 (REQ-12): evidence=[POLICY_CHECK], automated=False
    ctrl_id = "12.1"
    framework = Framework.PCI_DSS

    engine.db.add_evidence({
        "control_id": ctrl_id,
        "framework": framework.value,
        "evidence_type": EvidenceType.SCAN_RESULT.value,  # wrong type for this control
        "source": "sast_scanner",
        "description": "CWE-89 SQL injection finding",
        "data_hash": "abc123",
        "app_id": "test-app",
        "finding_id": "F001",
        "metadata": {"severity": "low", "status": "open"},
    })

    posture = engine.assess_framework(framework, app_id="test-app")
    d = posture.to_dict()

    # The compliance_percentage must not exceed a small honest value.
    # With one scan finding on a policy-only control that has automated=False,
    # the policy control must remain NOT_ASSESSED (not inflating the %).
    # The denominator excludes not_assessed + not_applicable so the
    # percentage can only be non-zero if there is a genuinely satisfied
    # automated+technical control — which there isn't here with one finding.
    pct = d["compliance_percentage"]
    assessable = d["total_controls"] - d["not_applicable"] - d["not_assessed"]
    if assessable == 0:
        assert pct == 0.0 or pct <= 0.1, (
            f"compliance_percentage={pct} with 0 assessable controls — "
            "denominator should yield 0 (SPEC-006 Finding 2)"
        )
    else:
        # Even if there are other assessable controls they have no evidence
        # so at most NOT_SATISFIED (score 0). Percentage must be 0.
        assert pct == 0.0, (
            f"compliance_percentage={pct} with only a mis-typed scan finding — "
            "scan evidence must not satisfy POLICY_CHECK controls (SPEC-006 Finding 2)"
        )


def test_fresh_org_policy_control_stays_not_assessed(tmp_path):
    """
    A fresh org with exactly one SAST scan finding must not show > 0%
    on policy/training/physical controls in the compliance_percentage.
    """
    import os as _os
    _er = _os.path.join(_os.path.dirname(__file__), "..", "suite-evidence-risk")
    if _os.path.isdir(_er) and _er not in sys.path:
        sys.path.insert(0, _os.path.abspath(_er))

    from compliance.compliance_engine import (  # type: ignore
        ComplianceEngine,
        ComplianceDB,
        Framework,
        EvidenceType,
        ControlStatus,
    )

    db = ComplianceDB(str(tmp_path / "fresh_org.db"))
    engine = ComplianceEngine(db=db)

    # One low-severity scan finding mapped to ISO 27001 — which has many
    # Organizational/People/Physical controls requiring POLICY_CHECK or
    # TRAINING_RECORD, not SCAN_RESULT.
    engine.db.add_evidence({
        "control_id": "A.5.1",
        "framework": Framework.ISO_27001.value,
        "evidence_type": EvidenceType.SCAN_RESULT.value,
        "source": "sast",
        "description": "CWE-200 finding",
        "data_hash": "def456",
        "app_id": "fresh-org",
        "finding_id": "F002",
        "metadata": {"severity": "low", "status": "open"},
    })

    posture = engine.assess_framework(Framework.ISO_27001, app_id="fresh-org")
    d = posture.to_dict()

    assessable = d["total_controls"] - d["not_applicable"] - d["not_assessed"]
    pct = d["compliance_percentage"]

    # A.5.1 is automated=False (POLICY_CHECK) so must stay NOT_ASSESSED
    # meaning it does not go into assessable denominator
    # All other controls also have no evidence → NOT_SATISFIED or NOT_ASSESSED
    # → compliance_percentage must be 0
    assert pct == 0.0, (
        f"Fresh org with 1 SAST scan shows {pct}% compliance on ISO 27001 — "
        "scan-CWE mapping is inflating policy/training/physical controls (SPEC-006 Finding 2)"
    )


# --- Finding 3: CSPM encryption_enabled default True ---

def test_cspm_resource_default_encryption_is_false():
    """
    A CloudResource constructed with no explicit encryption_enabled must
    default to False (unknown), not True.  Absence of data is not a passing
    encryption signal.
    """
    from core.cspm import CloudResource, CloudProvider, ResourceCategory  # type: ignore

    resource = CloudResource(
        provider=CloudProvider.AWS,
        category=ResourceCategory.STORAGE,
        resource_type="s3_bucket",
        resource_id="test-bucket-001",
        name="test-bucket",
        region="us-east-1",
        account_id="123456789012",
        org_id="test-org",
    )
    assert resource.encryption_enabled is False, (
        f"CloudResource.encryption_enabled defaults to {resource.encryption_enabled!r} — "
        "must be False so absent data does not silently pass encryption checks (SPEC-006 Finding 3)"
    )


def test_cspm_s3_encryption_check_fails_without_explicit_flag():
    """
    check_aws_s3_encryption on a resource with no encryption data must
    return NON_COMPLIANT, not COMPLIANT.
    """
    from core.cspm import (  # type: ignore
        CloudResource, CloudProvider, ResourceCategory,
        SecurityCheck, CheckSeverity, ComplianceStatus, CSPMEngine,
    )

    resource = CloudResource(
        provider=CloudProvider.AWS,
        category=ResourceCategory.STORAGE,
        resource_type="s3_bucket",
        resource_id="unscanned-bucket",
        name="unscanned-bucket",
        region="us-east-1",
        account_id="000000000000",
        org_id="test-org",
        # encryption_enabled intentionally omitted — defaults to False now
    )
    check = SecurityCheck(
        name="S3 Encryption",
        description="Check S3 default encryption",
        provider=CloudProvider.AWS,
        category=ResourceCategory.STORAGE,
        severity=CheckSeverity.HIGH,
        check_function="check_aws_s3_encryption",
    )
    engine = CSPMEngine(db_path=":memory:")
    result = engine.check_aws_s3_encryption(resource, check)
    assert result.status == ComplianceStatus.NON_COMPLIANT, (
        f"S3 bucket with unknown encryption status returned {result.status!r} — "
        "must be NON_COMPLIANT when encryption_enabled=False (SPEC-006 Finding 3)"
    )
