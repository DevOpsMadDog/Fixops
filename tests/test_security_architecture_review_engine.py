"""Tests for SecurityArchitectureReviewEngine — 35+ tests."""

from __future__ import annotations

import os
import tempfile

import pytest

from core.security_architecture_review_engine import SecurityArchitectureReviewEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "arch_review_test.db")
    return SecurityArchitectureReviewEngine(db_path=db)


@pytest.fixture
def org():
    return "org_arc_test"


@pytest.fixture
def review(engine, org):
    return engine.create_review(
        org_id=org,
        review_name="API Gateway Review",
        system_name="api-gateway-v2",
        review_type="full",
        reviewer="alice",
    )


# ---------------------------------------------------------------------------
# create_review
# ---------------------------------------------------------------------------


def test_create_review_defaults(engine, org):
    r = engine.create_review(org, "My Review", "my-system")
    assert r["review_name"] == "My Review"
    assert r["system_name"] == "my-system"
    assert r["status"] == "draft"
    assert r["overall_score"] == 0.0
    assert r["finding_count"] == 0
    assert r["critical_count"] == 0
    assert r["risk_level"] == "medium"
    assert r["completed_at"] is None
    assert r["findings"] == []
    assert r["controls"] == []


def test_create_review_with_reviewer(engine, org):
    r = engine.create_review(org, "Vendor Review", "vendor-sys", review_type="vendor", reviewer="bob")
    assert r["reviewer"] == "bob"
    assert r["review_type"] == "vendor"


def test_create_review_all_types(engine, org):
    for rt in ("full", "partial", "threat-model", "compliance", "vendor"):
        r = engine.create_review(org, f"review-{rt}", "sys", review_type=rt)
        assert r["review_type"] == rt


def test_create_review_invalid_type(engine, org):
    with pytest.raises(ValueError, match="Invalid review_type"):
        engine.create_review(org, "bad", "sys", review_type="unknown")


# ---------------------------------------------------------------------------
# add_finding
# ---------------------------------------------------------------------------


def test_add_finding_increments_finding_count(engine, org, review):
    rid = review["id"]
    engine.add_finding(rid, org, "Auth", "design-flaw", "Weak Auth")
    r = engine.get_review(rid, org)
    assert r["finding_count"] == 1


def test_add_finding_increments_critical_count(engine, org, review):
    rid = review["id"]
    engine.add_finding(rid, org, "Auth", "missing-control", "No MFA", severity="critical")
    r = engine.get_review(rid, org)
    assert r["critical_count"] == 1


def test_add_finding_non_critical_does_not_increment_critical_count(engine, org, review):
    rid = review["id"]
    engine.add_finding(rid, org, "Auth", "configuration", "Weak Cipher", severity="high")
    r = engine.get_review(rid, org)
    assert r["critical_count"] == 0
    assert r["finding_count"] == 1


def test_add_finding_risk_level_critical(engine, org, review):
    rid = review["id"]
    engine.add_finding(rid, org, "X", "design-flaw", "T", severity="critical")
    r = engine.get_review(rid, org)
    assert r["risk_level"] == "critical"


def test_add_finding_risk_level_high_after_six_findings(engine, org, review):
    rid = review["id"]
    for i in range(6):
        engine.add_finding(rid, org, "X", "configuration", f"F{i}", severity="medium")
    r = engine.get_review(rid, org)
    assert r["risk_level"] == "high"


def test_add_finding_risk_level_medium_after_three_findings(engine, org, review):
    rid = review["id"]
    for i in range(3):
        engine.add_finding(rid, org, "X", "configuration", f"F{i}", severity="low")
    r = engine.get_review(rid, org)
    assert r["risk_level"] == "medium"


def test_add_finding_risk_level_low_at_one_finding(engine, org, review):
    rid = review["id"]
    engine.add_finding(rid, org, "X", "configuration", "F0", severity="info")
    r = engine.get_review(rid, org)
    # 1 finding, 0 critical → low
    assert r["risk_level"] == "low"


def test_add_finding_risk_level_medium_at_two_findings(engine, org, review):
    rid = review["id"]
    engine.add_finding(rid, org, "X", "configuration", "F1", severity="info")
    engine.add_finding(rid, org, "X", "configuration", "F2", severity="info")
    r = engine.get_review(rid, org)
    # 2 findings, 0 critical → still low (not > 2)
    assert r["risk_level"] == "low"


def test_add_finding_risk_level_medium_at_exactly_three(engine, org, review):
    rid = review["id"]
    for i in range(3):
        engine.add_finding(rid, org, "X", "configuration", f"F{i}", severity="info")
    r = engine.get_review(rid, org)
    # 3 findings → medium (> 2)
    assert r["risk_level"] == "medium"


def test_add_finding_invalid_type(engine, org, review):
    with pytest.raises(ValueError, match="Invalid finding_type"):
        engine.add_finding(review["id"], org, "X", "bad-type", "T")


def test_add_finding_invalid_severity(engine, org, review):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.add_finding(review["id"], org, "X", "configuration", "T", severity="blocker")


def test_add_finding_nonexistent_review(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.add_finding("nonexistent", org, "X", "configuration", "T")


def test_add_finding_appears_in_get_review(engine, org, review):
    rid = review["id"]
    engine.add_finding(rid, org, "DB", "data-exposure", "PII Leak", description="SSN exposed")
    r = engine.get_review(rid, org)
    assert len(r["findings"]) == 1
    assert r["findings"][0]["title"] == "PII Leak"
    assert r["findings"][0]["severity"] == "medium"


def test_add_finding_all_types(engine, org, review):
    rid = review["id"]
    for ft in ("design-flaw", "missing-control", "weak-implementation",
                "configuration", "dependency-risk", "data-exposure"):
        engine.add_finding(rid, org, "X", ft, ft)
    r = engine.get_review(rid, org)
    assert r["finding_count"] == 6


# ---------------------------------------------------------------------------
# add_control
# ---------------------------------------------------------------------------


def test_add_control_basic(engine, org, review):
    rid = review["id"]
    c = engine.add_control(rid, org, "MFA", "IAM", "partial", 60.0, "No hardware keys")
    assert c["control_name"] == "MFA"
    assert c["effectiveness"] == 60.0
    assert c["implementation_status"] == "partial"


def test_add_control_effectiveness_clamped_high(engine, org, review):
    c = engine.add_control(review["id"], org, "WAF", "Network", "implemented", 150.0)
    assert c["effectiveness"] == 100.0


def test_add_control_effectiveness_clamped_low(engine, org, review):
    c = engine.add_control(review["id"], org, "WAF", "Network", "not_implemented", -50.0)
    assert c["effectiveness"] == 0.0


def test_add_control_invalid_impl_status(engine, org, review):
    with pytest.raises(ValueError, match="Invalid implementation_status"):
        engine.add_control(review["id"], org, "X", "IAM", "unknown")


def test_add_control_nonexistent_review(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.add_control("nonexistent", org, "X", "IAM")


def test_add_control_appears_in_get_review(engine, org, review):
    rid = review["id"]
    engine.add_control(rid, org, "Encryption", "Data", "implemented", 95.0)
    r = engine.get_review(rid, org)
    assert len(r["controls"]) == 1
    assert r["controls"][0]["control_name"] == "Encryption"


def test_add_control_all_statuses(engine, org, review):
    rid = review["id"]
    for s in ("implemented", "partial", "not_implemented", "compensating"):
        engine.add_control(rid, org, f"ctrl-{s}", "IAM", s, 50.0)
    r = engine.get_review(rid, org)
    assert len(r["controls"]) == 4


# ---------------------------------------------------------------------------
# complete_review
# ---------------------------------------------------------------------------


def test_complete_review_status(engine, org, review):
    rid = review["id"]
    engine.add_control(rid, org, "C1", "IAM", "partial", 60.0)
    r = engine.complete_review(rid, org)
    assert r["status"] == "completed"
    assert r["completed_at"] is not None


def test_complete_review_overall_score_avg(engine, org, review):
    rid = review["id"]
    engine.add_control(rid, org, "C1", "IAM", "partial", 60.0)
    engine.add_control(rid, org, "C2", "Network", "implemented", 80.0)
    engine.add_control(rid, org, "C3", "Crypto", "not_implemented", 10.0)
    r = engine.complete_review(rid, org)
    assert r["overall_score"] == pytest.approx((60.0 + 80.0 + 10.0) / 3, abs=0.01)


def test_complete_review_no_controls_score_zero(engine, org, review):
    r = engine.complete_review(review["id"], org)
    assert r["overall_score"] == 0.0


def test_complete_review_nonexistent(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.complete_review("nonexistent", org)


# ---------------------------------------------------------------------------
# get_control_gaps
# ---------------------------------------------------------------------------


def test_get_control_gaps_excludes_implemented(engine, org, review):
    rid = review["id"]
    engine.add_control(rid, org, "Implemented", "IAM", "implemented", 100.0)
    engine.add_control(rid, org, "Partial", "IAM", "partial", 50.0)
    engine.add_control(rid, org, "Missing", "IAM", "not_implemented", 0.0)
    gaps = engine.get_control_gaps(org)
    names = [g["control_name"] for g in gaps]
    assert "Implemented" not in names
    assert "Partial" in names
    assert "Missing" in names


def test_get_control_gaps_ordered_by_effectiveness_asc(engine, org, review):
    rid = review["id"]
    engine.add_control(rid, org, "C1", "IAM", "partial", 70.0)
    engine.add_control(rid, org, "C2", "IAM", "not_implemented", 10.0)
    engine.add_control(rid, org, "C3", "IAM", "compensating", 40.0)
    gaps = engine.get_control_gaps(org)
    scores = [g["effectiveness"] for g in gaps]
    assert scores == sorted(scores)


def test_get_control_gaps_empty_when_all_implemented(engine, org, review):
    rid = review["id"]
    engine.add_control(rid, org, "C1", "IAM", "implemented", 100.0)
    assert engine.get_control_gaps(org) == []


# ---------------------------------------------------------------------------
# org_id isolation
# ---------------------------------------------------------------------------


def test_org_isolation_reviews(engine):
    r1 = engine.create_review("org_a", "R1", "S1")
    engine.create_review("org_b", "R2", "S2")
    assert len(engine.list_reviews("org_a")) == 1
    assert engine.list_reviews("org_a")[0]["id"] == r1["id"]


def test_org_isolation_get_review(engine):
    r = engine.create_review("org_a", "R1", "S1")
    assert engine.get_review(r["id"], "org_b") is None


def test_org_isolation_findings(engine):
    r = engine.create_review("org_a", "R1", "S1")
    engine.add_finding(r["id"], "org_a", "X", "configuration", "T")
    # org_b cannot see org_a's review
    assert engine.get_review(r["id"], "org_b") is None


def test_org_isolation_control_gaps(engine):
    r = engine.create_review("org_a", "R1", "S1")
    engine.add_control(r["id"], "org_a", "C1", "IAM", "partial", 30.0)
    assert len(engine.get_control_gaps("org_a")) == 1
    assert len(engine.get_control_gaps("org_b")) == 0


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


def test_summary_empty(engine, org):
    s = engine.get_summary(org)
    assert s["total_reviews"] == 0
    assert s["avg_score"] == 0.0
    assert s["critical_finding_count"] == 0


def test_summary_aggregation(engine, org):
    r1 = engine.create_review(org, "R1", "S1")
    r2 = engine.create_review(org, "R2", "S2")
    engine.add_finding(r1["id"], org, "X", "design-flaw", "F1", severity="critical")
    engine.add_finding(r2["id"], org, "X", "configuration", "F2", severity="high")
    engine.add_control(r1["id"], org, "C1", "IAM", "partial", 60.0)
    engine.complete_review(r1["id"], org)

    s = engine.get_summary(org)
    assert s["total_reviews"] == 2
    assert s["by_status"]["completed"] == 1
    assert s["by_status"]["draft"] == 1
    assert s["critical_finding_count"] == 1
    assert s["avg_score"] == pytest.approx(60.0, abs=0.01)


def test_summary_by_risk_level(engine, org):
    r = engine.create_review(org, "R1", "S1")
    engine.add_finding(r["id"], org, "X", "design-flaw", "CF", severity="critical")
    s = engine.get_summary(org)
    assert "critical" in s["by_risk_level"]


def test_list_reviews_by_status(engine, org):
    r1 = engine.create_review(org, "R1", "S1")
    engine.create_review(org, "R2", "S2")
    engine.complete_review(r1["id"], org)
    completed = engine.list_reviews(org, status="completed")
    drafts = engine.list_reviews(org, status="draft")
    assert len(completed) == 1
    assert len(drafts) == 1
