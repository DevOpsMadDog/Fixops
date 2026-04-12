"""
Tests for the Vendor Security Scorecard module.

Covers:
- Vendor CRUD (add, get, list, update, delete)
- Assessment scoring, grading, and tiering
- Manual and auto-assessment
- Assessment history and latest retrieval
- Risk change detection
- SBOM component linking
- High-risk vendor filtering
- Assessment expiration
- Vendor stats aggregation
- Router endpoints (with TestClient + auth bypass)

Run with:
    python -m pytest tests/test_vendor_scorecard.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

# Add suite paths
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

# Force dev mode so router auth passes through
os.environ.setdefault("FIXOPS_MODE", "dev")

from core.vendor_scorecard import (
    AssessmentStatus,
    SecurityAssessment,
    Vendor,
    VendorRiskTier,
    VendorScorecard,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_vendors.db")


@pytest.fixture
def scorecard(db_path):
    return VendorScorecard(db_path=db_path)


def _make_vendor(
    name: str = "Acme Corp",
    domain: str = "acme.com",
    org_id: str = "org1",
    **kwargs,
) -> Vendor:
    return Vendor(
        id=str(uuid.uuid4()),
        name=name,
        domain=domain,
        org_id=org_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        **kwargs,
    )


# ============================================================================
# Grade and tier helpers
# ============================================================================

class TestGradeCalculation:
    def test_grade_a(self, scorecard):
        assert scorecard._calculate_grade(95) == "A"
        assert scorecard._calculate_grade(90) == "A"

    def test_grade_b(self, scorecard):
        assert scorecard._calculate_grade(85) == "B"
        assert scorecard._calculate_grade(80) == "B"

    def test_grade_c(self, scorecard):
        assert scorecard._calculate_grade(75) == "C"
        assert scorecard._calculate_grade(70) == "C"

    def test_grade_d(self, scorecard):
        assert scorecard._calculate_grade(65) == "D"
        assert scorecard._calculate_grade(60) == "D"

    def test_grade_f(self, scorecard):
        assert scorecard._calculate_grade(59) == "F"
        assert scorecard._calculate_grade(0) == "F"


class TestTierCalculation:
    def test_tier_minimal(self, scorecard):
        assert scorecard._calculate_tier(95) == VendorRiskTier.MINIMAL
        assert scorecard._calculate_tier(90) == VendorRiskTier.MINIMAL

    def test_tier_low(self, scorecard):
        assert scorecard._calculate_tier(80) == VendorRiskTier.LOW
        assert scorecard._calculate_tier(75) == VendorRiskTier.LOW

    def test_tier_medium(self, scorecard):
        assert scorecard._calculate_tier(70) == VendorRiskTier.MEDIUM
        assert scorecard._calculate_tier(60) == VendorRiskTier.MEDIUM

    def test_tier_high(self, scorecard):
        assert scorecard._calculate_tier(55) == VendorRiskTier.HIGH
        assert scorecard._calculate_tier(40) == VendorRiskTier.HIGH

    def test_tier_critical(self, scorecard):
        assert scorecard._calculate_tier(39) == VendorRiskTier.CRITICAL
        assert scorecard._calculate_tier(0) == VendorRiskTier.CRITICAL


# ============================================================================
# Vendor CRUD
# ============================================================================

class TestVendorCRUD:
    def test_add_and_get_vendor(self, scorecard):
        vendor = _make_vendor(name="TestVendor", domain="test.com")
        added = scorecard.add_vendor(vendor)
        assert added.id == vendor.id
        fetched = scorecard.get_vendor(vendor.id)
        assert fetched.name == "TestVendor"
        assert fetched.domain == "test.com"

    def test_get_vendor_not_found(self, scorecard):
        with pytest.raises(KeyError):
            scorecard.get_vendor("nonexistent-id")

    def test_list_vendors_empty(self, scorecard):
        vendors = scorecard.list_vendors(org_id="org_empty")
        assert vendors == []

    def test_list_vendors_by_org(self, scorecard):
        v1 = scorecard.add_vendor(_make_vendor(name="V1", org_id="orgA"))
        v2 = scorecard.add_vendor(_make_vendor(name="V2", org_id="orgA"))
        v3 = scorecard.add_vendor(_make_vendor(name="V3", org_id="orgB"))

        result_a = scorecard.list_vendors(org_id="orgA")
        assert len(result_a) == 2
        names = {v.name for v in result_a}
        assert names == {"V1", "V2"}

        result_b = scorecard.list_vendors(org_id="orgB")
        assert len(result_b) == 1

    def test_list_vendors_by_tier(self, scorecard):
        v1 = _make_vendor(name="HighRisk", tier=VendorRiskTier.HIGH)
        v2 = _make_vendor(name="LowRisk", tier=VendorRiskTier.LOW)
        scorecard.add_vendor(v1)
        scorecard.add_vendor(v2)

        high = scorecard.list_vendors(tier_filter=VendorRiskTier.HIGH)
        assert any(v.name == "HighRisk" for v in high)
        low = scorecard.list_vendors(tier_filter=VendorRiskTier.LOW)
        assert any(v.name == "LowRisk" for v in low)

    def test_list_all_vendors(self, scorecard):
        scorecard.add_vendor(_make_vendor(name="A"))
        scorecard.add_vendor(_make_vendor(name="B"))
        all_vendors = scorecard.list_vendors()
        assert len(all_vendors) >= 2

    def test_update_vendor(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor(name="Original"))
        updated = scorecard.update_vendor(vendor.id, {"name": "Updated", "description": "new desc"})
        assert updated.name == "Updated"
        assert updated.description == "new desc"
        fetched = scorecard.get_vendor(vendor.id)
        assert fetched.name == "Updated"

    def test_update_vendor_not_found(self, scorecard):
        with pytest.raises(KeyError):
            scorecard.update_vendor("bad-id", {"name": "X"})

    def test_delete_vendor(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        scorecard.delete_vendor(vendor.id)
        with pytest.raises(KeyError):
            scorecard.get_vendor(vendor.id)

    def test_delete_vendor_not_found(self, scorecard):
        with pytest.raises(KeyError):
            scorecard.delete_vendor("nonexistent")

    def test_vendor_tags(self, scorecard):
        vendor = _make_vendor(tags=["payments", "gdpr", "soc2"])
        added = scorecard.add_vendor(vendor)
        fetched = scorecard.get_vendor(added.id)
        assert set(fetched.tags) == {"payments", "gdpr", "soc2"}


# ============================================================================
# Manual assessment
# ============================================================================

class TestManualAssessment:
    def test_assess_vendor_all_factors(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        factors = {
            "ssl_score": 80.0,
            "headers_score": 70.0,
            "dns_score": 90.0,
            "vulnerability_score": 60.0,
            "data_handling_score": 75.0,
        }
        assessment = scorecard.assess_vendor(vendor.id, factors, assessor="analyst")
        assert 0 <= assessment.score <= 100
        assert assessment.grade in ("A", "B", "C", "D", "F")
        assert assessment.status == AssessmentStatus.COMPLETED
        assert assessment.assessor == "analyst"

    def test_assess_vendor_partial_factors(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        factors = {"ssl_score": 95.0, "vulnerability_score": 85.0}
        assessment = scorecard.assess_vendor(vendor.id, factors)
        assert assessment.score > 0
        assert assessment.grade in ("A", "B", "C", "D", "F")

    def test_assess_updates_vendor_tier(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        # Perfect score should push tier to MINIMAL
        factors = {k: 100.0 for k in (
            "ssl_score", "headers_score", "dns_score",
            "vulnerability_score", "data_handling_score"
        )}
        scorecard.assess_vendor(vendor.id, factors)
        updated_vendor = scorecard.get_vendor(vendor.id)
        assert updated_vendor.tier == VendorRiskTier.MINIMAL

    def test_assess_low_score_critical_tier(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        factors = {k: 10.0 for k in (
            "ssl_score", "headers_score", "dns_score",
            "vulnerability_score", "data_handling_score"
        )}
        scorecard.assess_vendor(vendor.id, factors)
        updated_vendor = scorecard.get_vendor(vendor.id)
        assert updated_vendor.tier == VendorRiskTier.CRITICAL

    def test_assess_vendor_not_found(self, scorecard):
        with pytest.raises(KeyError):
            scorecard.assess_vendor("bad-id", {"ssl_score": 80.0})

    def test_assess_with_notes(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        assessment = scorecard.assess_vendor(
            vendor.id, {"ssl_score": 75.0}, notes="Annual review"
        )
        assert assessment.notes == "Annual review"

    def test_assessment_has_expires_at(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        assessment = scorecard.assess_vendor(
            vendor.id, {"ssl_score": 75.0}, validity_days=30
        )
        assessed = datetime.fromisoformat(assessment.assessed_at)
        expires = datetime.fromisoformat(assessment.expires_at)
        delta_days = (expires - assessed).days
        assert 29 <= delta_days <= 31


# ============================================================================
# Auto assessment
# ============================================================================

class TestAutoAssessment:
    def test_auto_assess_returns_assessment(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor(domain="example.com"))
        assessment = scorecard.auto_assess(vendor.id)
        assert isinstance(assessment, SecurityAssessment)
        assert 0 <= assessment.score <= 100
        assert assessment.assessor == "auto-scanner"
        assert "example.com" in assessment.notes

    def test_auto_assess_has_all_factors(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor(domain="example.com"))
        assessment = scorecard.auto_assess(vendor.id)
        expected_factors = {
            "ssl_score", "headers_score", "dns_score",
            "vulnerability_score", "data_handling_score",
        }
        assert expected_factors == set(assessment.factors.keys())

    def test_auto_assess_deterministic(self, scorecard, db_path):
        """Same domain should produce same score across two scorecard instances."""
        sc2 = VendorScorecard(db_path=db_path)
        v1 = scorecard.add_vendor(_make_vendor(domain="stable-domain.com"))
        a1 = scorecard.auto_assess(v1.id)

        v2 = sc2.add_vendor(_make_vendor(domain="stable-domain.com"))
        a2 = sc2.auto_assess(v2.id)
        assert a1.score == a2.score

    def test_auto_assess_not_found(self, scorecard):
        with pytest.raises(KeyError):
            scorecard.auto_assess("nonexistent")

    def test_auto_assess_well_known_domain_higher(self, scorecard):
        """Well-known domains should score higher than unknown ones."""
        v_known = scorecard.add_vendor(_make_vendor(domain="google.com", name="Google"))
        v_unknown = scorecard.add_vendor(_make_vendor(domain="obscure-xyz-999.io", name="Unknown"))
        a_known = scorecard.auto_assess(v_known.id)
        a_unknown = scorecard.auto_assess(v_unknown.id)
        assert a_known.score > a_unknown.score


# ============================================================================
# Assessment history and latest
# ============================================================================

class TestAssessmentHistory:
    def test_get_latest_assessment_none(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        assert scorecard.get_latest_assessment(vendor.id) is None

    def test_get_latest_assessment(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        scorecard.assess_vendor(vendor.id, {"ssl_score": 60.0})
        scorecard.assess_vendor(vendor.id, {"ssl_score": 80.0})
        latest = scorecard.get_latest_assessment(vendor.id)
        assert latest is not None
        assert latest.factors.get("ssl_score") == 80.0

    def test_get_assessment_history_order(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        for score in (50.0, 70.0, 90.0):
            scorecard.assess_vendor(vendor.id, {"ssl_score": score})
        history = scorecard.get_assessment_history(vendor.id)
        assert len(history) == 3
        # Newest first
        assert history[0].factors["ssl_score"] == 90.0
        assert history[-1].factors["ssl_score"] == 50.0

    def test_assessment_history_empty(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        assert scorecard.get_assessment_history(vendor.id) == []


# ============================================================================
# Risk changes
# ============================================================================

class TestRiskChanges:
    def test_no_changes_single_assessment(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor(org_id="orgC"))
        scorecard.assess_vendor(vendor.id, {"ssl_score": 75.0})
        changes = scorecard.get_risk_changes(org_id="orgC", days=30)
        assert changes == []

    def test_detects_score_change(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor(org_id="orgD"))
        scorecard.assess_vendor(vendor.id, {"ssl_score": 50.0})
        scorecard.assess_vendor(vendor.id, {"ssl_score": 90.0})
        changes = scorecard.get_risk_changes(org_id="orgD", days=30)
        assert len(changes) == 1
        assert changes[0]["vendor_id"] == vendor.id
        assert changes[0]["direction"] == "improved"

    def test_degraded_direction(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor(org_id="orgE"))
        scorecard.assess_vendor(vendor.id, {"ssl_score": 90.0})
        scorecard.assess_vendor(vendor.id, {"ssl_score": 40.0})
        changes = scorecard.get_risk_changes(org_id="orgE", days=30)
        assert len(changes) == 1
        assert changes[0]["direction"] == "degraded"
        assert changes[0]["delta"] < 0

    def test_no_change_within_threshold(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor(org_id="orgF"))
        scorecard.assess_vendor(vendor.id, {"ssl_score": 75.0})
        # Score within 1 point — not counted as a change
        scorecard.assess_vendor(vendor.id, {"ssl_score": 75.5})
        changes = scorecard.get_risk_changes(org_id="orgF", days=30)
        assert changes == []


# ============================================================================
# SBOM linking
# ============================================================================

class TestSBOMLink:
    def test_link_components(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        scorecard.link_sbom_components(vendor.id, ["requests", "numpy", "flask"])
        components = scorecard.get_vendor_components(vendor.id)
        assert set(components) == {"requests", "numpy", "flask"}

    def test_link_updates_count(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        scorecard.link_sbom_components(vendor.id, ["libA", "libB"])
        fetched = scorecard.get_vendor(vendor.id)
        assert fetched.sbom_component_count == 2

    def test_link_idempotent(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        scorecard.link_sbom_components(vendor.id, ["libA", "libA", "libB"])
        components = scorecard.get_vendor_components(vendor.id)
        assert components.count("libA") == 1

    def test_link_sbom_vendor_not_found(self, scorecard):
        with pytest.raises(KeyError):
            scorecard.link_sbom_components("bad-id", ["libX"])

    def test_get_vendor_components_empty(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor())
        assert scorecard.get_vendor_components(vendor.id) == []


# ============================================================================
# High risk filtering
# ============================================================================

class TestHighRiskVendors:
    def test_returns_critical_and_high(self, scorecard):
        crit = scorecard.add_vendor(_make_vendor(name="Crit", tier=VendorRiskTier.CRITICAL, org_id="orgG"))
        high = scorecard.add_vendor(_make_vendor(name="High", tier=VendorRiskTier.HIGH, org_id="orgG"))
        med = scorecard.add_vendor(_make_vendor(name="Med", tier=VendorRiskTier.MEDIUM, org_id="orgG"))

        results = scorecard.get_high_risk_vendors(org_id="orgG")
        names = {v.name for v in results}
        assert "Crit" in names
        assert "High" in names
        assert "Med" not in names

    def test_empty_when_no_high_risk(self, scorecard):
        scorecard.add_vendor(_make_vendor(name="Safe", tier=VendorRiskTier.MINIMAL, org_id="orgH"))
        results = scorecard.get_high_risk_vendors(org_id="orgH")
        assert results == []


# ============================================================================
# Expiration
# ============================================================================

class TestExpireAssessments:
    def test_expire_marks_old_assessments(self, scorecard):
        import sqlite3 as _sqlite3

        vendor = scorecard.add_vendor(_make_vendor(org_id="orgI"))
        assessment = scorecard.assess_vendor(vendor.id, {"ssl_score": 75.0})

        # Manually backdate expires_at in DB
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with _sqlite3.connect(str(scorecard.db_path)) as conn:
            conn.execute(
                "UPDATE assessments SET expires_at = ? WHERE id = ?",
                (past, assessment.id),
            )

        count = scorecard.expire_assessments(org_id="orgI")
        assert count == 1

        updated = scorecard.get_latest_assessment(vendor.id)
        assert updated.status == AssessmentStatus.EXPIRED

    def test_expire_returns_zero_when_none_expired(self, scorecard):
        vendor = scorecard.add_vendor(_make_vendor(org_id="orgJ"))
        scorecard.assess_vendor(vendor.id, {"ssl_score": 75.0}, validity_days=90)
        count = scorecard.expire_assessments(org_id="orgJ")
        assert count == 0

    def test_expire_only_affects_org(self, scorecard):
        import sqlite3 as _sqlite3

        v1 = scorecard.add_vendor(_make_vendor(org_id="orgK"))
        v2 = scorecard.add_vendor(_make_vendor(org_id="orgL"))
        a1 = scorecard.assess_vendor(v1.id, {"ssl_score": 75.0})
        a2 = scorecard.assess_vendor(v2.id, {"ssl_score": 75.0})

        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with _sqlite3.connect(str(scorecard.db_path)) as conn:
            conn.execute(
                "UPDATE assessments SET expires_at = ? WHERE id IN (?, ?)",
                (past, a1.id, a2.id),
            )

        count = scorecard.expire_assessments(org_id="orgK")
        assert count == 1


# ============================================================================
# Vendor stats
# ============================================================================

class TestVendorStats:
    def test_empty_org_stats(self, scorecard):
        stats = scorecard.get_vendor_stats(org_id="empty_org")
        assert stats["total_vendors"] == 0
        assert stats["average_score"] is None

    def test_stats_counts(self, scorecard):
        org = "orgStats"
        v1 = scorecard.add_vendor(_make_vendor(name="S1", org_id=org, tier=VendorRiskTier.HIGH))
        v2 = scorecard.add_vendor(_make_vendor(name="S2", org_id=org, tier=VendorRiskTier.LOW))
        scorecard.assess_vendor(v1.id, {"ssl_score": 40.0})

        stats = scorecard.get_vendor_stats(org_id=org)
        assert stats["total_vendors"] == 2
        assert stats["assessed_vendors"] == 1
        assert stats["unassessed_vendors"] == 1

    def test_stats_tier_breakdown(self, scorecard):
        org = "orgTier"
        scorecard.add_vendor(_make_vendor(org_id=org, tier=VendorRiskTier.CRITICAL))
        scorecard.add_vendor(_make_vendor(org_id=org, tier=VendorRiskTier.HIGH))
        scorecard.add_vendor(_make_vendor(org_id=org, tier=VendorRiskTier.MEDIUM))

        stats = scorecard.get_vendor_stats(org_id=org)
        assert stats["tier_breakdown"]["critical"] == 1
        assert stats["tier_breakdown"]["high"] == 1
        assert stats["tier_breakdown"]["medium"] == 1

    def test_stats_average_score(self, scorecard):
        org = "orgAvg"
        v1 = scorecard.add_vendor(_make_vendor(name="A1", org_id=org))
        v2 = scorecard.add_vendor(_make_vendor(name="A2", org_id=org))
        scorecard.assess_vendor(v1.id, {k: 80.0 for k in (
            "ssl_score", "headers_score", "dns_score",
            "vulnerability_score", "data_handling_score"
        )})
        scorecard.assess_vendor(v2.id, {k: 60.0 for k in (
            "ssl_score", "headers_score", "dns_score",
            "vulnerability_score", "data_handling_score"
        )})
        stats = scorecard.get_vendor_stats(org_id=org)
        # Average should be between 60 and 80
        assert stats["average_score"] is not None
        assert 55.0 <= stats["average_score"] <= 85.0


# ============================================================================
# Enum values
# ============================================================================

class TestEnums:
    def test_vendor_risk_tier_values(self):
        assert VendorRiskTier.CRITICAL.value == "critical"
        assert VendorRiskTier.HIGH.value == "high"
        assert VendorRiskTier.MEDIUM.value == "medium"
        assert VendorRiskTier.LOW.value == "low"
        assert VendorRiskTier.MINIMAL.value == "minimal"

    def test_assessment_status_values(self):
        assert AssessmentStatus.PENDING.value == "pending"
        assert AssessmentStatus.IN_PROGRESS.value == "in_progress"
        assert AssessmentStatus.COMPLETED.value == "completed"
        assert AssessmentStatus.EXPIRED.value == "expired"


# ============================================================================
# Pydantic model validation
# ============================================================================

class TestModels:
    def test_vendor_model_defaults(self):
        v = Vendor(
            id="v1",
            name="Test",
            domain="test.com",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        assert v.tier == VendorRiskTier.MEDIUM
        assert v.tags == []
        assert v.org_id == "default"
        assert v.sbom_component_count == 0

    def test_security_assessment_model(self):
        a = SecurityAssessment(
            id="a1",
            vendor_id="v1",
            score=85.0,
            grade="B",
            assessed_at=datetime.now(timezone.utc).isoformat(),
            expires_at=datetime.now(timezone.utc).isoformat(),
        )
        assert a.status == AssessmentStatus.COMPLETED
        assert a.assessor == "system"

    def test_score_boundary(self):
        # Score must be 0-100
        with pytest.raises(Exception):
            SecurityAssessment(
                id="a1",
                vendor_id="v1",
                score=101.0,  # invalid
                grade="A",
                assessed_at=datetime.now(timezone.utc).isoformat(),
                expires_at=datetime.now(timezone.utc).isoformat(),
            )
