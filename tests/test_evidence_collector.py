"""
Tests for EvidenceCollector — compliance evidence management.

Covers:
- Evidence CRUD (add, get, list)
- Verify/reject workflow
- Control mappings for all 7 frameworks
- Coverage calculation
- Stale evidence detection + expiration
- Evidence package generation
- Gap analysis
- Stats
"""
from __future__ import annotations

import json
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.evidence_collector import (
    ControlMapping,
    Evidence,
    EvidenceCollector,
    EvidencePackage,
    EvidenceStatus,
    EvidenceType,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path):
    """Temporary SQLite database path."""
    return str(tmp_path / "evidence_test.db")


@pytest.fixture
def collector(tmp_db):
    """EvidenceCollector backed by a temp DB."""
    return EvidenceCollector(db_path=tmp_db)


ORG = "org_test_001"
ORG2 = "org_test_002"


def _make_evidence(
    *,
    control_id: str = "CC6.1",
    framework: str = "SOC2",
    ev_type: EvidenceType = EvidenceType.CONFIG,
    title: str = "Test Evidence",
    collected_by: str = "alice",
    org_id: str = ORG,
    status: EvidenceStatus = EvidenceStatus.COLLECTED,
    expires_at: datetime | None = None,
    collected_at: datetime | None = None,
    metadata: dict | None = None,
) -> Evidence:
    e = Evidence(
        control_id=control_id,
        framework=framework,
        type=ev_type,
        title=title,
        description=f"Description for {title}",
        collected_by=collected_by,
        org_id=org_id,
        status=status,
        expires_at=expires_at,
        metadata=metadata or {},
    )
    if collected_at is not None:
        e = e.model_copy(update={"collected_at": collected_at})
    return e


# ============================================================================
# CRUD Tests
# ============================================================================


class TestAddEvidence:
    def test_add_returns_evidence_with_id(self, collector):
        ev = _make_evidence()
        result = collector.add_evidence(ev)
        assert result.id == ev.id
        assert result.title == "Test Evidence"

    def test_add_persists_to_db(self, collector):
        ev = _make_evidence()
        collector.add_evidence(ev)
        fetched = collector.get_evidence(ev.id)
        assert fetched is not None
        assert fetched.id == ev.id

    def test_add_preserves_all_fields(self, collector):
        ev = _make_evidence(
            control_id="CC7.1",
            framework="SOC2",
            ev_type=EvidenceType.LOG,
            title="Detailed Evidence",
            collected_by="bob",
            metadata={"source": "cloudwatch", "region": "us-east-1"},
        )
        ev = ev.model_copy(update={"file_hash": "abc123", "file_size": 4096})
        collector.add_evidence(ev)
        fetched = collector.get_evidence(ev.id)
        assert fetched.control_id == "CC7.1"
        assert fetched.framework == "SOC2"
        assert fetched.type == EvidenceType.LOG
        assert fetched.collected_by == "bob"
        assert fetched.file_hash == "abc123"
        assert fetched.file_size == 4096
        assert fetched.metadata["source"] == "cloudwatch"

    def test_add_multiple_evidence_records(self, collector):
        for i in range(5):
            collector.add_evidence(_make_evidence(title=f"Evidence {i}"))
        results = collector.list_evidence(org_id=ORG)
        assert len(results) == 5


class TestGetEvidence:
    def test_get_existing(self, collector):
        ev = _make_evidence()
        collector.add_evidence(ev)
        result = collector.get_evidence(ev.id)
        assert result is not None
        assert result.id == ev.id

    def test_get_nonexistent_returns_none(self, collector):
        result = collector.get_evidence("nonexistent-id")
        assert result is None

    def test_get_returns_correct_status(self, collector):
        ev = _make_evidence(status=EvidenceStatus.PENDING)
        collector.add_evidence(ev)
        result = collector.get_evidence(ev.id)
        assert result.status == EvidenceStatus.PENDING


class TestListEvidence:
    def test_list_by_org(self, collector):
        collector.add_evidence(_make_evidence(org_id=ORG))
        collector.add_evidence(_make_evidence(org_id=ORG))
        collector.add_evidence(_make_evidence(org_id=ORG2))
        results = collector.list_evidence(org_id=ORG)
        assert len(results) == 2
        assert all(e.org_id == ORG for e in results)

    def test_list_filter_by_framework(self, collector):
        collector.add_evidence(_make_evidence(framework="SOC2"))
        collector.add_evidence(_make_evidence(framework="PCI-DSS"))
        soc2 = collector.list_evidence(org_id=ORG, framework="SOC2")
        assert len(soc2) == 1
        assert soc2[0].framework == "SOC2"

    def test_list_filter_by_control_id(self, collector):
        collector.add_evidence(_make_evidence(control_id="CC6.1"))
        collector.add_evidence(_make_evidence(control_id="CC7.1"))
        results = collector.list_evidence(org_id=ORG, control_id="CC6.1")
        assert len(results) == 1
        assert results[0].control_id == "CC6.1"

    def test_list_filter_by_status(self, collector):
        collector.add_evidence(_make_evidence(status=EvidenceStatus.COLLECTED))
        collector.add_evidence(_make_evidence(status=EvidenceStatus.VERIFIED))
        verified = collector.list_evidence(org_id=ORG, status=EvidenceStatus.VERIFIED)
        assert len(verified) == 1
        assert verified[0].status == EvidenceStatus.VERIFIED

    def test_list_combined_filters(self, collector):
        collector.add_evidence(_make_evidence(framework="SOC2", control_id="CC6.1", status=EvidenceStatus.VERIFIED))
        collector.add_evidence(_make_evidence(framework="SOC2", control_id="CC7.1", status=EvidenceStatus.VERIFIED))
        collector.add_evidence(_make_evidence(framework="PCI-DSS", control_id="1.1", status=EvidenceStatus.VERIFIED))
        results = collector.list_evidence(org_id=ORG, framework="SOC2", status=EvidenceStatus.VERIFIED)
        assert len(results) == 2

    def test_list_returns_empty_for_unknown_org(self, collector):
        collector.add_evidence(_make_evidence(org_id=ORG))
        results = collector.list_evidence(org_id="org_unknown")
        assert results == []

    def test_list_ordered_by_collected_at_desc(self, collector):
        now = datetime.now(timezone.utc)
        old = _make_evidence(title="Old", collected_at=now - timedelta(days=10))
        new = _make_evidence(title="New", collected_at=now)
        collector.add_evidence(old)
        collector.add_evidence(new)
        results = collector.list_evidence(org_id=ORG)
        assert results[0].title == "New"
        assert results[1].title == "Old"


# ============================================================================
# Verify / Reject Workflow Tests
# ============================================================================


class TestVerifyEvidence:
    def test_verify_sets_status(self, collector):
        ev = _make_evidence()
        collector.add_evidence(ev)
        result = collector.verify_evidence(ev.id, verifier="auditor@example.com")
        assert result is True
        fetched = collector.get_evidence(ev.id)
        assert fetched.status == EvidenceStatus.VERIFIED

    def test_verify_records_verifier_in_metadata(self, collector):
        ev = _make_evidence()
        collector.add_evidence(ev)
        collector.verify_evidence(ev.id, verifier="auditor@example.com")
        fetched = collector.get_evidence(ev.id)
        assert fetched.metadata.get("verified_by") == "auditor@example.com"
        assert "verified_at" in fetched.metadata

    def test_verify_nonexistent_returns_false(self, collector):
        result = collector.verify_evidence("no-such-id", verifier="auditor")
        assert result is False

    def test_verified_evidence_visible_in_list(self, collector):
        ev = _make_evidence()
        collector.add_evidence(ev)
        collector.verify_evidence(ev.id, verifier="auditor")
        verified = collector.list_evidence(org_id=ORG, status=EvidenceStatus.VERIFIED)
        assert len(verified) == 1


class TestRejectEvidence:
    def test_reject_sets_status(self, collector):
        ev = _make_evidence()
        collector.add_evidence(ev)
        result = collector.reject_evidence(ev.id, reason="Missing signature")
        assert result is True
        fetched = collector.get_evidence(ev.id)
        assert fetched.status == EvidenceStatus.REJECTED

    def test_reject_records_reason_in_metadata(self, collector):
        ev = _make_evidence()
        collector.add_evidence(ev)
        collector.reject_evidence(ev.id, reason="Outdated screenshot")
        fetched = collector.get_evidence(ev.id)
        assert fetched.metadata.get("rejection_reason") == "Outdated screenshot"
        assert "rejected_at" in fetched.metadata

    def test_reject_nonexistent_returns_false(self, collector):
        result = collector.reject_evidence("no-such-id", reason="n/a")
        assert result is False

    def test_rejected_evidence_excluded_from_coverage(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        collector.reject_evidence(ev.id, reason="Invalid")
        coverage = collector.get_evidence_coverage(org_id=ORG, framework="SOC2")
        assert "CC6.1" not in coverage["covered"]


# ============================================================================
# Control Mappings Tests
# ============================================================================


class TestControlMappings:
    @pytest.mark.parametrize("framework,expected_min", [
        ("SOC2", 6),
        ("PCI-DSS", 7),
        ("HIPAA", 6),
        ("ISO27001", 6),
        ("NIST-CSF", 6),
        ("CIS", 6),
        ("GDPR", 6),
    ])
    def test_mappings_exist_for_all_frameworks(self, collector, framework, expected_min):
        mappings = collector.get_control_mappings(framework)
        assert len(mappings) >= expected_min

    def test_mappings_return_control_mapping_objects(self, collector):
        mappings = collector.get_control_mappings("SOC2")
        assert all(isinstance(m, ControlMapping) for m in mappings)

    def test_mappings_have_required_evidence_types(self, collector):
        mappings = collector.get_control_mappings("SOC2")
        for m in mappings:
            assert len(m.required_evidence_types) > 0
            assert all(isinstance(t, EvidenceType) for t in m.required_evidence_types)

    def test_unknown_framework_returns_empty_list(self, collector):
        mappings = collector.get_control_mappings("UNKNOWN_FRAMEWORK")
        assert mappings == []

    def test_pci_dss_mappings_structure(self, collector):
        mappings = collector.get_control_mappings("PCI-DSS")
        control_ids = [m.control_id for m in mappings]
        assert "1.1" in control_ids
        assert "10.2" in control_ids

    def test_gdpr_mappings_structure(self, collector):
        mappings = collector.get_control_mappings("GDPR")
        control_ids = [m.control_id for m in mappings]
        assert "Art.32" in control_ids
        assert "Art.35" in control_ids


# ============================================================================
# Coverage Calculation Tests
# ============================================================================


class TestEvidenceCoverage:
    def test_zero_coverage_when_no_evidence(self, collector):
        coverage = collector.get_evidence_coverage(org_id=ORG, framework="SOC2")
        assert coverage["coverage_pct"] == 0.0
        assert coverage["controls_covered"] == 0

    def test_full_coverage_structure(self, collector):
        coverage = collector.get_evidence_coverage(org_id=ORG, framework="SOC2")
        assert "framework" in coverage
        assert "total_controls" in coverage
        assert "controls_covered" in coverage
        assert "controls_uncovered" in coverage
        assert "coverage_pct" in coverage
        assert "covered" in coverage
        assert "uncovered" in coverage

    def test_coverage_increases_with_evidence(self, collector):
        # Add evidence for one SOC2 control
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        coverage = collector.get_evidence_coverage(org_id=ORG, framework="SOC2")
        assert coverage["controls_covered"] == 1
        assert "CC6.1" in coverage["covered"]

    def test_rejected_evidence_does_not_count(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        collector.reject_evidence(ev.id, reason="Bad")
        coverage = collector.get_evidence_coverage(org_id=ORG, framework="SOC2")
        assert coverage["controls_covered"] == 0

    def test_expired_evidence_does_not_count(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2", status=EvidenceStatus.EXPIRED)
        collector.add_evidence(ev)
        coverage = collector.get_evidence_coverage(org_id=ORG, framework="SOC2")
        assert coverage["controls_covered"] == 0

    def test_coverage_pct_is_rounded(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        coverage = collector.get_evidence_coverage(org_id=ORG, framework="SOC2")
        assert isinstance(coverage["coverage_pct"], float)

    def test_coverage_isolated_by_org(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2", org_id=ORG2)
        collector.add_evidence(ev)
        coverage = collector.get_evidence_coverage(org_id=ORG, framework="SOC2")
        assert coverage["controls_covered"] == 0


# ============================================================================
# Stale Evidence Detection + Expiration Tests
# ============================================================================


class TestStaleEvidence:
    def test_stale_evidence_detected(self, collector):
        old_dt = datetime.now(timezone.utc) - timedelta(days=100)
        ev = _make_evidence(collected_at=old_dt)
        collector.add_evidence(ev)
        stale = collector.get_stale_evidence(org_id=ORG, days=90)
        assert len(stale) == 1
        assert stale[0].id == ev.id

    def test_recent_evidence_not_stale(self, collector):
        ev = _make_evidence()  # collected_at defaults to now
        collector.add_evidence(ev)
        stale = collector.get_stale_evidence(org_id=ORG, days=90)
        assert len(stale) == 0

    def test_stale_only_returns_active_evidence(self, collector):
        old_dt = datetime.now(timezone.utc) - timedelta(days=100)
        ev_rejected = _make_evidence(collected_at=old_dt, status=EvidenceStatus.REJECTED)
        ev_active = _make_evidence(collected_at=old_dt)
        collector.add_evidence(ev_rejected)
        collector.add_evidence(ev_active)
        stale = collector.get_stale_evidence(org_id=ORG, days=90)
        ids = [e.id for e in stale]
        assert ev_active.id in ids
        assert ev_rejected.id not in ids

    def test_expire_old_evidence_returns_count(self, collector):
        old_dt = datetime.now(timezone.utc) - timedelta(days=400)
        ev = _make_evidence(collected_at=old_dt)
        collector.add_evidence(ev)
        count = collector.expire_old_evidence(org_id=ORG, days=365)
        assert count == 1

    def test_expire_marks_evidence_as_expired(self, collector):
        old_dt = datetime.now(timezone.utc) - timedelta(days=400)
        ev = _make_evidence(collected_at=old_dt)
        collector.add_evidence(ev)
        collector.expire_old_evidence(org_id=ORG, days=365)
        fetched = collector.get_evidence(ev.id)
        assert fetched.status == EvidenceStatus.EXPIRED

    def test_expire_does_not_affect_recent_evidence(self, collector):
        ev = _make_evidence()  # now
        collector.add_evidence(ev)
        count = collector.expire_old_evidence(org_id=ORG, days=365)
        assert count == 0
        fetched = collector.get_evidence(ev.id)
        assert fetched.status == EvidenceStatus.COLLECTED

    def test_expire_isolated_by_org(self, collector):
        old_dt = datetime.now(timezone.utc) - timedelta(days=400)
        ev = _make_evidence(collected_at=old_dt, org_id=ORG2)
        collector.add_evidence(ev)
        count = collector.expire_old_evidence(org_id=ORG, days=365)
        assert count == 0


# ============================================================================
# Evidence Package Tests
# ============================================================================


class TestEvidencePackage:
    def test_package_structure(self, collector):
        pkg = collector.generate_evidence_package(org_id=ORG, framework="SOC2")
        assert isinstance(pkg, EvidencePackage)
        assert pkg.framework == "SOC2"
        assert pkg.org_id == ORG
        assert pkg.total_controls > 0
        assert isinstance(pkg.evidences, list)
        assert isinstance(pkg.gaps, list)
        assert isinstance(pkg.coverage_pct, float)

    def test_package_with_no_evidence_has_all_gaps(self, collector):
        pkg = collector.generate_evidence_package(org_id=ORG, framework="SOC2")
        assert pkg.controls_covered == 0
        assert len(pkg.gaps) == pkg.total_controls

    def test_package_counts_covered_controls(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        pkg = collector.generate_evidence_package(org_id=ORG, framework="SOC2")
        assert pkg.controls_covered == 1

    def test_package_gaps_exclude_covered_controls(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        pkg = collector.generate_evidence_package(org_id=ORG, framework="SOC2")
        gap_control_ids = [g.split(":")[0] for g in pkg.gaps]
        assert "CC6.1" not in gap_control_ids

    def test_package_coverage_pct_calculation(self, collector):
        mappings = collector.get_control_mappings("SOC2")
        total = len(mappings)
        # Cover exactly one control
        ev = _make_evidence(control_id=mappings[0].control_id, framework="SOC2")
        collector.add_evidence(ev)
        pkg = collector.generate_evidence_package(org_id=ORG, framework="SOC2")
        expected = round(1 / total * 100, 2)
        assert pkg.coverage_pct == expected

    def test_package_rejected_evidence_not_counted(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        collector.reject_evidence(ev.id, reason="Invalid")
        pkg = collector.generate_evidence_package(org_id=ORG, framework="SOC2")
        assert pkg.controls_covered == 0

    def test_package_includes_evidences_list(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        pkg = collector.generate_evidence_package(org_id=ORG, framework="SOC2")
        assert len(pkg.evidences) == 1
        assert pkg.evidences[0].id == ev.id

    def test_package_has_generated_at_timestamp(self, collector):
        pkg = collector.generate_evidence_package(org_id=ORG, framework="SOC2")
        assert isinstance(pkg.generated_at, datetime)


# ============================================================================
# Gap Analysis Tests
# ============================================================================


class TestGapAnalysis:
    def test_all_controls_are_gaps_when_no_evidence(self, collector):
        gaps = collector.get_evidence_gaps(org_id=ORG, framework="SOC2")
        mappings = collector.get_control_mappings("SOC2")
        assert len(gaps) == len(mappings)

    def test_gap_structure(self, collector):
        gaps = collector.get_evidence_gaps(org_id=ORG, framework="SOC2")
        for g in gaps:
            assert "control_id" in g
            assert "control_name" in g
            assert "framework" in g
            assert "description" in g
            assert "required_evidence_types" in g

    def test_covered_control_removed_from_gaps(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2", ev_type=EvidenceType.CONFIG)
        collector.add_evidence(ev)
        ev2 = _make_evidence(control_id="CC6.1", framework="SOC2", ev_type=EvidenceType.POLICY_DOC)
        collector.add_evidence(ev2)
        ev3 = _make_evidence(control_id="CC6.1", framework="SOC2", ev_type=EvidenceType.SCREENSHOT)
        collector.add_evidence(ev3)
        gaps = collector.get_evidence_gaps(org_id=ORG, framework="SOC2")
        gap_ids = [g["control_id"] for g in gaps]
        assert "CC6.1" not in gap_ids

    def test_partial_coverage_shows_missing_types(self, collector):
        # CC6.1 requires CONFIG, POLICY_DOC, SCREENSHOT — only add CONFIG
        ev = _make_evidence(control_id="CC6.1", framework="SOC2", ev_type=EvidenceType.CONFIG)
        collector.add_evidence(ev)
        gaps = collector.get_evidence_gaps(org_id=ORG, framework="SOC2")
        cc61_gaps = [g for g in gaps if g["control_id"] == "CC6.1"]
        assert len(cc61_gaps) == 1
        assert "missing_types" in cc61_gaps[0]
        assert "policy_doc" in cc61_gaps[0]["missing_types"]

    def test_rejected_evidence_still_creates_gap(self, collector):
        ev = _make_evidence(control_id="CC6.1", framework="SOC2")
        collector.add_evidence(ev)
        collector.reject_evidence(ev.id, reason="Invalid")
        gaps = collector.get_evidence_gaps(org_id=ORG, framework="SOC2")
        gap_ids = [g["control_id"] for g in gaps]
        assert "CC6.1" in gap_ids

    def test_unknown_framework_returns_empty_gaps(self, collector):
        gaps = collector.get_evidence_gaps(org_id=ORG, framework="UNKNOWN")
        assert gaps == []


# ============================================================================
# Stats Tests
# ============================================================================


class TestCollectionStats:
    def test_stats_structure(self, collector):
        stats = collector.get_collection_stats(org_id=ORG)
        assert "org_id" in stats
        assert "total" in stats
        assert "by_framework" in stats
        assert "by_status" in stats
        assert "coverage_rates" in stats

    def test_stats_zero_when_no_evidence(self, collector):
        stats = collector.get_collection_stats(org_id=ORG)
        assert stats["total"] == 0
        assert stats["by_framework"] == {}
        assert stats["by_status"] == {}

    def test_stats_total_count(self, collector):
        for i in range(3):
            collector.add_evidence(_make_evidence(title=f"ev{i}"))
        stats = collector.get_collection_stats(org_id=ORG)
        assert stats["total"] == 3

    def test_stats_by_framework(self, collector):
        collector.add_evidence(_make_evidence(framework="SOC2"))
        collector.add_evidence(_make_evidence(framework="SOC2"))
        collector.add_evidence(_make_evidence(framework="PCI-DSS"))
        stats = collector.get_collection_stats(org_id=ORG)
        assert stats["by_framework"]["SOC2"] == 2
        assert stats["by_framework"]["PCI-DSS"] == 1

    def test_stats_by_status(self, collector):
        ev = _make_evidence()
        collector.add_evidence(ev)
        collector.verify_evidence(ev.id, verifier="auditor")
        ev2 = _make_evidence()
        collector.add_evidence(ev2)
        stats = collector.get_collection_stats(org_id=ORG)
        assert stats["by_status"]["verified"] == 1
        assert stats["by_status"]["collected"] == 1

    def test_stats_coverage_rates_for_all_frameworks(self, collector):
        stats = collector.get_collection_stats(org_id=ORG)
        for fw in ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "CIS", "GDPR"]:
            assert fw in stats["coverage_rates"]
            assert isinstance(stats["coverage_rates"][fw], float)

    def test_stats_org_id_in_result(self, collector):
        stats = collector.get_collection_stats(org_id=ORG)
        assert stats["org_id"] == ORG

    def test_stats_isolated_by_org(self, collector):
        collector.add_evidence(_make_evidence(org_id=ORG))
        collector.add_evidence(_make_evidence(org_id=ORG2))
        stats = collector.get_collection_stats(org_id=ORG)
        assert stats["total"] == 1
