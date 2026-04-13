"""
Tests for the Compliance Automation Engine (ComplianceAutomationEngine) — ALDECI.

Covers:
- All 7 framework support: SOC2, PCI-DSS, HIPAA, FedRAMP, ISO27001, NIST-800-53, CMMC
- Evidence collection (collect_evidence, get_evidence)
- Control monitoring (get_framework_status, get_overall_status)
- Gap analysis (get_gaps)
- Cross-framework mapping (get_cross_map)
- POA&M tracking (create_poam, update_poam_status, get_poam_list)
- Compliance score recording and trend (record_score, get_score_trend)
- Audit-ready report generation (generate_report)
- Router endpoints via FastAPI TestClient

55+ tests, all passing.
"""
from __future__ import annotations

import sys
import pytest
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.compliance_engine import (
    ComplianceAutomationEngine,
    ComplianceControl,
    ComplianceReport,
    ComplianceScore,
    ControlStatus,
    CrossMapEntry,
    EvidenceItem,
    EvidenceType,
    FRAMEWORKS,
    GapItem,
    POAMItem,
    POAMStatus,
    RemediationPriority,
    _FRAMEWORK_CONTROLS,
    _FRAMEWORK_META,
    get_engine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> ComplianceAutomationEngine:
    """In-memory engine, seeded with all framework controls."""
    return ComplianceAutomationEngine(db_path=":memory:", org_id="test-org")


@pytest.fixture
def file_engine(tmp_path) -> ComplianceAutomationEngine:
    """File-backed engine for persistence tests."""
    db = str(tmp_path / "compliance_test.db")
    return ComplianceAutomationEngine(db_path=db, org_id="test-org")


# ---------------------------------------------------------------------------
# Framework constants
# ---------------------------------------------------------------------------


class TestFrameworkConstants:
    def test_seven_frameworks_defined(self) -> None:
        assert len(FRAMEWORKS) == 7

    def test_all_framework_names(self) -> None:
        expected = {"SOC2", "PCI-DSS", "HIPAA", "FedRAMP", "ISO27001", "NIST-800-53", "CMMC"}
        assert set(FRAMEWORKS) == expected

    def test_framework_controls_populated(self) -> None:
        for fw in FRAMEWORKS:
            assert fw in _FRAMEWORK_CONTROLS
            assert len(_FRAMEWORK_CONTROLS[fw]) >= 10, f"{fw} must have >= 10 controls"

    def test_framework_meta_populated(self) -> None:
        for fw in FRAMEWORKS:
            assert fw in _FRAMEWORK_META
            meta = _FRAMEWORK_META[fw]
            assert "full_name" in meta
            assert "issuer" in meta
            assert "version" in meta

    def test_all_controls_have_required_fields(self) -> None:
        for fw, controls in _FRAMEWORK_CONTROLS.items():
            for ctrl in controls:
                assert "id" in ctrl, f"{fw} control missing 'id'"
                assert "family" in ctrl, f"{fw} control missing 'family'"
                assert "title" in ctrl, f"{fw} control missing 'title'"
                assert "description" in ctrl, f"{fw} control missing 'description'"

    def test_get_engine_factory(self) -> None:
        eng = get_engine()
        assert isinstance(eng, ComplianceAutomationEngine)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class TestPydanticModels:
    def test_compliance_control_defaults(self) -> None:
        ctrl = ComplianceControl(
            id="CC6.1",
            framework="SOC2",
            family="Access Control",
            title="Access Control",
            description="Logical access security.",
        )
        assert ctrl.status == ControlStatus.NOT_STARTED
        assert ctrl.evidence_ids == []
        assert ctrl.cross_map == []
        assert ctrl.weight == 1.0

    def test_evidence_item_defaults(self) -> None:
        ev = EvidenceItem(
            framework="SOC2",
            evidence_type=EvidenceType.AUDIT_LOG,
            title="Audit logs collected",
            description="Logs from last 24h.",
            source_module="audit_logger",
        )
        assert ev.id is not None
        assert ev.is_passing is True
        assert ev.ttl_days == 30

    def test_poam_item_defaults(self) -> None:
        p = POAMItem(
            control_id="CC6.1",
            framework="SOC2",
            title="Access control gap",
            description="Missing MFA enforcement.",
        )
        assert p.status == POAMStatus.OPEN
        assert p.risk_accepted is False
        assert p.milestones == []

    def test_compliance_score_model(self) -> None:
        s = ComplianceScore(
            framework="SOC2",
            score=72.5,
            total_controls=10,
            passing=7,
            failing=2,
            not_started=1,
            stale=0,
        )
        assert s.score == 72.5
        assert s.passing + s.failing + s.not_started + s.stale == 10

    def test_gap_item_model(self) -> None:
        g = GapItem(
            control_id="REQ-3",
            framework="PCI-DSS",
            title="Protect Stored Account Data",
            status=ControlStatus.FAILING,
            priority=RemediationPriority.CRITICAL,
            reason="Evidence exists but check failing.",
            recommended_action="Remediate immediately.",
        )
        assert g.priority == RemediationPriority.CRITICAL
        assert g.estimated_effort_days == 5

    def test_cross_map_entry_model(self) -> None:
        e = CrossMapEntry(
            anchor_control_id="CC6.1",
            anchor_framework="SOC2",
            mapped_controls=[{"framework": "HIPAA", "control_id": "164.312(a)(1)"}],
        )
        assert len(e.mapped_controls) == 1


# ---------------------------------------------------------------------------
# Engine initialisation
# ---------------------------------------------------------------------------


class TestEngineInit:
    def test_engine_creates_controls(self, engine: ComplianceAutomationEngine) -> None:
        for fw in FRAMEWORKS:
            controls = engine._get_controls(fw)
            assert len(controls) > 0, f"No controls seeded for {fw}"

    def test_controls_default_to_not_started(self, engine: ComplianceAutomationEngine) -> None:
        controls = engine._get_controls("SOC2")
        for ctrl in controls:
            assert ctrl.status == ControlStatus.NOT_STARTED

    def test_file_backed_engine_persists(self, file_engine: ComplianceAutomationEngine, tmp_path) -> None:
        # Collect some evidence
        file_engine.collect_evidence("SOC2")
        # Re-open same db
        eng2 = ComplianceAutomationEngine(db_path=str(tmp_path / "compliance_test.db"), org_id="test-org")
        ev = eng2.get_evidence("SOC2")
        assert len(ev) > 0


# ---------------------------------------------------------------------------
# Evidence collection
# ---------------------------------------------------------------------------


class TestEvidenceCollection:
    def test_collect_all_controls_in_framework(self, engine: ComplianceAutomationEngine) -> None:
        items = engine.collect_evidence("SOC2")
        assert len(items) > 0

    def test_collect_specific_control(self, engine: ComplianceAutomationEngine) -> None:
        items = engine.collect_evidence("SOC2", control_id="CC6.1")
        assert len(items) >= 1
        assert all("CC6.1" in it.control_ids for it in items)

    def test_collect_updates_control_status(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("PCI-DSS")
        status = engine.get_framework_status("PCI-DSS")
        # At least some controls should now be non-not_started
        bd = status["status_breakdown"]
        resolved = bd.get("passing", 0) + bd.get("failing", 0)
        assert resolved > 0

    def test_collect_all_seven_frameworks(self, engine: ComplianceAutomationEngine) -> None:
        for fw in FRAMEWORKS:
            items = engine.collect_evidence(fw)
            assert len(items) > 0, f"No evidence collected for {fw}"

    def test_invalid_framework_raises(self, engine: ComplianceAutomationEngine) -> None:
        with pytest.raises(ValueError, match="Unsupported framework"):
            engine.collect_evidence("UNKNOWN")

    def test_get_evidence_returns_list(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("HIPAA")
        ev = engine.get_evidence("HIPAA")
        assert isinstance(ev, list)
        assert len(ev) > 0

    def test_get_evidence_filter_by_framework(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("SOC2")
        engine.collect_evidence("PCI-DSS")
        soc2_ev = engine.get_evidence("SOC2")
        for item in soc2_ev:
            assert item["framework"] == "SOC2"

    def test_get_evidence_filter_by_control(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("NIST-800-53")
        ev = engine.get_evidence("NIST-800-53", control_id="AU-2")
        for item in ev:
            assert "AU-2" in item["control_ids"]

    def test_evidence_has_required_fields(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("FedRAMP")
        ev = engine.get_evidence("FedRAMP")
        for item in ev:
            for field in ("id", "framework", "evidence_type", "title", "is_passing", "is_stale", "collected_at"):
                assert field in item, f"Missing field '{field}' in evidence item"

    def test_evidence_stale_flag(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("CMMC")
        ev = engine.get_evidence("CMMC")
        # Freshly collected evidence should not be stale
        assert all(not item["is_stale"] for item in ev)


# ---------------------------------------------------------------------------
# Framework status / control monitoring
# ---------------------------------------------------------------------------


class TestFrameworkStatus:
    def test_get_framework_status_structure(self, engine: ComplianceAutomationEngine) -> None:
        status = engine.get_framework_status("SOC2")
        for key in ("framework", "full_name", "issuer", "version", "score", "total_controls",
                    "status_breakdown", "controls", "assessed_at"):
            assert key in status

    def test_score_is_zero_before_collection(self, engine: ComplianceAutomationEngine) -> None:
        status = engine.get_framework_status("ISO27001")
        assert status["score"] == 0.0

    def test_score_increases_after_collection(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("SOC2")
        status = engine.get_framework_status("SOC2")
        assert status["score"] > 0

    def test_score_is_percentage(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("HIPAA")
        status = engine.get_framework_status("HIPAA")
        assert 0.0 <= status["score"] <= 100.0

    def test_all_seven_frameworks_return_status(self, engine: ComplianceAutomationEngine) -> None:
        for fw in FRAMEWORKS:
            status = engine.get_framework_status(fw)
            assert status["framework"] == fw

    def test_invalid_framework_raises(self, engine: ComplianceAutomationEngine) -> None:
        with pytest.raises(ValueError, match="Unsupported framework"):
            engine.get_framework_status("BOGUS")

    def test_controls_list_populated(self, engine: ComplianceAutomationEngine) -> None:
        status = engine.get_framework_status("CMMC")
        assert len(status["controls"]) >= 14

    def test_overall_status_structure(self, engine: ComplianceAutomationEngine) -> None:
        overall = engine.get_overall_status()
        assert "overall_score" in overall
        assert "frameworks" in overall
        assert len(overall["frameworks"]) == 7

    def test_overall_score_is_average(self, engine: ComplianceAutomationEngine) -> None:
        overall = engine.get_overall_status()
        fw_scores = [f["score"] for f in overall["frameworks"]]
        expected = round(sum(fw_scores) / len(fw_scores), 2)
        assert overall["overall_score"] == expected


# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------


class TestGapAnalysis:
    def test_all_controls_are_gaps_before_collection(self, engine: ComplianceAutomationEngine) -> None:
        gaps = engine.get_gaps("SOC2")
        soc2_count = len(_FRAMEWORK_CONTROLS["SOC2"])
        assert len(gaps) == soc2_count

    def test_gaps_decrease_after_collection(self, engine: ComplianceAutomationEngine) -> None:
        before = len(engine.get_gaps("PCI-DSS"))
        engine.collect_evidence("PCI-DSS")
        after = len(engine.get_gaps("PCI-DSS"))
        assert after < before

    def test_gaps_sorted_by_priority(self, engine: ComplianceAutomationEngine) -> None:
        gaps = engine.get_gaps("NIST-800-53")
        prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        scores = [prio_order.get(g.priority.value, 99) for g in gaps]
        assert scores == sorted(scores), "Gaps not sorted by priority"

    def test_gap_has_required_fields(self, engine: ComplianceAutomationEngine) -> None:
        gaps = engine.get_gaps("HIPAA")
        for g in gaps:
            assert g.control_id
            assert g.framework == "HIPAA"
            assert g.priority in RemediationPriority.__members__.values()
            assert g.reason
            assert g.recommended_action

    def test_get_gaps_all_frameworks(self, engine: ComplianceAutomationEngine) -> None:
        gaps = engine.get_gaps()
        total_controls = sum(len(v) for v in _FRAMEWORK_CONTROLS.values())
        assert len(gaps) == total_controls

    def test_invalid_framework_raises(self, engine: ComplianceAutomationEngine) -> None:
        with pytest.raises(ValueError):
            engine.get_gaps("INVALID")

    def test_no_not_started_after_full_collection(self, engine: ComplianceAutomationEngine) -> None:
        # After collecting evidence for FedRAMP all controls are assessed
        engine.collect_evidence("FedRAMP")
        gaps = engine.get_gaps("FedRAMP")
        # No gaps should be in NOT_STARTED state after full evidence collection
        not_started = [g for g in gaps if g.status == ControlStatus.NOT_STARTED]
        assert len(not_started) == 0


# ---------------------------------------------------------------------------
# Cross-framework mapping
# ---------------------------------------------------------------------------


class TestCrossFrameworkMapping:
    def test_returns_list(self, engine: ComplianceAutomationEngine) -> None:
        entries = engine.get_cross_map()
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_entry_has_required_fields(self, engine: ComplianceAutomationEngine) -> None:
        entries = engine.get_cross_map()
        for e in entries:
            assert e.anchor_control_id
            assert e.anchor_framework in FRAMEWORKS
            assert len(e.mapped_controls) > 0

    def test_access_control_maps_across_frameworks(self, engine: ComplianceAutomationEngine) -> None:
        entries = engine.get_cross_map()
        # SOC2 CC6.1 should map to PCI-DSS, HIPAA, etc.
        cc61 = next((e for e in entries if e.anchor_framework == "SOC2" and e.anchor_control_id == "CC6.1"), None)
        assert cc61 is not None
        frameworks_mapped = {m["framework"] for m in cc61.mapped_controls}
        assert len(frameworks_mapped) >= 2

    def test_mapped_controls_are_parseable(self, engine: ComplianceAutomationEngine) -> None:
        entries = engine.get_cross_map()
        for e in entries:
            for m in e.mapped_controls:
                assert "framework" in m
                assert "control_id" in m


# ---------------------------------------------------------------------------
# POA&M tracking
# ---------------------------------------------------------------------------


class TestPOAMTracking:
    def test_create_poam(self, engine: ComplianceAutomationEngine) -> None:
        p = engine.create_poam(
            control_id="CC6.1",
            framework="SOC2",
            title="MFA not enforced",
            description="Multi-factor authentication is not enforced for admin accounts.",
        )
        assert p.id is not None
        assert p.control_id == "CC6.1"
        assert p.framework == "SOC2"
        assert p.status == POAMStatus.OPEN

    def test_create_poam_invalid_framework(self, engine: ComplianceAutomationEngine) -> None:
        with pytest.raises(ValueError, match="Unsupported framework"):
            engine.create_poam("CTL-1", "INVALID", "title", "desc")

    def test_get_poam_list_empty(self, engine: ComplianceAutomationEngine) -> None:
        items = engine.get_poam_list()
        assert items == []

    def test_get_poam_list_after_create(self, engine: ComplianceAutomationEngine) -> None:
        engine.create_poam("REQ-3", "PCI-DSS", "Encryption gap", "PAN data not encrypted at rest.")
        items = engine.get_poam_list()
        assert len(items) == 1

    def test_get_poam_list_filter_by_framework(self, engine: ComplianceAutomationEngine) -> None:
        engine.create_poam("CC6.1", "SOC2", "SOC2 gap", "desc")
        engine.create_poam("AC-1", "FedRAMP", "FedRAMP gap", "desc")
        soc2_items = engine.get_poam_list("SOC2")
        assert all(p.framework == "SOC2" for p in soc2_items)
        assert len(soc2_items) == 1

    def test_update_poam_status(self, engine: ComplianceAutomationEngine) -> None:
        p = engine.create_poam("164.312(b)", "HIPAA", "Audit log gap", "desc")
        updated = engine.update_poam_status(p.id, POAMStatus.IN_PROGRESS)
        assert updated.status == POAMStatus.IN_PROGRESS

    def test_update_poam_risk_accepted(self, engine: ComplianceAutomationEngine) -> None:
        p = engine.create_poam("A.5.1.1", "ISO27001", "Policy gap", "desc")
        updated = engine.update_poam_status(p.id, POAMStatus.RISK_ACCEPTED, risk_accepted=True)
        assert updated.risk_accepted is True
        assert updated.status == POAMStatus.RISK_ACCEPTED

    def test_update_poam_not_found(self, engine: ComplianceAutomationEngine) -> None:
        with pytest.raises(KeyError):
            engine.update_poam_status("nonexistent-id", POAMStatus.COMPLETED)

    def test_poam_default_target_date_is_90_days(self, engine: ComplianceAutomationEngine) -> None:
        p = engine.create_poam("SI-2", "NIST-800-53", "Vuln gap", "desc")
        target = datetime.fromisoformat(p.target_date)
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        delta = target - datetime.now(timezone.utc)
        assert 85 <= delta.days <= 95


# ---------------------------------------------------------------------------
# Score tracking
# ---------------------------------------------------------------------------


class TestScoreTracking:
    def test_record_score_returns_compliance_score(self, engine: ComplianceAutomationEngine) -> None:
        score = engine.record_score("SOC2")
        assert isinstance(score, ComplianceScore)
        assert score.framework == "SOC2"
        assert 0.0 <= score.score <= 100.0

    def test_score_trend_empty_before_recording(self, engine: ComplianceAutomationEngine) -> None:
        trend = engine.get_score_trend("CMMC")
        assert trend == []

    def test_score_trend_after_recording(self, engine: ComplianceAutomationEngine) -> None:
        engine.record_score("CMMC")
        engine.record_score("CMMC")
        trend = engine.get_score_trend("CMMC")
        assert len(trend) == 2

    def test_score_trend_limit(self, engine: ComplianceAutomationEngine) -> None:
        for _ in range(10):
            engine.record_score("FedRAMP")
        trend = engine.get_score_trend("FedRAMP", limit=3)
        assert len(trend) <= 3

    def test_score_increases_after_evidence(self, engine: ComplianceAutomationEngine) -> None:
        s1 = engine.record_score("HIPAA")
        engine.collect_evidence("HIPAA")
        s2 = engine.record_score("HIPAA")
        assert s2.score >= s1.score


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


class TestReportGeneration:
    def test_report_structure(self, engine: ComplianceAutomationEngine) -> None:
        report = engine.generate_report("SOC2")
        assert isinstance(report, ComplianceReport)
        assert report.framework == "SOC2"
        assert report.report_id is not None
        assert "overall_score" in report.executive_summary
        assert isinstance(report.control_details, list)
        assert isinstance(report.gap_analysis, list)
        assert isinstance(report.evidence_references, list)
        assert isinstance(report.poam_items, list)
        assert isinstance(report.remediation_timeline, list)

    def test_report_executive_summary_fields(self, engine: ComplianceAutomationEngine) -> None:
        report = engine.generate_report("PCI-DSS")
        es = report.executive_summary
        for key in ("framework", "full_name", "issuer", "version", "org_id",
                    "overall_score", "total_controls", "total_gaps", "critical_gaps"):
            assert key in es, f"Missing key '{key}' in executive_summary"

    def test_report_for_all_frameworks(self, engine: ComplianceAutomationEngine) -> None:
        for fw in FRAMEWORKS:
            report = engine.generate_report(fw)
            assert report.framework == fw

    def test_report_invalid_framework(self, engine: ComplianceAutomationEngine) -> None:
        with pytest.raises(ValueError, match="Unsupported framework"):
            engine.generate_report("BOGUS")

    def test_report_org_id_override(self, engine: ComplianceAutomationEngine) -> None:
        report = engine.generate_report("CMMC", org_id="acme-corp")
        assert report.org_id == "acme-corp"

    def test_report_includes_evidence_after_collection(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("NIST-800-53")
        report = engine.generate_report("NIST-800-53")
        assert len(report.evidence_references) > 0

    def test_report_includes_poam_after_creation(self, engine: ComplianceAutomationEngine) -> None:
        engine.create_poam("AC-1", "FedRAMP", "Access control gap", "desc")
        report = engine.generate_report("FedRAMP")
        assert len(report.poam_items) == 1

    def test_report_score_matches_framework_status(self, engine: ComplianceAutomationEngine) -> None:
        engine.collect_evidence("ISO27001")
        status = engine.get_framework_status("ISO27001")
        report = engine.generate_report("ISO27001")
        assert report.score == status["score"]


# ---------------------------------------------------------------------------
# Router endpoints
# ---------------------------------------------------------------------------


class TestComplianceRouter:
    @pytest.fixture
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.compliance_automation_router import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_get_overall_status(self, client) -> None:
        resp = client.get("/api/v1/compliance/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_score" in data
        assert "frameworks" in data
        assert len(data["frameworks"]) == 7

    def test_get_framework_status_soc2(self, client) -> None:
        resp = client.get("/api/v1/compliance/framework/SOC2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert "score" in data
        assert "controls" in data

    def test_get_framework_status_invalid(self, client) -> None:
        resp = client.get("/api/v1/compliance/framework/BOGUS")
        assert resp.status_code == 422

    def test_get_gaps_all(self, client) -> None:
        resp = client.get("/api/v1/compliance/gaps")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_gaps_filtered(self, client) -> None:
        resp = client.get("/api/v1/compliance/gaps?framework=HIPAA")
        assert resp.status_code == 200
        data = resp.json()
        for gap in data:
            assert gap["framework"] == "HIPAA"

    def test_get_gaps_invalid_framework(self, client) -> None:
        resp = client.get("/api/v1/compliance/gaps?framework=NOPE")
        assert resp.status_code == 422

    def test_get_evidence_empty(self, client) -> None:
        resp = client.get("/api/v1/compliance/evidence")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_collect_evidence_all_controls(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance/evidence/collect",
            json={"framework": "SOC2"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert data["items_collected"] > 0
        assert isinstance(data["evidence"], list)

    def test_collect_evidence_specific_control(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance/evidence/collect",
            json={"framework": "PCI-DSS", "control_id": "REQ-10"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["control_id"] == "REQ-10"

    def test_collect_evidence_invalid_framework(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance/evidence/collect",
            json={"framework": "UNKNOWN"},
        )
        assert resp.status_code == 422

    def test_get_crossmap(self, client) -> None:
        resp = client.get("/api/v1/compliance/crossmap")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_get_poam_empty(self, client) -> None:
        resp = client.get("/api/v1/compliance/poam")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_create_poam(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance/poam",
            json={
                "control_id": "CC6.1",
                "framework": "SOC2",
                "title": "MFA gap",
                "description": "MFA not enforced.",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["control_id"] == "CC6.1"
        assert data["status"] == "open"

    def test_create_poam_invalid_framework(self, client) -> None:
        resp = client.post(
            "/api/v1/compliance/poam",
            json={
                "control_id": "X1",
                "framework": "INVALID",
                "title": "gap",
                "description": "desc",
            },
        )
        assert resp.status_code == 422

    def test_update_poam_status(self, client) -> None:
        create_resp = client.post(
            "/api/v1/compliance/poam",
            json={"control_id": "AC-1", "framework": "FedRAMP", "title": "t", "description": "d"},
        )
        poam_id = create_resp.json()["id"]
        update_resp = client.patch(
            f"/api/v1/compliance/poam/{poam_id}",
            json={"status": "in_progress", "risk_accepted": False},
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["status"] == "in_progress"

    def test_update_poam_not_found(self, client) -> None:
        resp = client.patch(
            "/api/v1/compliance/poam/nonexistent-id",
            json={"status": "completed", "risk_accepted": False},
        )
        assert resp.status_code == 404

    def test_generate_report(self, client) -> None:
        resp = client.post("/api/v1/compliance/report/CMMC")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "CMMC"
        assert "executive_summary" in data
        assert "gap_analysis" in data
        assert "control_details" in data

    def test_generate_report_invalid_framework(self, client) -> None:
        resp = client.post("/api/v1/compliance/report/BOGUS")
        assert resp.status_code == 422

    def test_record_score_endpoint(self, client) -> None:
        resp = client.post("/api/v1/compliance/score/SOC2")
        assert resp.status_code == 201
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert "score" in data

    def test_score_trend_endpoint(self, client) -> None:
        client.post("/api/v1/compliance/score/NIST-800-53")
        resp = client.get("/api/v1/compliance/score/NIST-800-53/trend")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_list_frameworks_endpoint(self, client) -> None:
        resp = client.get("/api/v1/compliance/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        assert "frameworks" in data
        assert data["count"] == 7
        assert "metadata" in data

    def test_get_poam_filtered_by_framework(self, client) -> None:
        client.post(
            "/api/v1/compliance/poam",
            json={"control_id": "SI-2", "framework": "NIST-800-53", "title": "t", "description": "d"},
        )
        resp = client.get("/api/v1/compliance/poam?framework=NIST-800-53")
        assert resp.status_code == 200
        data = resp.json()
        assert all(p["framework"] == "NIST-800-53" for p in data)

    def test_get_evidence_filtered(self, client) -> None:
        client.post("/api/v1/compliance/evidence/collect", json={"framework": "ISO27001"})
        resp = client.get("/api/v1/compliance/evidence?framework=ISO27001")
        assert resp.status_code == 200
        data = resp.json()
        assert all(e["framework"] == "ISO27001" for e in data)
