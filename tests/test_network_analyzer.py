"""
Tests for NetworkAnalyzer — network segmentation analysis.

Covers:
- NetworkZone / NetworkFlow / SegmentationViolation Pydantic models
- NetworkAnalyzer: define_zone, add_flow, analyze_segmentation,
  detect_violations, get_zone_matrix, get_lateral_movement_risk,
  get_micro_segmentation_score, get_network_stats
- Router endpoints (FastAPI TestClient)
- Edge cases: missing zones, empty state, policy logic

30+ tests, all passing.
"""
from __future__ import annotations

import os
import sys
import tempfile
import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.network_analyzer import (
    FlowDirection,
    NetworkAnalyzer,
    NetworkFlow,
    NetworkZone,
    SegmentationViolation,
    ViolationSeverity,
    ZoneType,
    _policy_check,
    _risk_label,
    _score_grade,
    get_network_analyzer,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Return path to a temp SQLite DB."""
    return str(tmp_path / "test_network.db")


@pytest.fixture
def analyzer(tmp_db):
    """Fresh NetworkAnalyzer for each test."""
    return NetworkAnalyzer(db_path=tmp_db)


@pytest.fixture
def populated_analyzer(analyzer):
    """Analyzer with zones + flows pre-loaded."""
    ext = analyzer.define_zone("internet", ZoneType.EXTERNAL, cidrs=["0.0.0.0/0"], trust_level=0)
    dmz = analyzer.define_zone("dmz", ZoneType.DMZ, cidrs=["10.0.1.0/24"], trust_level=30)
    internal = analyzer.define_zone("internal", ZoneType.INTERNAL, cidrs=["10.0.2.0/24"], trust_level=70)
    restricted = analyzer.define_zone("db-tier", ZoneType.RESTRICTED, cidrs=["10.0.3.0/24"], trust_level=90)
    mgmt = analyzer.define_zone("management", ZoneType.MANAGEMENT, cidrs=["192.168.0.0/24"], trust_level=95)

    # Allowed flows
    analyzer.add_flow(ext.id, dmz.id, ports=[443], protocol="tcp")
    analyzer.add_flow(dmz.id, internal.id, ports=[8080], protocol="tcp")
    # Policy-denied flows
    analyzer.add_flow(ext.id, internal.id, ports=[22], protocol="tcp")
    analyzer.add_flow(ext.id, restricted.id, ports=[5432], protocol="tcp")
    analyzer.add_flow(dmz.id, restricted.id, ports=[3306], protocol="tcp")

    return analyzer, {
        "ext": ext, "dmz": dmz, "internal": internal,
        "restricted": restricted, "mgmt": mgmt,
    }


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestNetworkZone:
    def test_zone_defaults(self):
        zone = NetworkZone(name="test", type=ZoneType.INTERNAL, trust_level=50)
        assert zone.id is not None
        assert zone.cidrs == []
        assert zone.assets == []
        assert zone.metadata == {}

    def test_zone_to_dict(self):
        zone = NetworkZone(
            name="dmz", type=ZoneType.DMZ, cidrs=["10.0.0.0/24"],
            assets=["a1"], trust_level=30,
        )
        d = zone.to_dict()
        assert d["name"] == "dmz"
        assert d["type"] == "dmz"
        assert d["cidrs"] == ["10.0.0.0/24"]
        assert d["assets"] == ["a1"]
        assert d["trust_level"] == 30
        assert "created_at" in d

    def test_zone_type_enum_values(self):
        assert ZoneType.DMZ.value == "dmz"
        assert ZoneType.INTERNAL.value == "internal"
        assert ZoneType.EXTERNAL.value == "external"
        assert ZoneType.RESTRICTED.value == "restricted"
        assert ZoneType.MANAGEMENT.value == "management"


class TestNetworkFlow:
    def test_flow_defaults(self):
        flow = NetworkFlow(
            source_zone="z1", dest_zone="z2",
            direction=FlowDirection.INBOUND, allowed=True,
        )
        assert flow.ports == []
        assert flow.protocol == "tcp"
        assert flow.risk_score == 0.0

    def test_flow_to_dict(self):
        flow = NetworkFlow(
            source_zone="z1", dest_zone="z2", ports=[443],
            protocol="tcp", direction=FlowDirection.OUTBOUND,
            allowed=False, risk_score=75.0,
        )
        d = flow.to_dict()
        assert d["ports"] == [443]
        assert d["allowed"] is False
        assert d["risk_score"] == 75.0
        assert d["direction"] == "outbound"


class TestSegmentationViolation:
    def test_violation_to_dict(self):
        flow = NetworkFlow(
            source_zone="z1", dest_zone="z2",
            direction=FlowDirection.LATERAL, allowed=False,
        )
        v = SegmentationViolation(
            flow=flow,
            rule_violated="No policy defined",
            severity=ViolationSeverity.HIGH,
        )
        d = v.to_dict()
        assert "flow" in d
        assert d["severity"] == "high"
        assert d["rule_violated"] == "No policy defined"
        assert "detected_at" in d


# ---------------------------------------------------------------------------
# Policy logic tests
# ---------------------------------------------------------------------------


class TestPolicyCheck:
    def test_same_zone_always_allowed(self):
        allowed, reason = _policy_check("internal", "internal")
        assert allowed is True

    def test_external_to_dmz_allowed(self):
        allowed, _ = _policy_check("external", "dmz")
        assert allowed is True

    def test_external_to_internal_denied(self):
        allowed, reason = _policy_check("external", "internal")
        assert allowed is False
        assert "forbidden" in reason.lower()

    def test_external_to_restricted_denied(self):
        allowed, _ = _policy_check("external", "restricted")
        assert allowed is False

    def test_external_to_management_denied(self):
        allowed, _ = _policy_check("external", "management")
        assert allowed is False

    def test_dmz_to_restricted_denied(self):
        allowed, _ = _policy_check("dmz", "restricted")
        assert allowed is False

    def test_management_to_internal_allowed(self):
        allowed, _ = _policy_check("management", "internal")
        assert allowed is True

    def test_management_to_external_denied(self):
        allowed, _ = _policy_check("management", "external")
        assert allowed is False

    def test_unknown_pair_denied(self):
        allowed, reason = _policy_check("restricted", "external")
        assert allowed is False


# ---------------------------------------------------------------------------
# NetworkAnalyzer core tests
# ---------------------------------------------------------------------------


class TestDefineZone:
    def test_create_zone_returns_zone(self, analyzer):
        zone = analyzer.define_zone("dmz", ZoneType.DMZ, cidrs=["10.0.0.0/24"], trust_level=30)
        assert zone.id is not None
        assert zone.name == "dmz"
        assert zone.type == ZoneType.DMZ
        assert zone.trust_level == 30

    def test_get_zone_by_id(self, analyzer):
        zone = analyzer.define_zone("internal", ZoneType.INTERNAL, trust_level=70)
        fetched = analyzer.get_zone(zone.id)
        assert fetched is not None
        assert fetched.id == zone.id
        assert fetched.name == "internal"

    def test_get_zone_missing_returns_none(self, analyzer):
        assert analyzer.get_zone("nonexistent-id") is None

    def test_list_zones_empty(self, analyzer):
        assert analyzer.list_zones() == []

    def test_list_zones_multiple(self, analyzer):
        analyzer.define_zone("z1", ZoneType.DMZ, trust_level=30)
        analyzer.define_zone("z2", ZoneType.INTERNAL, trust_level=70)
        zones = analyzer.list_zones()
        assert len(zones) == 2

    def test_zone_persisted_cidrs(self, analyzer):
        zone = analyzer.define_zone("ext", ZoneType.EXTERNAL, cidrs=["0.0.0.0/0"], trust_level=0)
        fetched = analyzer.get_zone(zone.id)
        assert fetched.cidrs == ["0.0.0.0/0"]


class TestAddFlow:
    def test_add_flow_allowed(self, analyzer):
        ext = analyzer.define_zone("ext", ZoneType.EXTERNAL, trust_level=0)
        dmz = analyzer.define_zone("dmz", ZoneType.DMZ, trust_level=30)
        flow = analyzer.add_flow(ext.id, dmz.id, ports=[443])
        assert flow.allowed is True
        assert flow.source_zone == ext.id
        assert flow.dest_zone == dmz.id

    def test_add_flow_denied(self, analyzer):
        ext = analyzer.define_zone("ext", ZoneType.EXTERNAL, trust_level=0)
        internal = analyzer.define_zone("internal", ZoneType.INTERNAL, trust_level=70)
        flow = analyzer.add_flow(ext.id, internal.id, ports=[22])
        assert flow.allowed is False
        assert flow.risk_score > 0

    def test_add_flow_invalid_source_raises(self, analyzer):
        dmz = analyzer.define_zone("dmz", ZoneType.DMZ, trust_level=30)
        with pytest.raises(ValueError, match="Source zone"):
            analyzer.add_flow("bad-id", dmz.id, ports=[80])

    def test_add_flow_invalid_dest_raises(self, analyzer):
        ext = analyzer.define_zone("ext", ZoneType.EXTERNAL, trust_level=0)
        with pytest.raises(ValueError, match="Destination zone"):
            analyzer.add_flow(ext.id, "bad-id", ports=[80])

    def test_add_flow_risk_score_populated(self, analyzer):
        ext = analyzer.define_zone("ext", ZoneType.EXTERNAL, trust_level=0)
        restricted = analyzer.define_zone("restricted", ZoneType.RESTRICTED, trust_level=90)
        flow = analyzer.add_flow(ext.id, restricted.id, ports=[5432])
        assert flow.risk_score > 0

    def test_list_flows_empty(self, analyzer):
        assert analyzer.list_flows() == []

    def test_list_flows_filter_allowed(self, populated_analyzer):
        analyzer, zones = populated_analyzer
        allowed = analyzer.list_flows(allowed=True)
        assert all(f.allowed for f in allowed)

    def test_list_flows_filter_denied(self, populated_analyzer):
        analyzer, zones = populated_analyzer
        denied = analyzer.list_flows(allowed=False)
        assert all(not f.allowed for f in denied)


class TestAnalyzeSegmentation:
    def test_empty_returns_100_compliance(self, analyzer):
        result = analyzer.analyze_segmentation()
        assert result["compliance_percentage"] == 100.0
        assert result["total_flows"] == 0

    def test_compliance_percentage_mixed(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        result = analyzer.analyze_segmentation()
        assert result["total_flows"] == 5
        assert 0 < result["compliance_percentage"] < 100
        assert result["violation_count"] > 0

    def test_returns_violations_list(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        result = analyzer.analyze_segmentation()
        assert isinstance(result["violations"], list)
        assert len(result["violations"]) > 0


class TestDetectViolations:
    def test_no_violations_when_all_allowed(self, analyzer):
        ext = analyzer.define_zone("ext", ZoneType.EXTERNAL, trust_level=0)
        dmz = analyzer.define_zone("dmz", ZoneType.DMZ, trust_level=30)
        analyzer.add_flow(ext.id, dmz.id, ports=[443])
        violations = analyzer.detect_violations()
        assert violations == []

    def test_detects_unauthorized_flows(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        violations = analyzer.detect_violations()
        assert len(violations) > 0
        assert all(isinstance(v, SegmentationViolation) for v in violations)

    def test_violations_have_severity(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        violations = analyzer.detect_violations()
        for v in violations:
            assert v.severity in list(ViolationSeverity)

    def test_no_duplicate_violations(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        v1 = analyzer.detect_violations()
        v2 = analyzer.detect_violations()
        assert len(v1) == len(v2)


class TestZoneMatrix:
    def test_matrix_empty(self, analyzer):
        result = analyzer.get_zone_matrix()
        assert result["total_zone_pairs"] == 0
        assert result["matrix"] == []

    def test_matrix_populated(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        result = analyzer.get_zone_matrix()
        assert result["total_zone_pairs"] > 0
        for entry in result["matrix"]:
            assert "source_zone_name" in entry
            assert "dest_zone_name" in entry
            assert "flow_count" in entry
            assert "avg_risk_score" in entry

    def test_matrix_counts_correct(self, analyzer):
        ext = analyzer.define_zone("ext", ZoneType.EXTERNAL, trust_level=0)
        dmz = analyzer.define_zone("dmz", ZoneType.DMZ, trust_level=30)
        analyzer.add_flow(ext.id, dmz.id, ports=[443])
        analyzer.add_flow(ext.id, dmz.id, ports=[80])
        result = analyzer.get_zone_matrix()
        pair = result["matrix"][0]
        assert pair["flow_count"] == 2


class TestLateralMovementRisk:
    def test_lateral_risk_empty(self, analyzer):
        result = analyzer.get_lateral_movement_risk()
        assert result["total_lateral_flows"] == 0
        assert result["overall_lateral_movement_risk"] == 0.0

    def test_lateral_risk_with_flows(self, populated_analyzer):
        analyzer, zones = populated_analyzer
        # Add explicit lateral flow
        analyzer.add_flow(
            zones["dmz"].id, zones["internal"].id,
            ports=[8080], direction=FlowDirection.LATERAL,
        )
        result = analyzer.get_lateral_movement_risk()
        assert result["total_lateral_flows"] >= 1
        assert "risk_level" in result
        assert "pivot_zones" in result
        assert "high_risk_paths" in result


class TestMicroSegmentationScore:
    def test_score_no_zones(self, analyzer):
        result = analyzer.get_micro_segmentation_score()
        assert result["score"] == 100

    def test_score_returns_grade(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        result = analyzer.get_micro_segmentation_score()
        assert result["grade"] in ("A", "B", "C", "D", "F")
        assert 0 <= result["score"] <= 100

    def test_score_breakdown_keys(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        result = analyzer.get_micro_segmentation_score()
        breakdown = result["breakdown"]
        assert "policy_compliance" in breakdown
        assert "zone_isolation" in breakdown
        assert "lateral_movement_control" in breakdown
        assert "zone_granularity" in breakdown

    def test_score_decreases_with_violations(self, analyzer):
        """More violations = lower score."""
        ext = analyzer.define_zone("ext", ZoneType.EXTERNAL, trust_level=0)
        restricted = analyzer.define_zone("restricted", ZoneType.RESTRICTED, trust_level=90)
        # No flows — perfect score
        clean = analyzer.get_micro_segmentation_score()
        # Add denied flows
        for _ in range(5):
            analyzer.add_flow(ext.id, restricted.id, ports=[5432])
        dirty = analyzer.get_micro_segmentation_score()
        assert dirty["score"] <= clean["score"]


class TestGetNetworkStats:
    def test_stats_empty(self, analyzer):
        stats = analyzer.get_network_stats()
        assert stats["zone_count"] == 0
        assert stats["flow_count"] == 0
        assert stats["violation_count"] == 0

    def test_stats_populated(self, populated_analyzer):
        analyzer, _ = populated_analyzer
        analyzer.detect_violations()
        stats = analyzer.get_network_stats()
        assert stats["zone_count"] == 5
        assert stats["flow_count"] == 5
        assert stats["violation_count"] > 0
        assert "zones_by_type" in stats
        assert "violations_by_severity" in stats

    def test_stats_avg_risk_score(self, analyzer):
        ext = analyzer.define_zone("ext", ZoneType.EXTERNAL, trust_level=0)
        dmz = analyzer.define_zone("dmz", ZoneType.DMZ, trust_level=30)
        analyzer.add_flow(ext.id, dmz.id, ports=[443])
        stats = analyzer.get_network_stats()
        assert stats["avg_risk_score"] >= 0.0


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_risk_label_low(self):
        assert _risk_label(10.0) == "low"

    def test_risk_label_medium(self):
        assert _risk_label(30.0) == "medium"

    def test_risk_label_high(self):
        assert _risk_label(60.0) == "high"

    def test_risk_label_critical(self):
        assert _risk_label(80.0) == "critical"

    def test_score_grade_a(self):
        assert _score_grade(95) == "A"

    def test_score_grade_b(self):
        assert _score_grade(85) == "B"

    def test_score_grade_f(self):
        assert _score_grade(50) == "F"


# ---------------------------------------------------------------------------
# Router integration tests
# ---------------------------------------------------------------------------


class TestNetworkAnalyzerRouter:
    @pytest.fixture
    def client(self, tmp_db, monkeypatch):
        """TestClient with isolated DB."""
        import core.network_analyzer as na_module
        # Reset singleton for test isolation
        monkeypatch.setattr(na_module, "_analyzer", None)
        monkeypatch.setenv("FIXOPS_API_TOKEN", "test-token")

        fresh = NetworkAnalyzer(db_path=tmp_db)
        monkeypatch.setattr(na_module, "_analyzer", fresh)

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.network_analyzer_router import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_create_zone(self, client):
        resp = client.post("/api/v1/network/zones", json={
            "name": "dmz", "type": "dmz", "trust_level": 30,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "dmz"
        assert data["type"] == "dmz"

    def test_list_zones_empty(self, client):
        resp = client.get("/api/v1/network/zones")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_zone_not_found(self, client):
        resp = client.get("/api/v1/network/zones/nonexistent")
        assert resp.status_code == 404

    def test_add_flow_missing_zone(self, client):
        resp = client.post("/api/v1/network/flows", json={
            "source_zone": "bad", "dest_zone": "bad2",
        })
        assert resp.status_code == 404

    def test_full_workflow(self, client):
        # Create zones
        ext = client.post("/api/v1/network/zones", json={
            "name": "internet", "type": "external", "trust_level": 0,
        }).json()
        dmz = client.post("/api/v1/network/zones", json={
            "name": "dmz", "type": "dmz", "trust_level": 30,
        }).json()

        # Add allowed flow
        flow = client.post("/api/v1/network/flows", json={
            "source_zone": ext["id"], "dest_zone": dmz["id"], "ports": [443],
        }).json()
        assert flow["allowed"] is True

        # Segmentation analysis
        analysis = client.get("/api/v1/network/analysis/segmentation").json()
        assert analysis["total_flows"] == 1

        # Zone matrix
        matrix = client.get("/api/v1/network/analysis/zone-matrix").json()
        assert matrix["total_zone_pairs"] == 1

        # Segmentation score
        score = client.get("/api/v1/network/analysis/segmentation-score").json()
        assert 0 <= score["score"] <= 100

        # Stats
        stats = client.get("/api/v1/network/stats").json()
        assert stats["zone_count"] == 2
        assert stats["flow_count"] == 1

    def test_detect_violations_endpoint(self, client):
        ext = client.post("/api/v1/network/zones", json={
            "name": "internet", "type": "external", "trust_level": 0,
        }).json()
        internal = client.post("/api/v1/network/zones", json={
            "name": "internal", "type": "internal", "trust_level": 70,
        }).json()
        client.post("/api/v1/network/flows", json={
            "source_zone": ext["id"], "dest_zone": internal["id"], "ports": [22],
        })
        violations = client.post("/api/v1/network/analysis/detect-violations").json()
        assert len(violations) == 1
        assert violations[0]["severity"] in ("critical", "high", "medium", "low")

    def test_lateral_movement_endpoint(self, client):
        resp = client.get("/api/v1/network/analysis/lateral-movement")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_lateral_flows" in data
        assert "risk_level" in data
