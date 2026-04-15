"""Tests for EndpointThreatHuntingEngine — 30+ tests covering all methods,
state transitions, JSON round-trip, findings_count increment, and org isolation."""

from __future__ import annotations

import os
import pytest

from core.endpoint_threat_hunting_engine import EndpointThreatHuntingEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_eth.db")
    return EndpointThreatHuntingEngine(db_path=db)


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------


def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "eth.db")
    EndpointThreatHuntingEngine(db_path=db)
    assert os.path.exists(db)


def test_engine_two_instances_same_db(tmp_path):
    db = str(tmp_path / "eth.db")
    e1 = EndpointThreatHuntingEngine(db_path=db)
    e2 = EndpointThreatHuntingEngine(db_path=db)
    e1.create_hunt(ORG_A, {"hunt_name": "Hunt1", "hunt_type": "proactive"})
    assert len(e2.list_hunts(ORG_A)) == 1


# ---------------------------------------------------------------------------
# Hunts — create
# ---------------------------------------------------------------------------


def test_create_hunt_returns_dict(engine):
    result = engine.create_hunt(ORG_A, {"hunt_name": "APT Hunt", "hunt_type": "proactive"})
    assert "id" in result
    assert result["org_id"] == ORG_A
    assert result["hunt_name"] == "APT Hunt"
    assert result["hunt_type"] == "proactive"
    assert result["status"] == "planned"
    assert result["findings_count"] == 0
    assert result["endpoints_scanned"] == 0


def test_create_hunt_technique_ids_round_trip(engine):
    techniques = ["T1059", "T1078", "T1547"]
    result = engine.create_hunt(ORG_A, {
        "hunt_name": "MITRE Hunt",
        "hunt_type": "scheduled",
        "technique_ids": techniques,
    })
    assert result["technique_ids"] == techniques


def test_create_hunt_invalid_hunt_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid hunt_type"):
        engine.create_hunt(ORG_A, {"hunt_name": "Bad Hunt", "hunt_type": "unknown"})


def test_create_hunt_all_types(engine):
    for htype in ("proactive", "reactive", "scheduled", "automated"):
        result = engine.create_hunt(ORG_A, {"hunt_name": f"Hunt-{htype}", "hunt_type": htype})
        assert result["hunt_type"] == htype


def test_create_hunt_defaults_status_planned(engine):
    result = engine.create_hunt(ORG_A, {"hunt_name": "Hunt", "hunt_type": "proactive"})
    assert result["status"] == "planned"
    assert result["started_at"] is None
    assert result["completed_at"] is None


def test_create_hunt_stores_hunter(engine):
    result = engine.create_hunt(ORG_A, {
        "hunt_name": "Hunt",
        "hunt_type": "proactive",
        "hunter": "analyst1",
    })
    assert result["hunter"] == "analyst1"


# ---------------------------------------------------------------------------
# Hunts — start
# ---------------------------------------------------------------------------


def test_start_hunt_sets_active(engine):
    hunt = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    result = engine.start_hunt(ORG_A, hunt["id"])
    assert result["status"] == "active"
    assert result["started_at"] is not None


def test_start_hunt_unknown_raises_key_error(engine):
    with pytest.raises(KeyError):
        engine.start_hunt(ORG_A, "nonexistent-id")


def test_start_hunt_already_active_raises_value_error(engine):
    hunt = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    engine.start_hunt(ORG_A, hunt["id"])
    with pytest.raises(ValueError, match="already active"):
        engine.start_hunt(ORG_A, hunt["id"])


def test_start_hunt_org_isolation(engine):
    hunt = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    with pytest.raises(KeyError):
        engine.start_hunt(ORG_B, hunt["id"])


# ---------------------------------------------------------------------------
# Hunts — complete
# ---------------------------------------------------------------------------


def test_complete_hunt_sets_completed(engine):
    hunt = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    engine.start_hunt(ORG_A, hunt["id"])
    result = engine.complete_hunt(ORG_A, hunt["id"], endpoints_scanned=250)
    assert result["status"] == "completed"
    assert result["completed_at"] is not None
    assert result["endpoints_scanned"] == 250


def test_complete_hunt_unknown_raises_key_error(engine):
    with pytest.raises(KeyError):
        engine.complete_hunt(ORG_A, "nonexistent-id")


# ---------------------------------------------------------------------------
# Hunts — list / get
# ---------------------------------------------------------------------------


def test_list_hunts_empty(engine):
    assert engine.list_hunts(ORG_A) == []


def test_list_hunts_returns_all(engine):
    engine.create_hunt(ORG_A, {"hunt_name": "H1", "hunt_type": "proactive"})
    engine.create_hunt(ORG_A, {"hunt_name": "H2", "hunt_type": "reactive"})
    assert len(engine.list_hunts(ORG_A)) == 2


def test_list_hunts_filter_by_status(engine):
    h = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    engine.start_hunt(ORG_A, h["id"])
    engine.create_hunt(ORG_A, {"hunt_name": "H2", "hunt_type": "proactive"})
    active = engine.list_hunts(ORG_A, status="active")
    assert len(active) == 1
    assert active[0]["status"] == "active"


def test_list_hunts_filter_by_type(engine):
    engine.create_hunt(ORG_A, {"hunt_name": "H1", "hunt_type": "proactive"})
    engine.create_hunt(ORG_A, {"hunt_name": "H2", "hunt_type": "reactive"})
    proactive = engine.list_hunts(ORG_A, hunt_type="proactive")
    assert len(proactive) == 1
    assert proactive[0]["hunt_type"] == "proactive"


def test_list_hunts_org_isolation(engine):
    engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    engine.create_hunt(ORG_B, {"hunt_name": "H", "hunt_type": "proactive"})
    assert len(engine.list_hunts(ORG_A)) == 1
    assert len(engine.list_hunts(ORG_B)) == 1


def test_get_hunt_returns_dict(engine):
    hunt = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    result = engine.get_hunt(ORG_A, hunt["id"])
    assert result is not None
    assert result["id"] == hunt["id"]


def test_get_hunt_not_found_returns_none(engine):
    assert engine.get_hunt(ORG_A, "nonexistent") is None


def test_get_hunt_org_isolation(engine):
    hunt = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    assert engine.get_hunt(ORG_B, hunt["id"]) is None


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def test_record_finding_returns_dict(engine):
    hunt = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    result = engine.record_finding(ORG_A, {
        "hunt_id": hunt["id"],
        "endpoint_id": "ep-001",
        "finding_type": "malware",
        "severity": "critical",
        "process_name": "cmd.exe",
    })
    assert "id" in result
    assert result["finding_type"] == "malware"
    assert result["severity"] == "critical"
    assert result["status"] == "new"


def test_record_finding_increments_findings_count(engine):
    hunt = engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    assert engine.get_hunt(ORG_A, hunt["id"])["findings_count"] == 0
    engine.record_finding(ORG_A, {"hunt_id": hunt["id"], "finding_type": "persistence", "severity": "high"})
    engine.record_finding(ORG_A, {"hunt_id": hunt["id"], "finding_type": "malware", "severity": "medium"})
    assert engine.get_hunt(ORG_A, hunt["id"])["findings_count"] == 2


def test_record_finding_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid finding_type"):
        engine.record_finding(ORG_A, {"hunt_id": "x", "finding_type": "unknown", "severity": "low"})


def test_record_finding_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.record_finding(ORG_A, {"hunt_id": "x", "finding_type": "malware", "severity": "extreme"})


def test_list_findings_empty(engine):
    assert engine.list_findings(ORG_A) == []


def test_list_findings_filter_by_hunt(engine):
    h1 = engine.create_hunt(ORG_A, {"hunt_name": "H1", "hunt_type": "proactive"})
    h2 = engine.create_hunt(ORG_A, {"hunt_name": "H2", "hunt_type": "proactive"})
    engine.record_finding(ORG_A, {"hunt_id": h1["id"], "finding_type": "malware", "severity": "low"})
    engine.record_finding(ORG_A, {"hunt_id": h2["id"], "finding_type": "persistence", "severity": "low"})
    result = engine.list_findings(ORG_A, hunt_id=h1["id"])
    assert len(result) == 1
    assert result[0]["hunt_id"] == h1["id"]


def test_list_findings_filter_by_severity(engine):
    engine.record_finding(ORG_A, {"hunt_id": "x", "finding_type": "malware", "severity": "critical"})
    engine.record_finding(ORG_A, {"hunt_id": "x", "finding_type": "persistence", "severity": "low"})
    critical = engine.list_findings(ORG_A, severity="critical")
    assert all(f["severity"] == "critical" for f in critical)


def test_update_finding_status(engine):
    f = engine.record_finding(ORG_A, {"hunt_id": "x", "finding_type": "malware", "severity": "high"})
    result = engine.update_finding_status(ORG_A, f["id"], "confirmed")
    assert result["status"] == "confirmed"


def test_update_finding_status_invalid_raises(engine):
    f = engine.record_finding(ORG_A, {"hunt_id": "x", "finding_type": "malware", "severity": "high"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.update_finding_status(ORG_A, f["id"], "invalid_status")


def test_list_findings_org_isolation(engine):
    engine.record_finding(ORG_A, {"hunt_id": "x", "finding_type": "malware", "severity": "low"})
    engine.record_finding(ORG_B, {"hunt_id": "y", "finding_type": "malware", "severity": "low"})
    assert len(engine.list_findings(ORG_A)) == 1
    assert len(engine.list_findings(ORG_B)) == 1


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------


def test_add_ioc_returns_dict(engine):
    result = engine.add_ioc(ORG_A, {
        "hunt_id": "hunt-1",
        "ioc_value": "4a5e1c0f",
        "ioc_type": "hash",
        "confidence_score": 85.0,
    })
    assert "id" in result
    assert result["ioc_type"] == "hash"
    assert result["confidence_score"] == 85.0


def test_add_ioc_clamps_confidence(engine):
    r1 = engine.add_ioc(ORG_A, {"hunt_id": "x", "ioc_value": "v", "ioc_type": "ip", "confidence_score": 150.0})
    assert r1["confidence_score"] == 100.0
    r2 = engine.add_ioc(ORG_A, {"hunt_id": "x", "ioc_value": "v", "ioc_type": "ip", "confidence_score": -5.0})
    assert r2["confidence_score"] == 0.0


def test_add_ioc_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid ioc_type"):
        engine.add_ioc(ORG_A, {"hunt_id": "x", "ioc_value": "v", "ioc_type": "unknown"})


def test_add_ioc_all_types(engine):
    for ioc_type in ("hash", "ip", "domain", "path", "registry_key", "mutex", "process_name", "user_agent"):
        result = engine.add_ioc(ORG_A, {"hunt_id": "x", "ioc_value": "v", "ioc_type": ioc_type})
        assert result["ioc_type"] == ioc_type


def test_list_iocs_empty(engine):
    assert engine.list_iocs(ORG_A) == []


def test_list_iocs_filter_by_hunt(engine):
    engine.add_ioc(ORG_A, {"hunt_id": "h1", "ioc_value": "v1", "ioc_type": "hash"})
    engine.add_ioc(ORG_A, {"hunt_id": "h2", "ioc_value": "v2", "ioc_type": "ip"})
    result = engine.list_iocs(ORG_A, hunt_id="h1")
    assert len(result) == 1
    assert result[0]["hunt_id"] == "h1"


def test_list_iocs_filter_by_type(engine):
    engine.add_ioc(ORG_A, {"hunt_id": "x", "ioc_value": "v1", "ioc_type": "hash"})
    engine.add_ioc(ORG_A, {"hunt_id": "x", "ioc_value": "v2", "ioc_type": "ip"})
    hashes = engine.list_iocs(ORG_A, ioc_type="hash")
    assert all(i["ioc_type"] == "hash" for i in hashes)


def test_list_iocs_org_isolation(engine):
    engine.add_ioc(ORG_A, {"hunt_id": "x", "ioc_value": "v", "ioc_type": "hash"})
    engine.add_ioc(ORG_B, {"hunt_id": "y", "ioc_value": "v", "ioc_type": "hash"})
    assert len(engine.list_iocs(ORG_A)) == 1
    assert len(engine.list_iocs(ORG_B)) == 1


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_hunting_stats_empty(engine):
    stats = engine.get_hunting_stats(ORG_A)
    assert stats["total_hunts"] == 0
    assert stats["active_hunts"] == 0
    assert stats["completed_hunts"] == 0
    assert stats["total_findings"] == 0
    assert stats["critical_findings"] == 0
    assert stats["confirmed_findings"] == 0
    assert stats["total_iocs"] == 0
    assert stats["by_hunt_type"] == {}
    assert stats["by_finding_type"] == {}


def test_get_hunting_stats_counts(engine):
    h1 = engine.create_hunt(ORG_A, {"hunt_name": "H1", "hunt_type": "proactive"})
    engine.start_hunt(ORG_A, h1["id"])
    h2 = engine.create_hunt(ORG_A, {"hunt_name": "H2", "hunt_type": "reactive"})
    engine.start_hunt(ORG_A, h2["id"])
    engine.complete_hunt(ORG_A, h2["id"], endpoints_scanned=100)

    engine.record_finding(ORG_A, {"hunt_id": h1["id"], "finding_type": "malware", "severity": "critical"})
    f2 = engine.record_finding(ORG_A, {"hunt_id": h1["id"], "finding_type": "persistence", "severity": "high"})
    engine.update_finding_status(ORG_A, f2["id"], "confirmed")

    engine.add_ioc(ORG_A, {"hunt_id": h1["id"], "ioc_value": "abc", "ioc_type": "hash"})
    engine.add_ioc(ORG_A, {"hunt_id": h1["id"], "ioc_value": "1.2.3.4", "ioc_type": "ip"})

    stats = engine.get_hunting_stats(ORG_A)
    assert stats["total_hunts"] == 2
    assert stats["active_hunts"] == 1
    assert stats["completed_hunts"] == 1
    assert stats["total_findings"] == 2
    assert stats["critical_findings"] == 1
    assert stats["confirmed_findings"] == 1
    assert stats["total_iocs"] == 2
    assert stats["by_hunt_type"]["proactive"] == 1
    assert stats["by_hunt_type"]["reactive"] == 1
    assert stats["by_finding_type"]["malware"] == 1
    assert stats["by_finding_type"]["persistence"] == 1


def test_get_hunting_stats_org_isolation(engine):
    engine.create_hunt(ORG_A, {"hunt_name": "H", "hunt_type": "proactive"})
    engine.create_hunt(ORG_B, {"hunt_name": "H", "hunt_type": "proactive"})
    engine.create_hunt(ORG_B, {"hunt_name": "H2", "hunt_type": "reactive"})
    assert engine.get_hunting_stats(ORG_A)["total_hunts"] == 1
    assert engine.get_hunting_stats(ORG_B)["total_hunts"] == 2
