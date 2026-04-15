"""Tests for NetworkForensicsEngine — 30+ tests covering captures,
artifacts, analysis, stats, and org isolation."""
from __future__ import annotations

import os
import pytest

from core.network_forensics_engine import NetworkForensicsEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_nf.db")
    return NetworkForensicsEngine(db_path=db)


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------

def test_engine_init_creates_db(tmp_path):
    db = str(tmp_path / "nf.db")
    NetworkForensicsEngine(db_path=db)
    assert os.path.exists(db)


def test_engine_two_instances_same_db(tmp_path):
    db = str(tmp_path / "nf.db")
    e1 = NetworkForensicsEngine(db_path=db)
    e2 = NetworkForensicsEngine(db_path=db)
    e1.create_capture(ORG_A, {"interface": "eth0"})
    assert len(e2.list_captures(ORG_A)) == 1


# ---------------------------------------------------------------------------
# Captures — create
# ---------------------------------------------------------------------------

def test_create_capture_returns_dict(engine):
    result = engine.create_capture(ORG_A, {"interface": "eth0"})
    assert "id" in result
    assert result["org_id"] == ORG_A
    assert result["interface"] == "eth0"
    assert result["status"] == "running"


def test_create_capture_custom_fields(engine):
    result = engine.create_capture(ORG_A, {
        "interface": "eth1",
        "filter_bpf": "tcp port 80",
        "duration_sec": 120,
    })
    assert result["filter_bpf"] == "tcp port 80"
    assert result["duration_sec"] == 120


def test_create_capture_missing_interface_raises(engine):
    with pytest.raises(ValueError, match="interface"):
        engine.create_capture(ORG_A, {})


def test_create_capture_empty_interface_raises(engine):
    with pytest.raises(ValueError, match="interface"):
        engine.create_capture(ORG_A, {"interface": "   "})


def test_create_capture_default_status_running(engine):
    result = engine.create_capture(ORG_A, {"interface": "eth0"})
    assert result["status"] == "running"


def test_create_capture_started_at_populated(engine):
    result = engine.create_capture(ORG_A, {"interface": "eth0"})
    assert result["started_at"] is not None


# ---------------------------------------------------------------------------
# Captures — list / get
# ---------------------------------------------------------------------------

def test_list_captures_empty(engine):
    assert engine.list_captures(ORG_A) == []


def test_list_captures_returns_own_org(engine):
    engine.create_capture(ORG_A, {"interface": "eth0"})
    engine.create_capture(ORG_A, {"interface": "eth1"})
    engine.create_capture(ORG_B, {"interface": "eth0"})
    results = engine.list_captures(ORG_A)
    assert len(results) == 2
    assert all(r["org_id"] == ORG_A for r in results)


def test_list_captures_org_isolation(engine):
    engine.create_capture(ORG_A, {"interface": "eth0"})
    assert engine.list_captures(ORG_B) == []


def test_list_captures_filter_by_status(engine):
    engine.create_capture(ORG_A, {"interface": "eth0"})
    cap = engine.create_capture(ORG_A, {"interface": "eth1"})
    engine.update_capture_status(ORG_A, cap["id"], "completed")
    running = engine.list_captures(ORG_A, status="running")
    assert len(running) == 1
    assert running[0]["status"] == "running"
    completed = engine.list_captures(ORG_A, status="completed")
    assert len(completed) == 1


def test_get_capture_returns_record(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    fetched = engine.get_capture(ORG_A, cap["id"])
    assert fetched is not None
    assert fetched["id"] == cap["id"]


def test_get_capture_not_found_returns_none(engine):
    assert engine.get_capture(ORG_A, "nonexistent-id") is None


def test_get_capture_org_isolation(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    assert engine.get_capture(ORG_B, cap["id"]) is None


# ---------------------------------------------------------------------------
# Artifacts — add
# ---------------------------------------------------------------------------

def test_add_artifact_valid_type_pcap(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    art = engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "pcap", "size_bytes": 1024})
    assert "id" in art
    assert art["artifact_type"] == "pcap"
    assert art["size_bytes"] == 1024
    assert art["org_id"] == ORG_A
    assert art["capture_id"] == cap["id"]


def test_add_artifact_valid_type_flow(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    art = engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "flow"})
    assert art["artifact_type"] == "flow"


def test_add_artifact_valid_type_dns_log(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    art = engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "dns_log"})
    assert art["artifact_type"] == "dns_log"


def test_add_artifact_valid_type_http_log(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    art = engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "http_log"})
    assert art["artifact_type"] == "http_log"


def test_add_artifact_invalid_type_raises(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    with pytest.raises(ValueError, match="artifact_type"):
        engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "unknown_type"})


def test_add_artifact_findings_count(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    art = engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "pcap", "findings_count": 5})
    assert art["findings_count"] == 5


# ---------------------------------------------------------------------------
# Analyze capture
# ---------------------------------------------------------------------------

def test_analyze_capture_returns_summary(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "pcap"})
    summary = engine.analyze_capture(ORG_A, cap["id"], {
        "suspicious_ips": ["10.0.0.1", "192.168.1.5"],
        "protocols_seen": ["TCP", "UDP"],
        "anomalies": ["port scan detected"],
    })
    assert summary["capture_id"] == cap["id"]
    assert "10.0.0.1" in summary["suspicious_ips"]
    assert "TCP" in summary["protocols_seen"]
    assert "port scan detected" in summary["anomalies"]


def test_analyze_capture_no_artifact_still_returns(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    summary = engine.analyze_capture(ORG_A, cap["id"], {"suspicious_ips": []})
    assert summary["capture_id"] == cap["id"]
    assert summary["suspicious_ips"] == []


def test_analyze_capture_updates_artifact_analysis_json(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "pcap"})
    engine.analyze_capture(ORG_A, cap["id"], {"suspicious_ips": ["1.2.3.4"], "anomalies": ["x"]})
    arts = engine.list_artifacts(ORG_A, capture_id=cap["id"])
    assert arts[0]["analysis_json"] != ""


# ---------------------------------------------------------------------------
# List artifacts
# ---------------------------------------------------------------------------

def test_list_artifacts_empty(engine):
    assert engine.list_artifacts(ORG_A) == []


def test_list_artifacts_org_isolation(engine):
    cap_a = engine.create_capture(ORG_A, {"interface": "eth0"})
    engine.add_artifact(ORG_A, cap_a["id"], {"artifact_type": "pcap"})
    assert engine.list_artifacts(ORG_B) == []


def test_list_artifacts_filter_by_capture_id(engine):
    cap1 = engine.create_capture(ORG_A, {"interface": "eth0"})
    cap2 = engine.create_capture(ORG_A, {"interface": "eth1"})
    engine.add_artifact(ORG_A, cap1["id"], {"artifact_type": "pcap"})
    engine.add_artifact(ORG_A, cap2["id"], {"artifact_type": "flow"})
    arts = engine.list_artifacts(ORG_A, capture_id=cap1["id"])
    assert len(arts) == 1
    assert arts[0]["capture_id"] == cap1["id"]


def test_list_artifacts_all_for_org(engine):
    cap1 = engine.create_capture(ORG_A, {"interface": "eth0"})
    cap2 = engine.create_capture(ORG_A, {"interface": "eth1"})
    engine.add_artifact(ORG_A, cap1["id"], {"artifact_type": "pcap"})
    engine.add_artifact(ORG_A, cap2["id"], {"artifact_type": "flow"})
    assert len(engine.list_artifacts(ORG_A)) == 2


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_stats_empty_org(engine):
    stats = engine.get_forensics_stats(ORG_A)
    assert stats["total_captures"] == 0
    assert stats["active_captures"] == 0
    assert stats["total_artifacts"] == 0
    assert stats["suspicious_captures"] == 0


def test_stats_total_captures(engine):
    engine.create_capture(ORG_A, {"interface": "eth0"})
    engine.create_capture(ORG_A, {"interface": "eth1"})
    stats = engine.get_forensics_stats(ORG_A)
    assert stats["total_captures"] == 2


def test_stats_active_captures(engine):
    cap1 = engine.create_capture(ORG_A, {"interface": "eth0"})
    cap2 = engine.create_capture(ORG_A, {"interface": "eth1"})
    engine.update_capture_status(ORG_A, cap1["id"], "completed")
    stats = engine.get_forensics_stats(ORG_A)
    assert stats["active_captures"] == 1


def test_stats_suspicious_captures(engine):
    cap = engine.create_capture(ORG_A, {"interface": "eth0"})
    engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "pcap", "findings_count": 3})
    engine.add_artifact(ORG_A, cap["id"], {"artifact_type": "flow", "findings_count": 0})
    stats = engine.get_forensics_stats(ORG_A)
    assert stats["suspicious_captures"] == 1


def test_stats_org_isolation(engine):
    engine.create_capture(ORG_A, {"interface": "eth0"})
    stats = engine.get_forensics_stats(ORG_B)
    assert stats["total_captures"] == 0


def test_stats_contains_org_id(engine):
    stats = engine.get_forensics_stats(ORG_A)
    assert stats["org_id"] == ORG_A
