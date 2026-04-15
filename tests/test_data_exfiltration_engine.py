"""Tests for DataExfiltrationEngine — incidents, policies, indicators, stats."""

from __future__ import annotations

import pytest

from core.data_exfiltration_engine import DataExfiltrationEngine


@pytest.fixture
def engine(tmp_path):
    return DataExfiltrationEngine(db_path=str(tmp_path / "data_exfiltration.db"))


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = tmp_path / "exfil.db"
    DataExfiltrationEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = tmp_path / "exfil.db"
    DataExfiltrationEngine(db_path=str(db))
    DataExfiltrationEngine(db_path=str(db))


# ---------------------------------------------------------------------------
# record_incident
# ---------------------------------------------------------------------------

def test_record_incident_returns_record(engine):
    incident = engine.record_incident("org1", {
        "incident_type": "email",
        "severity": "high",
        "user_id": "user-42",
        "data_classification": "confidential",
        "estimated_volume_mb": 5.5,
        "detection_method": "dlp",
    })
    assert incident["id"]
    assert incident["incident_type"] == "email"
    assert incident["severity"] == "high"
    assert incident["org_id"] == "org1"
    assert incident["status"] == "detected"
    assert incident["data_classification"] == "confidential"
    assert incident["estimated_volume_mb"] == 5.5
    assert incident["blocked"] is False


def test_record_incident_invalid_incident_type_raises(engine):
    with pytest.raises(ValueError, match="incident_type"):
        engine.record_incident("org1", {
            "incident_type": "ftp_upload",
            "severity": "low",
            "data_classification": "internal",
            "detection_method": "dlp",
        })


def test_record_incident_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_incident("org1", {
            "incident_type": "usb",
            "severity": "extreme",
            "data_classification": "internal",
            "detection_method": "dlp",
        })


def test_record_incident_invalid_data_classification_raises(engine):
    with pytest.raises(ValueError, match="data_classification"):
        engine.record_incident("org1", {
            "incident_type": "usb",
            "severity": "high",
            "data_classification": "restricted",
            "detection_method": "dlp",
        })


def test_record_incident_invalid_detection_method_raises(engine):
    with pytest.raises(ValueError, match="detection_method"):
        engine.record_incident("org1", {
            "incident_type": "cloud_upload",
            "severity": "medium",
            "data_classification": "internal",
            "detection_method": "ai",
        })


def test_record_incident_default_status_detected(engine):
    incident = engine.record_incident("org1", {
        "incident_type": "print",
        "severity": "low",
        "data_classification": "internal",
        "detection_method": "endpoint",
    })
    assert incident["status"] == "detected"


def test_record_incident_all_types(engine):
    types = ["email", "usb", "cloud_upload", "print", "screenshot", "api_abuse", "network_tunnel", "removable_media"]
    for t in types:
        inc = engine.record_incident("org1", {
            "incident_type": t,
            "severity": "low",
            "data_classification": "public",
            "detection_method": "manual",
        })
        assert inc["incident_type"] == t


# ---------------------------------------------------------------------------
# list_incidents
# ---------------------------------------------------------------------------

def test_list_incidents_empty(engine):
    assert engine.list_incidents("org1") == []


def test_list_incidents_org_isolation(engine):
    engine.record_incident("org1", {
        "incident_type": "email", "severity": "low",
        "data_classification": "internal", "detection_method": "dlp",
    })
    engine.record_incident("org2", {
        "incident_type": "usb", "severity": "high",
        "data_classification": "confidential", "detection_method": "ueba",
    })
    assert len(engine.list_incidents("org1")) == 1
    assert len(engine.list_incidents("org2")) == 1


def test_list_incidents_filter_severity(engine):
    engine.record_incident("org1", {
        "incident_type": "email", "severity": "critical",
        "data_classification": "top_secret", "detection_method": "dlp",
    })
    engine.record_incident("org1", {
        "incident_type": "usb", "severity": "low",
        "data_classification": "public", "detection_method": "endpoint",
    })
    results = engine.list_incidents("org1", severity="critical")
    assert len(results) == 1
    assert results[0]["severity"] == "critical"


def test_list_incidents_filter_status(engine):
    engine.record_incident("org1", {
        "incident_type": "print", "severity": "medium",
        "data_classification": "internal", "detection_method": "manual",
        "status": "confirmed",
    })
    engine.record_incident("org1", {
        "incident_type": "screenshot", "severity": "low",
        "data_classification": "public", "detection_method": "network",
        "status": "false_positive",
    })
    results = engine.list_incidents("org1", status="confirmed")
    assert len(results) == 1
    assert results[0]["status"] == "confirmed"


def test_list_incidents_filter_incident_type(engine):
    engine.record_incident("org1", {
        "incident_type": "api_abuse", "severity": "high",
        "data_classification": "confidential", "detection_method": "ueba",
    })
    engine.record_incident("org1", {
        "incident_type": "usb", "severity": "critical",
        "data_classification": "top_secret", "detection_method": "endpoint",
    })
    results = engine.list_incidents("org1", incident_type="api_abuse")
    assert len(results) == 1
    assert results[0]["incident_type"] == "api_abuse"


# ---------------------------------------------------------------------------
# get_incident
# ---------------------------------------------------------------------------

def test_get_incident_returns_record(engine):
    incident = engine.record_incident("org1", {
        "incident_type": "network_tunnel", "severity": "high",
        "data_classification": "confidential", "detection_method": "network",
    })
    fetched = engine.get_incident("org1", incident["id"])
    assert fetched is not None
    assert fetched["id"] == incident["id"]


def test_get_incident_not_found_returns_none(engine):
    assert engine.get_incident("org1", "nonexistent-id") is None


def test_get_incident_org_isolation(engine):
    incident = engine.record_incident("org1", {
        "incident_type": "email", "severity": "low",
        "data_classification": "public", "detection_method": "manual",
    })
    assert engine.get_incident("org2", incident["id"]) is None


# ---------------------------------------------------------------------------
# update_incident_status
# ---------------------------------------------------------------------------

def test_update_incident_status_valid(engine):
    incident = engine.record_incident("org1", {
        "incident_type": "usb", "severity": "high",
        "data_classification": "confidential", "detection_method": "endpoint",
    })
    updated = engine.update_incident_status("org1", incident["id"], "investigating")
    assert updated is not None
    assert updated["status"] == "investigating"


def test_update_incident_status_invalid_raises(engine):
    incident = engine.record_incident("org1", {
        "incident_type": "usb", "severity": "low",
        "data_classification": "internal", "detection_method": "dlp",
    })
    with pytest.raises(ValueError, match="status"):
        engine.update_incident_status("org1", incident["id"], "closed")


def test_update_incident_status_not_found_returns_none(engine):
    result = engine.update_incident_status("org1", "nonexistent-id", "remediated")
    assert result is None


# ---------------------------------------------------------------------------
# create_policy + list_policies
# ---------------------------------------------------------------------------

def test_create_policy_returns_record(engine):
    policy = engine.create_policy("org1", {
        "policy_name": "Block USB Transfers",
        "action": "block",
        "data_classification": "confidential",
        "channel": "usb",
        "enabled": True,
    })
    assert policy["id"]
    assert policy["policy_name"] == "Block USB Transfers"
    assert policy["action"] == "block"
    assert policy["enabled"] is True


def test_create_policy_invalid_action_raises(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_policy("org1", {
            "policy_name": "X",
            "action": "deny",
            "data_classification": "internal",
            "channel": "all",
        })


def test_create_policy_invalid_data_classification_raises(engine):
    with pytest.raises(ValueError, match="data_classification"):
        engine.create_policy("org1", {
            "policy_name": "X",
            "action": "alert",
            "data_classification": "secret",
            "channel": "all",
        })


def test_create_policy_invalid_channel_raises(engine):
    with pytest.raises(ValueError, match="channel"):
        engine.create_policy("org1", {
            "policy_name": "X",
            "action": "log",
            "data_classification": "internal",
            "channel": "ftp",
        })


def test_list_policies_enabled_filter(engine):
    engine.create_policy("org1", {
        "policy_name": "Active Policy", "action": "block",
        "data_classification": "internal", "channel": "all", "enabled": True,
    })
    engine.create_policy("org1", {
        "policy_name": "Disabled Policy", "action": "log",
        "data_classification": "public", "channel": "email", "enabled": False,
    })
    enabled = engine.list_policies("org1", enabled=True)
    disabled = engine.list_policies("org1", enabled=False)
    assert len(enabled) == 1
    assert len(disabled) == 1
    assert enabled[0]["enabled"] is True
    assert disabled[0]["enabled"] is False


# ---------------------------------------------------------------------------
# add_indicator + list_indicators
# ---------------------------------------------------------------------------

def test_add_indicator_returns_record(engine):
    indicator = engine.add_indicator("org1", {
        "indicator_type": "keyword",
        "value": "SSN",
        "confidence_score": 85.0,
    })
    assert indicator["id"]
    assert indicator["indicator_type"] == "keyword"
    assert indicator["confidence_score"] == 85.0


def test_add_indicator_clamps_confidence_above_100(engine):
    indicator = engine.add_indicator("org1", {
        "indicator_type": "regex",
        "value": r"\d{4}-\d{4}-\d{4}-\d{4}",
        "confidence_score": 150.0,
    })
    assert indicator["confidence_score"] == 100.0


def test_add_indicator_clamps_confidence_below_0(engine):
    indicator = engine.add_indicator("org1", {
        "indicator_type": "file_type",
        "value": ".pem",
        "confidence_score": -10.0,
    })
    assert indicator["confidence_score"] == 0.0


def test_add_indicator_invalid_indicator_type_raises(engine):
    with pytest.raises(ValueError, match="indicator_type"):
        engine.add_indicator("org1", {
            "indicator_type": "behavioral",
            "value": "something",
            "confidence_score": 50.0,
        })


def test_list_indicators_filter_by_incident_id(engine):
    incident1 = engine.record_incident("org1", {
        "incident_type": "email", "severity": "high",
        "data_classification": "confidential", "detection_method": "dlp",
    })
    engine.add_indicator("org1", {
        "incident_id": incident1["id"],
        "indicator_type": "keyword",
        "value": "CONFIDENTIAL",
        "confidence_score": 90.0,
    })
    engine.add_indicator("org1", {
        "incident_id": "other-incident",
        "indicator_type": "regex",
        "value": r"\d+",
        "confidence_score": 60.0,
    })
    results = engine.list_indicators("org1", incident_id=incident1["id"])
    assert len(results) == 1
    assert results[0]["incident_id"] == incident1["id"]


def test_list_indicators_org_isolation(engine):
    engine.add_indicator("org1", {
        "indicator_type": "destination",
        "value": "dropbox.com",
        "confidence_score": 75.0,
    })
    engine.add_indicator("org2", {
        "indicator_type": "destination",
        "value": "wetransfer.com",
        "confidence_score": 70.0,
    })
    assert len(engine.list_indicators("org1")) == 1
    assert len(engine.list_indicators("org2")) == 1


def test_list_indicators_all_types(engine):
    types = ["keyword", "regex", "file_type", "destination", "volume_threshold", "time_pattern"]
    for t in types:
        engine.add_indicator("org1", {"indicator_type": t, "value": "v", "confidence_score": 50.0})
    results = engine.list_indicators("org1")
    found_types = {r["indicator_type"] for r in results}
    assert found_types == set(types)


# ---------------------------------------------------------------------------
# get_exfil_stats
# ---------------------------------------------------------------------------

def test_get_exfil_stats_empty_org(engine):
    stats = engine.get_exfil_stats("org_empty")
    assert stats["total_incidents"] == 0
    assert stats["confirmed_incidents"] == 0
    assert stats["blocked_incidents"] == 0
    assert stats["critical_incidents"] == 0
    assert stats["total_volume_mb"] == 0.0
    assert stats["by_type"] == {}
    assert stats["by_status"] == {}
    assert stats["by_classification"] == {}


def test_get_exfil_stats_populated_counts(engine):
    engine.record_incident("org1", {
        "incident_type": "email", "severity": "critical",
        "data_classification": "confidential", "detection_method": "dlp",
        "estimated_volume_mb": 10.0, "blocked": True, "status": "confirmed",
    })
    engine.record_incident("org1", {
        "incident_type": "usb", "severity": "high",
        "data_classification": "internal", "detection_method": "endpoint",
        "estimated_volume_mb": 5.0, "blocked": False, "status": "detected",
    })

    stats = engine.get_exfil_stats("org1")
    assert stats["total_incidents"] == 2
    assert stats["confirmed_incidents"] == 1
    assert stats["blocked_incidents"] == 1
    assert stats["critical_incidents"] == 1
    assert stats["total_volume_mb"] == pytest.approx(15.0)
    assert stats["by_type"]["email"] == 1
    assert stats["by_type"]["usb"] == 1
    assert stats["by_status"]["confirmed"] == 1
    assert stats["by_status"]["detected"] == 1
    assert stats["by_classification"]["confidential"] == 1
    assert stats["by_classification"]["internal"] == 1
