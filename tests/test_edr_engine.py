"""Tests for EDREngine — 27 tests covering all methods + org isolation."""

from __future__ import annotations

import tempfile
import pytest
from core.edr_engine import EDREngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "edr_test.db")
    return EDREngine(db_path=db)


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _ep(engine, org, hostname="host-01", os_type="linux"):
    return engine.register_endpoint(org, {"hostname": hostname, "os_type": os_type})


# ---------------------------------------------------------------------------
# register_endpoint
# ---------------------------------------------------------------------------

def test_register_endpoint_returns_record(engine, org):
    ep = _ep(engine, org)
    assert ep["hostname"] == "host-01"
    assert ep["org_id"] == org
    assert ep["status"] == "online"
    assert ep["os_type"] == "linux"
    assert "endpoint_id" in ep


def test_register_endpoint_missing_hostname_raises(engine, org):
    with pytest.raises(ValueError, match="hostname"):
        engine.register_endpoint(org, {"hostname": ""})


def test_register_endpoint_invalid_os_type_raises(engine, org):
    with pytest.raises(ValueError, match="os_type"):
        engine.register_endpoint(org, {"hostname": "h", "os_type": "beos"})


def test_register_endpoint_all_os_types(engine, org):
    for os_type in ("windows", "linux", "macos", "android", "ios"):
        ep = engine.register_endpoint(org, {"hostname": f"h-{os_type}", "os_type": os_type})
        assert ep["os_type"] == os_type


# ---------------------------------------------------------------------------
# list_endpoints
# ---------------------------------------------------------------------------

def test_list_endpoints_empty(engine, org):
    assert engine.list_endpoints(org) == []


def test_list_endpoints_returns_own_org_only(engine, org, org2):
    _ep(engine, org, "host-a")
    _ep(engine, org2, "host-b")
    result = engine.list_endpoints(org)
    assert len(result) == 1
    assert result[0]["hostname"] == "host-a"


def test_list_endpoints_filter_status(engine, org):
    ep = _ep(engine, org, "host-x")
    engine.isolate_endpoint(org, ep["endpoint_id"], "test", "admin")
    online = engine.list_endpoints(org, status="online")
    isolated = engine.list_endpoints(org, status="isolated")
    assert len(online) == 0
    assert len(isolated) == 1


def test_list_endpoints_filter_os_type(engine, org):
    _ep(engine, org, "win-host", os_type="windows")
    _ep(engine, org, "lin-host", os_type="linux")
    windows = engine.list_endpoints(org, os_type="windows")
    assert len(windows) == 1
    assert windows[0]["hostname"] == "win-host"


# ---------------------------------------------------------------------------
# get_endpoint
# ---------------------------------------------------------------------------

def test_get_endpoint_found(engine, org):
    ep = _ep(engine, org)
    fetched = engine.get_endpoint(org, ep["endpoint_id"])
    assert fetched["endpoint_id"] == ep["endpoint_id"]


def test_get_endpoint_not_found_returns_none(engine, org):
    assert engine.get_endpoint(org, "nonexistent-id") is None


def test_get_endpoint_org_isolation(engine, org, org2):
    ep = _ep(engine, org)
    assert engine.get_endpoint(org2, ep["endpoint_id"]) is None


# ---------------------------------------------------------------------------
# ingest_process_event
# ---------------------------------------------------------------------------

def test_ingest_process_event_basic(engine, org):
    ep = _ep(engine, org)
    event = engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "bash",
        "event_type": "create",
        "pid": 1234,
    })
    assert event["process_name"] == "bash"
    assert event["event_id"] is not None


def test_ingest_process_event_powershell_encoded_triggers_critical(engine, org):
    ep = _ep(engine, org, os_type="windows")
    event = engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "powershell.exe",
        "cmdline": "powershell.exe -enc SGVsbG8=",
        "event_type": "create",
    })
    assert event["severity"] == "critical"
    assert "mitre_technique" in event
    assert event["mitre_technique"] == "T1059.001"
    assert "_detection_created" in event


def test_ingest_process_event_mimikatz_triggers_critical(engine, org):
    ep = _ep(engine, org, os_type="windows")
    event = engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "mimikatz.exe",
        "event_type": "create",
    })
    assert event["severity"] == "critical"
    assert "_detection_created" in event


def test_ingest_process_event_psexec_triggers_high(engine, org):
    ep = _ep(engine, org, os_type="windows")
    event = engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "psexec.exe",
        "event_type": "create",
    })
    assert event["severity"] == "high"


def test_ingest_process_event_cscript_triggers_medium(engine, org):
    ep = _ep(engine, org, os_type="windows")
    event = engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "cscript.exe",
        "event_type": "create",
    })
    assert event["severity"] == "medium"


def test_ingest_process_event_invalid_event_type_raises(engine, org):
    ep = _ep(engine, org)
    with pytest.raises(ValueError, match="event_type"):
        engine.ingest_process_event(org, ep["endpoint_id"], {
            "process_name": "bash",
            "event_type": "explode",
        })


# ---------------------------------------------------------------------------
# list_process_events
# ---------------------------------------------------------------------------

def test_list_process_events_empty(engine, org):
    assert engine.list_process_events(org) == []


def test_list_process_events_org_isolation(engine, org, org2):
    ep = _ep(engine, org)
    ep2 = _ep(engine, org2, "host-b")
    engine.ingest_process_event(org, ep["endpoint_id"], {"process_name": "bash", "event_type": "create"})
    engine.ingest_process_event(org2, ep2["endpoint_id"], {"process_name": "cmd", "event_type": "create"})
    assert len(engine.list_process_events(org)) == 1
    assert len(engine.list_process_events(org2)) == 1


def test_list_process_events_filter_severity(engine, org):
    ep = _ep(engine, org, os_type="windows")
    engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "powershell.exe",
        "cmdline": "-encodedcommand abc",
        "event_type": "create",
    })
    engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "notepad.exe",
        "event_type": "create",
    })
    critical = engine.list_process_events(org, severity="critical")
    assert len(critical) == 1


# ---------------------------------------------------------------------------
# list_detections + update_detection_status
# ---------------------------------------------------------------------------

def test_list_detections_empty(engine, org):
    assert engine.list_detections(org) == []


def test_detections_created_on_suspicious_event(engine, org):
    ep = _ep(engine, org, os_type="windows")
    engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "mimikatz.exe",
        "event_type": "create",
    })
    dets = engine.list_detections(org)
    assert len(dets) == 1
    assert dets[0]["detection_type"] == "credential_dumper"
    assert dets[0]["status"] == "new"


def test_update_detection_status(engine, org):
    ep = _ep(engine, org, os_type="windows")
    engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "psexec.exe",
        "event_type": "create",
    })
    det = engine.list_detections(org)[0]
    result = engine.update_detection_status(org, det["detection_id"], "investigating")
    assert result is True
    updated = engine.list_detections(org)[0]
    assert updated["status"] == "investigating"


def test_update_detection_status_invalid_raises(engine, org):
    with pytest.raises(ValueError, match="status"):
        engine.update_detection_status(org, "fake-id", "dancing")


def test_update_detection_status_not_found_returns_false(engine, org):
    result = engine.update_detection_status(org, "nonexistent", "resolved")
    assert result is False


# ---------------------------------------------------------------------------
# isolate_endpoint + release_endpoint
# ---------------------------------------------------------------------------

def test_isolate_endpoint(engine, org):
    ep = _ep(engine, org)
    iso = engine.isolate_endpoint(org, ep["endpoint_id"], "malware found", "soc-analyst")
    assert iso["isolation_id"] is not None
    assert iso["released_at"] is None
    fetched = engine.get_endpoint(org, ep["endpoint_id"])
    assert fetched["status"] == "isolated"


def test_release_endpoint(engine, org):
    ep = _ep(engine, org)
    engine.isolate_endpoint(org, ep["endpoint_id"], "suspected", "admin")
    released = engine.release_endpoint(org, ep["endpoint_id"])
    assert released is True
    fetched = engine.get_endpoint(org, ep["endpoint_id"])
    assert fetched["status"] == "online"


def test_release_endpoint_not_found_returns_false(engine, org):
    result = engine.release_endpoint(org, "ghost-endpoint")
    assert result is False


# ---------------------------------------------------------------------------
# get_edr_stats
# ---------------------------------------------------------------------------

def test_get_edr_stats_empty(engine, org):
    stats = engine.get_edr_stats(org)
    assert stats["total_endpoints"] == 0
    assert stats["new_detections"] == 0
    assert stats["by_detection_type"] == {}


def test_get_edr_stats_populated(engine, org):
    ep = _ep(engine, org, os_type="windows")
    engine.ingest_process_event(org, ep["endpoint_id"], {
        "process_name": "mimikatz.exe",
        "event_type": "create",
    })
    stats = engine.get_edr_stats(org)
    assert stats["total_endpoints"] == 1
    assert stats["new_detections"] == 1
    assert stats["critical_detections"] == 1
    assert "credential_dumper" in stats["by_detection_type"]


def test_get_edr_stats_org_isolation(engine, org, org2):
    _ep(engine, org)
    _ep(engine, org2, "host-b")
    stats = engine.get_edr_stats(org)
    assert stats["total_endpoints"] == 1
    stats2 = engine.get_edr_stats(org2)
    assert stats2["total_endpoints"] == 1
