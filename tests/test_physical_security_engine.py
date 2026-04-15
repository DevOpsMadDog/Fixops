"""Tests for PhysicalSecurityEngine — Physical Security.

Covers: init, location CRUD, access events, incident lifecycle, stats, org isolation.
"""

from __future__ import annotations

import pytest

from core.physical_security_engine import (
    AccessEventCreate,
    IncidentCreate,
    LocationCreate,
    PhysicalSecurityEngine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return PhysicalSecurityEngine(db_path=str(tmp_path / "test_physical.db"))


def _loc(name="HQ", location_type="office", security_level="medium", **kw) -> LocationCreate:
    return LocationCreate(
        name=name,
        location_type=location_type,
        address="123 Main St",
        security_level=security_level,
        **kw,
    )


def _register(engine, org_id="org1", **kw) -> dict:
    return engine.register_location(org_id, _loc(**kw))


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "phys.db"
    PhysicalSecurityEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "phys.db")
    PhysicalSecurityEngine(db_path=db)
    PhysicalSecurityEngine(db_path=db)  # should not raise


# ---------------------------------------------------------------------------
# 2. Location registration
# ---------------------------------------------------------------------------


def test_register_location_returns_record(engine):
    loc = _register(engine)
    assert loc["name"] == "HQ"
    assert loc["location_type"] == "office"
    assert loc["security_level"] == "medium"
    assert loc["status"] == "active"
    assert "id" in loc


def test_register_location_generates_uuid(engine):
    a = _register(engine, name="A")
    b = _register(engine, name="B")
    assert a["id"] != b["id"]


def test_register_location_all_types(engine):
    for lt in ("office", "datacenter", "warehouse", "facility", "remote"):
        loc = engine.register_location("org1", _loc(name=lt, location_type=lt))
        assert loc["location_type"] == lt


def test_register_location_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="location_type"):
        engine.register_location("org1", _loc(location_type="bunker"))


def test_register_location_invalid_security_level_raises(engine):
    with pytest.raises(ValueError, match="security_level"):
        engine.register_location("org1", _loc(security_level="ultra"))


def test_register_location_critical_security_level(engine):
    loc = _register(engine, security_level="critical")
    assert loc["security_level"] == "critical"


# ---------------------------------------------------------------------------
# 3. List and get locations
# ---------------------------------------------------------------------------


def test_list_locations_empty(engine):
    assert engine.list_locations("org1") == []


def test_list_locations_returns_all(engine):
    _register(engine, name="A")
    _register(engine, name="B")
    result = engine.list_locations("org1")
    assert len(result) == 2


def test_list_locations_filter_by_type(engine):
    _register(engine, name="office1", location_type="office")
    _register(engine, name="dc1", location_type="datacenter")
    result = engine.list_locations("org1", location_type="office")
    assert len(result) == 1
    assert result[0]["name"] == "office1"


def test_list_locations_filter_by_security_level(engine):
    _register(engine, name="A", security_level="high")
    _register(engine, name="B", security_level="low")
    result = engine.list_locations("org1", security_level="high")
    assert len(result) == 1


def test_get_location_returns_record(engine):
    loc = _register(engine)
    fetched = engine.get_location("org1", loc["id"])
    assert fetched["id"] == loc["id"]


def test_get_location_wrong_org_raises(engine):
    loc = _register(engine, org_id="org1")
    with pytest.raises(ValueError):
        engine.get_location("org2", loc["id"])


def test_get_location_not_found_raises(engine):
    with pytest.raises(ValueError):
        engine.get_location("org1", "nonexistent-id")


# ---------------------------------------------------------------------------
# 4. Access events
# ---------------------------------------------------------------------------


def _make_event(engine, org_id, location_id, access_type="entry", method="badge"):
    return engine.record_access_event(
        org_id,
        AccessEventCreate(
            location_id=location_id,
            person_id="p-001",
            access_type=access_type,
            method=method,
        ),
    )


def test_record_access_event_returns_record(engine):
    loc = _register(engine)
    ev = _make_event(engine, "org1", loc["id"])
    assert ev["location_id"] == loc["id"]
    assert ev["access_type"] == "entry"
    assert ev["method"] == "badge"
    assert "id" in ev
    assert "timestamp" in ev


def test_record_access_event_all_types(engine):
    loc = _register(engine)
    for at in ("entry", "exit", "attempt", "denied"):
        ev = _make_event(engine, "org1", loc["id"], access_type=at)
        assert ev["access_type"] == at


def test_record_access_event_all_methods(engine):
    loc = _register(engine)
    for m in ("badge", "biometric", "pin", "key", "tailgate"):
        ev = _make_event(engine, "org1", loc["id"], method=m)
        assert ev["method"] == m


def test_record_access_event_invalid_type_raises(engine):
    loc = _register(engine)
    with pytest.raises(ValueError, match="access_type"):
        _make_event(engine, "org1", loc["id"], access_type="unknown_type")


def test_record_access_event_invalid_method_raises(engine):
    loc = _register(engine)
    with pytest.raises(ValueError, match="method"):
        _make_event(engine, "org1", loc["id"], method="laser")


def test_record_access_event_wrong_org_raises(engine):
    loc = _register(engine, org_id="org1")
    with pytest.raises(ValueError):
        _make_event(engine, "org2", loc["id"])


def test_list_access_events_empty(engine):
    assert engine.list_access_events("org1") == []


def test_list_access_events_filter_by_location(engine):
    loc1 = _register(engine, name="L1")
    loc2 = _register(engine, name="L2")
    _make_event(engine, "org1", loc1["id"])
    _make_event(engine, "org1", loc2["id"])
    result = engine.list_access_events("org1", location_id=loc1["id"])
    assert len(result) == 1
    assert result[0]["location_id"] == loc1["id"]


def test_list_access_events_filter_by_type(engine):
    loc = _register(engine)
    _make_event(engine, "org1", loc["id"], access_type="entry")
    _make_event(engine, "org1", loc["id"], access_type="denied")
    result = engine.list_access_events("org1", access_type="denied")
    assert len(result) == 1
    assert result[0]["access_type"] == "denied"


def test_list_access_events_ordered_desc(engine):
    loc = _register(engine)
    _make_event(engine, "org1", loc["id"])
    _make_event(engine, "org1", loc["id"])
    result = engine.list_access_events("org1")
    assert result[0]["timestamp"] >= result[1]["timestamp"]


# ---------------------------------------------------------------------------
# 5. Incident lifecycle
# ---------------------------------------------------------------------------


def _make_incident(engine, org_id, location_id, incident_type="tailgating", severity="medium"):
    return engine.record_incident(
        org_id,
        IncidentCreate(
            location_id=location_id,
            incident_type=incident_type,
            severity=severity,
            description="Test incident",
        ),
    )


def test_record_incident_returns_open(engine):
    loc = _register(engine)
    inc = _make_incident(engine, "org1", loc["id"])
    assert inc["status"] == "open"
    assert inc["incident_type"] == "tailgating"
    assert inc["severity"] == "medium"
    assert "id" in inc
    assert "detected_at" in inc


def test_record_incident_all_types(engine):
    loc = _register(engine)
    for it in ("tailgating", "unauthorized_access", "theft", "vandalism", "fire", "flood", "other"):
        inc = _make_incident(engine, "org1", loc["id"], incident_type=it)
        assert inc["incident_type"] == it


def test_record_incident_invalid_type_raises(engine):
    loc = _register(engine)
    with pytest.raises(ValueError, match="incident_type"):
        _make_incident(engine, "org1", loc["id"], incident_type="explosion")


def test_record_incident_invalid_severity_raises(engine):
    loc = _register(engine)
    with pytest.raises(ValueError, match="severity"):
        _make_incident(engine, "org1", loc["id"], severity="extreme")


def test_resolve_incident(engine):
    loc = _register(engine)
    inc = _make_incident(engine, "org1", loc["id"])
    resolved = engine.resolve_incident("org1", inc["id"], "Issue addressed by security team")
    assert resolved["status"] == "resolved"
    assert resolved["resolution"] == "Issue addressed by security team"
    assert resolved["resolved_at"] is not None


def test_resolve_incident_wrong_org_raises(engine):
    loc = _register(engine, org_id="org1")
    inc = _make_incident(engine, "org1", loc["id"])
    with pytest.raises(ValueError):
        engine.resolve_incident("org2", inc["id"], "resolution")


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------


def test_get_physical_stats_empty(engine):
    stats = engine.get_physical_stats("org1")
    assert stats["total_locations"] == 0
    assert stats["by_type"] == {}
    assert stats["total_events_today"] == 0
    assert stats["denied_attempts"] == 0
    assert stats["open_incidents"] == 0
    assert stats["by_severity"] == {}


def test_get_physical_stats_counts(engine):
    loc = _register(engine, location_type="datacenter")
    _make_event(engine, "org1", loc["id"], access_type="entry")
    _make_event(engine, "org1", loc["id"], access_type="denied")
    _make_incident(engine, "org1", loc["id"], severity="high")

    stats = engine.get_physical_stats("org1")
    assert stats["total_locations"] == 1
    assert stats["by_type"]["datacenter"] == 1
    assert stats["total_events_today"] == 2
    assert stats["denied_attempts"] == 1
    assert stats["open_incidents"] == 1
    assert stats["by_severity"]["high"] == 1


def test_get_physical_stats_resolved_not_counted(engine):
    loc = _register(engine)
    inc = _make_incident(engine, "org1", loc["id"])
    engine.resolve_incident("org1", inc["id"], "resolved")

    stats = engine.get_physical_stats("org1")
    assert stats["open_incidents"] == 0
    assert stats["by_severity"] == {}


# ---------------------------------------------------------------------------
# 7. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_locations(engine):
    _register(engine, org_id="orgA", name="A-HQ")
    _register(engine, org_id="orgB", name="B-HQ")
    a_locs = engine.list_locations("orgA")
    b_locs = engine.list_locations("orgB")
    assert len(a_locs) == 1
    assert len(b_locs) == 1
    assert a_locs[0]["name"] == "A-HQ"
    assert b_locs[0]["name"] == "B-HQ"


def test_org_isolation_events(engine):
    locA = _register(engine, org_id="orgA")
    locB = _register(engine, org_id="orgB")
    _make_event(engine, "orgA", locA["id"])
    _make_event(engine, "orgB", locB["id"])
    assert len(engine.list_access_events("orgA")) == 1
    assert len(engine.list_access_events("orgB")) == 1


def test_org_isolation_stats(engine):
    locA = _register(engine, org_id="orgA")
    _register(engine, org_id="orgB")
    _make_incident(engine, "orgA", locA["id"])

    statsA = engine.get_physical_stats("orgA")
    statsB = engine.get_physical_stats("orgB")
    assert statsA["open_incidents"] == 1
    assert statsB["open_incidents"] == 0
