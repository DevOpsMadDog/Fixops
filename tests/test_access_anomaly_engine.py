"""Tests for AccessAnomalyEngine — 35+ tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta

import pytest

from core.access_anomaly_engine import AccessAnomalyEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "access_anomaly_test.db")
    return AccessAnomalyEngine(db_path=db)


ORG = "org-alpha"
ORG2 = "org-beta"
USER = "alice"
USER2 = "bob"


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Event recording
# ---------------------------------------------------------------------------

class TestRecordEvent:
    def test_basic_record(self, engine):
        ev = engine.record_event(ORG, USER, source_ip="1.2.3.4", country="US")
        assert ev["id"]
        assert ev["username"] == USER
        assert ev["country"] == "US"
        assert ev["risk_score"] == 0.0
        assert ev["anomaly_flags"] == []
        assert ev["success"] == 1

    def test_failed_event(self, engine):
        ev = engine.record_event(ORG, USER, success=0)
        assert ev["success"] == 0

    def test_custom_access_time(self, engine):
        t = "2024-03-15T02:30:00+00:00"
        ev = engine.record_event(ORG, USER, access_time=t)
        assert ev["access_time"] == t

    def test_default_access_time_set(self, engine):
        ev = engine.record_event(ORG, USER)
        assert ev["access_time"] is not None
        datetime.fromisoformat(ev["access_time"])

    def test_resource_stored(self, engine):
        ev = engine.record_event(ORG, USER, resource="/admin/dashboard", action="GET")
        assert ev["resource"] == "/admin/dashboard"
        assert ev["action"] == "GET"


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

class TestBaseline:
    def test_upsert_new(self, engine):
        b = engine.upsert_baseline(ORG, USER,
                                   typical_countries=["US", "CA"],
                                   typical_hours=list(range(8, 18)),
                                   typical_resources=["/home", "/dashboard"])
        assert b["username"] == USER
        assert "US" in b["typical_countries"]
        assert 9 in b["typical_hours"]

    def test_upsert_replaces(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        b2 = engine.upsert_baseline(ORG, USER, typical_countries=["DE", "FR"])
        assert "US" not in b2["typical_countries"]
        assert "DE" in b2["typical_countries"]

    def test_baseline_org_isolation(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        engine.upsert_baseline(ORG2, USER, typical_countries=["CN"])
        profile1 = engine.get_user_risk_profile(ORG, USER)
        profile2 = engine.get_user_risk_profile(ORG2, USER)
        assert "US" in profile1["baseline"]["typical_countries"]
        assert "CN" in profile2["baseline"]["typical_countries"]

    def test_last_updated_set(self, engine):
        b = engine.upsert_baseline(ORG, USER)
        assert b["last_updated"] is not None


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

class TestDetectAnomalies:
    def test_no_anomalies_within_baseline(self, engine):
        engine.upsert_baseline(ORG, USER,
                               typical_countries=["US"],
                               typical_hours=list(range(0, 24)),
                               typical_resources=["/home"])
        ev = engine.record_event(ORG, USER, country="US",
                                 access_time="2024-01-10T10:00:00+00:00",
                                 resource="/home")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        assert anomalies == []

    def test_unusual_country_detected(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        types = [a["anomaly_type"] for a in anomalies]
        assert "unusual_country" in types

    def test_unusual_country_severity_medium(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="NK",
                                 access_time="2024-01-10T09:00:00+00:00")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        country_anom = next(a for a in anomalies if a["anomaly_type"] == "unusual_country")
        assert country_anom["severity"] == "medium"

    def test_unusual_time_detected(self, engine):
        engine.upsert_baseline(ORG, USER,
                               typical_countries=["US"],
                               typical_hours=list(range(9, 18)),
                               typical_resources=["/home"])
        ev = engine.record_event(ORG, USER, country="US",
                                 access_time="2024-01-10T03:00:00+00:00",
                                 resource="/home")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        types = [a["anomaly_type"] for a in anomalies]
        assert "unusual_time" in types

    def test_unusual_time_severity_low(self, engine):
        engine.upsert_baseline(ORG, USER,
                               typical_hours=list(range(9, 18)))
        ev = engine.record_event(ORG, USER, country="US",
                                 access_time="2024-01-10T03:00:00+00:00")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        time_anom = next((a for a in anomalies if a["anomaly_type"] == "unusual_time"), None)
        assert time_anom is not None
        assert time_anom["severity"] == "low"

    def test_unusual_resource_detected(self, engine):
        engine.upsert_baseline(ORG, USER,
                               typical_countries=["US"],
                               typical_hours=list(range(0, 24)),
                               typical_resources=["/home"])
        ev = engine.record_event(ORG, USER, country="US",
                                 access_time="2024-01-10T10:00:00+00:00",
                                 resource="/admin/secrets")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        types = [a["anomaly_type"] for a in anomalies]
        assert "unusual_resource" in types

    def test_risk_score_sum(self, engine):
        """Risk score = sum of severity weights: medium(2) + low(1) + low(1) = 4."""
        engine.upsert_baseline(ORG, USER,
                               typical_countries=["US"],
                               typical_hours=list(range(9, 18)),
                               typical_resources=["/home"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T03:00:00+00:00",
                                 resource="/admin")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        # Reload event to check updated risk_score
        ev_updated = engine._get_event(ev["id"], ORG)
        assert ev_updated["risk_score"] == pytest.approx(4.0)  # medium(2)+low(1)+low(1)

    def test_anomaly_flags_updated_on_event(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="CN",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER, ev["id"])
        ev_updated = engine._get_event(ev["id"], ORG)
        assert "unusual_country" in ev_updated["anomaly_flags"]

    def test_detect_anomalies_no_baseline(self, engine):
        ev = engine.record_event(ORG, USER, country="US")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        assert anomalies == []

    def test_detect_missing_event_raises(self, engine):
        with pytest.raises(ValueError):
            engine.detect_anomalies(ORG, USER, "nonexistent-id")

    def test_multiple_anomalies_created(self, engine):
        engine.upsert_baseline(ORG, USER,
                               typical_countries=["US"],
                               typical_hours=list(range(9, 18)),
                               typical_resources=["/home"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T03:00:00+00:00",
                                 resource="/secret")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        assert len(anomalies) == 3  # country + time + resource


# ---------------------------------------------------------------------------
# Impossible travel
# ---------------------------------------------------------------------------

class TestImpossibleTravel:
    def test_impossible_travel_detected(self, engine):
        now = _now()
        engine.record_event(ORG, USER, country="US",
                            access_time=_iso(now))
        engine.record_event(ORG, USER, country="RU",
                            access_time=_iso(now + timedelta(hours=1)))
        anomalies = engine.detect_impossible_travel(ORG, USER, hours_window=4.0)
        assert len(anomalies) >= 1
        assert all(a["anomaly_type"] == "impossible_travel" for a in anomalies)

    def test_impossible_travel_severity_critical(self, engine):
        now = _now()
        engine.record_event(ORG, USER, country="US", access_time=_iso(now))
        engine.record_event(ORG, USER, country="CN",
                            access_time=_iso(now + timedelta(hours=2)))
        anomalies = engine.detect_impossible_travel(ORG, USER, hours_window=6.0)
        assert anomalies[0]["severity"] == "critical"
        assert anomalies[0]["risk_score"] == 4.0

    def test_no_impossible_travel_same_country(self, engine):
        now = _now()
        engine.record_event(ORG, USER, country="US", access_time=_iso(now))
        engine.record_event(ORG, USER, country="US",
                            access_time=_iso(now + timedelta(hours=1)))
        anomalies = engine.detect_impossible_travel(ORG, USER, hours_window=4.0)
        assert len(anomalies) == 0

    def test_no_impossible_travel_outside_window(self, engine):
        now = _now()
        engine.record_event(ORG, USER, country="US", access_time=_iso(now))
        engine.record_event(ORG, USER, country="RU",
                            access_time=_iso(now + timedelta(hours=10)))
        anomalies = engine.detect_impossible_travel(ORG, USER, hours_window=4.0)
        assert len(anomalies) == 0

    def test_impossible_travel_org_isolated(self, engine):
        now = _now()
        engine.record_event(ORG, USER, country="US", access_time=_iso(now))
        engine.record_event(ORG, USER, country="CN",
                            access_time=_iso(now + timedelta(hours=1)))
        anomalies_other = engine.detect_impossible_travel(ORG2, USER, hours_window=4.0)
        assert len(anomalies_other) == 0


# ---------------------------------------------------------------------------
# Resolve anomaly
# ---------------------------------------------------------------------------

class TestResolveAnomaly:
    def test_resolve_sets_status(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        anom = anomalies[0]
        resolved = engine.resolve_anomaly(anom["id"], ORG)
        assert resolved["status"] == "resolved"
        assert resolved["resolved_at"] is not None

    def test_resolve_wrong_org(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        anomalies = engine.detect_anomalies(ORG, USER, ev["id"])
        with pytest.raises(ValueError):
            engine.resolve_anomaly(anomalies[0]["id"], ORG2)

    def test_resolve_nonexistent(self, engine):
        with pytest.raises(ValueError):
            engine.resolve_anomaly("no-such-id", ORG)


# ---------------------------------------------------------------------------
# List anomalies + filtering
# ---------------------------------------------------------------------------

class TestListAnomalies:
    def _seed_anomalies(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER, ev["id"])

    def test_list_all(self, engine):
        self._seed_anomalies(engine)
        anomalies = engine.list_anomalies(ORG)
        assert len(anomalies) >= 1

    def test_list_by_status(self, engine):
        self._seed_anomalies(engine)
        open_a = engine.list_anomalies(ORG, status="open")
        resolved_a = engine.list_anomalies(ORG, status="resolved")
        assert len(open_a) >= 1
        assert len(resolved_a) == 0

    def test_list_by_type(self, engine):
        self._seed_anomalies(engine)
        country_a = engine.list_anomalies(ORG, anomaly_type="unusual_country")
        assert all(a["anomaly_type"] == "unusual_country" for a in country_a)

    def test_list_by_username(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER, ev["id"])
        results = engine.list_anomalies(ORG, username=USER)
        assert all(a["username"] == USER for a in results)
        empty = engine.list_anomalies(ORG, username="nobody")
        assert empty == []


# ---------------------------------------------------------------------------
# High-risk users
# ---------------------------------------------------------------------------

class TestHighRiskUsers:
    def test_high_risk_threshold(self, engine):
        # Create 4 anomalies for USER by registering events from unusual countries
        for country in ["RU", "CN", "IR", "KP"]:
            engine.upsert_baseline(ORG, USER, typical_countries=["US"])
            ev = engine.record_event(ORG, USER, country=country,
                                     access_time="2024-01-10T10:00:00+00:00")
            engine.detect_anomalies(ORG, USER, ev["id"])
        high = engine.get_high_risk_users(ORG, min_anomaly_count=3)
        users = [r["username"] for r in high]
        assert USER in users

    def test_below_threshold_excluded(self, engine):
        engine.upsert_baseline(ORG, USER2, typical_countries=["US"])
        ev = engine.record_event(ORG, USER2, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER2, ev["id"])
        high = engine.get_high_risk_users(ORG, min_anomaly_count=5)
        users = [r["username"] for r in high]
        assert USER2 not in users

    def test_high_risk_ordered_by_count(self, engine):
        for i in range(5):
            engine.upsert_baseline(ORG, USER, typical_countries=["US"])
            ev = engine.record_event(ORG, USER, country=f"C{i}",
                                     access_time="2024-01-10T10:00:00+00:00")
            engine.detect_anomalies(ORG, USER, ev["id"])
        engine.upsert_baseline(ORG, USER2, typical_countries=["US"])
        ev2 = engine.record_event(ORG, USER2, country="RU",
                                  access_time="2024-01-10T10:00:00+00:00")
        ev2b = engine.record_event(ORG, USER2, country="CN",
                                   access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER2, ev2["id"])
        engine.detect_anomalies(ORG, USER2, ev2b["id"])
        high = engine.get_high_risk_users(ORG, min_anomaly_count=1)
        assert high[0]["anomaly_count"] >= high[-1]["anomaly_count"]


# ---------------------------------------------------------------------------
# User risk profile
# ---------------------------------------------------------------------------

class TestUserRiskProfile:
    def test_profile_empty_user(self, engine):
        profile = engine.get_user_risk_profile(ORG, "nobody")
        assert profile["baseline"] == {}
        assert profile["open_anomalies"] == []
        assert profile["recent_events"] == []
        assert profile["risk_score"] == 0.0

    def test_profile_with_baseline_and_events(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        engine.record_event(ORG, USER, country="US",
                            access_time="2024-01-10T10:00:00+00:00")
        profile = engine.get_user_risk_profile(ORG, USER)
        assert profile["baseline"]["username"] == USER
        assert len(profile["recent_events"]) == 1

    def test_profile_risk_score_avg(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER, ev["id"])
        profile = engine.get_user_risk_profile(ORG, USER)
        assert profile["risk_score"] > 0.0


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

class TestSummary:
    def test_empty_summary(self, engine):
        s = engine.get_summary(ORG)
        assert s["total_events"] == 0
        assert s["total_anomalies"] == 0
        assert s["open_anomalies"] == 0

    def test_summary_counts(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER, ev["id"])
        s = engine.get_summary(ORG)
        assert s["total_events"] == 1
        assert s["total_anomalies"] >= 1
        assert s["open_anomalies"] >= 1

    def test_summary_impossible_travel_count(self, engine):
        now = _now()
        engine.record_event(ORG, USER, country="US", access_time=_iso(now))
        engine.record_event(ORG, USER, country="CN",
                            access_time=_iso(now + timedelta(hours=1)))
        engine.detect_impossible_travel(ORG, USER, hours_window=4.0)
        s = engine.get_summary(ORG)
        assert s["impossible_travel_count"] >= 1

    def test_summary_high_risk_users(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER, ev["id"])
        s = engine.get_summary(ORG)
        assert s["high_risk_users"] >= 1

    def test_summary_org_isolated(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER, ev["id"])
        s2 = engine.get_summary(ORG2)
        assert s2["total_events"] == 0
        assert s2["total_anomalies"] == 0


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_events_isolated(self, engine):
        engine.record_event(ORG, USER, country="US")
        engine.record_event(ORG2, USER, country="US")
        s1 = engine.get_summary(ORG)
        s2 = engine.get_summary(ORG2)
        assert s1["total_events"] == 1
        assert s2["total_events"] == 1

    def test_anomalies_isolated(self, engine):
        engine.upsert_baseline(ORG, USER, typical_countries=["US"])
        ev = engine.record_event(ORG, USER, country="RU",
                                 access_time="2024-01-10T10:00:00+00:00")
        engine.detect_anomalies(ORG, USER, ev["id"])
        anomalies_other = engine.list_anomalies(ORG2)
        assert anomalies_other == []
