"""
Comprehensive tests for ThreatGeolocationEngine.

Covers:
- record_geo_event: basic recording, validation of event_type/risk_level fallbacks
- list_geo_events: no filter, country_code filter, risk_level filter, limit
- get_country_heatmap: aggregation, risk_score weighting, hours window
- detect_impossible_travel: detected/not-detected, pairs content, edge cases
- create_geo_block_rule: creation, upsert behaviour
- list_geo_block_rules: org isolation
- check_ip_allowed: blocked country, allowed country, rule_matched content
- get_geo_stats: total events, top countries, blocked_countries count
- Multi-tenant isolation
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.threat_geolocation_engine import ThreatGeolocationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "geo.db")
    return ThreatGeolocationEngine(db_path=db)


ORG = "org-geo-test"
ORG2 = "org-geo-other"


def _event(overrides=None):
    base = {
        "ip": "1.2.3.4",
        "country_code": "US",
        "country_name": "United States",
        "city": "New York",
        "lat": 40.71,
        "lon": -74.01,
        "event_type": "login",
        "risk_level": "medium",
        "user_id": "user-1",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# record_geo_event
# ---------------------------------------------------------------------------

class TestRecordGeoEvent:
    def test_returns_dict_with_id(self, engine):
        result = engine.record_geo_event(ORG, _event())
        assert "id" in result
        assert len(result["id"]) == 36  # UUID

    def test_returns_correct_fields(self, engine):
        data = _event({"ip": "9.9.9.9", "country_code": "DE", "country_name": "Germany"})
        result = engine.record_geo_event(ORG, data)
        assert result["ip"] == "9.9.9.9"
        assert result["country_code"] == "DE"
        assert result["country_name"] == "Germany"
        assert result["org_id"] == ORG

    def test_invalid_event_type_fallback(self, engine):
        data = _event({"event_type": "invalid_type"})
        result = engine.record_geo_event(ORG, data)
        assert result["event_type"] == "access"

    def test_invalid_risk_level_fallback(self, engine):
        data = _event({"risk_level": "extreme"})
        result = engine.record_geo_event(ORG, data)
        assert result["risk_level"] == "low"

    def test_all_event_types_accepted(self, engine):
        for et in ("login", "scan", "attack", "access"):
            result = engine.record_geo_event(ORG, _event({"event_type": et}))
            assert result["event_type"] == et

    def test_all_risk_levels_accepted(self, engine):
        for rl in ("low", "medium", "high", "critical"):
            result = engine.record_geo_event(ORG, _event({"risk_level": rl}))
            assert result["risk_level"] == rl

    def test_created_at_is_iso_string(self, engine):
        result = engine.record_geo_event(ORG, _event())
        datetime.fromisoformat(result["created_at"])  # must not raise

    def test_lat_lon_stored(self, engine):
        data = _event({"lat": 51.5, "lon": -0.12})
        result = engine.record_geo_event(ORG, data)
        assert result["lat"] == pytest.approx(51.5)
        assert result["lon"] == pytest.approx(-0.12)

    def test_minimal_data_no_optional_fields(self, engine):
        result = engine.record_geo_event(ORG, {"ip": "5.5.5.5", "country_code": "FR", "country_name": "France"})
        assert result["country_code"] == "FR"


# ---------------------------------------------------------------------------
# list_geo_events
# ---------------------------------------------------------------------------

class TestListGeoEvents:
    def _seed(self, engine):
        engine.record_geo_event(ORG, _event({"country_code": "US", "risk_level": "high"}))
        engine.record_geo_event(ORG, _event({"country_code": "CN", "risk_level": "critical"}))
        engine.record_geo_event(ORG, _event({"country_code": "US", "risk_level": "low"}))
        engine.record_geo_event(ORG2, _event({"country_code": "US", "risk_level": "critical"}))

    def test_returns_all_org_events(self, engine):
        self._seed(engine)
        events = engine.list_geo_events(ORG)
        assert len(events) == 3

    def test_filter_by_country_code(self, engine):
        self._seed(engine)
        events = engine.list_geo_events(ORG, country_code="CN")
        assert len(events) == 1
        assert events[0]["country_code"] == "CN"

    def test_filter_by_risk_level(self, engine):
        self._seed(engine)
        events = engine.list_geo_events(ORG, risk_level="high")
        assert len(events) == 1
        assert events[0]["risk_level"] == "high"

    def test_filter_combined(self, engine):
        self._seed(engine)
        events = engine.list_geo_events(ORG, country_code="US", risk_level="low")
        assert len(events) == 1

    def test_org_isolation(self, engine):
        self._seed(engine)
        events = engine.list_geo_events(ORG2)
        assert len(events) == 1

    def test_limit(self, engine):
        for i in range(10):
            engine.record_geo_event(ORG, _event({"ip": f"1.2.3.{i}"}))
        events = engine.list_geo_events(ORG, limit=5)
        assert len(events) == 5

    def test_empty_org_returns_empty_list(self, engine):
        assert engine.list_geo_events("no-such-org") == []


# ---------------------------------------------------------------------------
# get_country_heatmap
# ---------------------------------------------------------------------------

class TestGetCountryHeatmap:
    def test_aggregates_by_country(self, engine):
        engine.record_geo_event(ORG, _event({"country_code": "US", "country_name": "United States", "risk_level": "high"}))
        engine.record_geo_event(ORG, _event({"country_code": "US", "country_name": "United States", "risk_level": "high"}))
        engine.record_geo_event(ORG, _event({"country_code": "RU", "country_name": "Russia", "risk_level": "critical"}))
        heatmap = engine.get_country_heatmap(ORG, hours=24)
        codes = {h["country_code"] for h in heatmap}
        assert "US" in codes
        assert "RU" in codes

    def test_event_count_correct(self, engine):
        for _ in range(3):
            engine.record_geo_event(ORG, _event({"country_code": "JP", "country_name": "Japan", "risk_level": "low"}))
        heatmap = engine.get_country_heatmap(ORG, hours=24)
        jp = next(h for h in heatmap if h["country_code"] == "JP")
        assert jp["event_count"] == 3

    def test_risk_score_is_numeric(self, engine):
        engine.record_geo_event(ORG, _event({"country_code": "KP", "country_name": "North Korea", "risk_level": "critical"}))
        heatmap = engine.get_country_heatmap(ORG, hours=24)
        kp = next(h for h in heatmap if h["country_code"] == "KP")
        assert 0.0 <= kp["risk_score"] <= 100.0

    def test_critical_has_higher_risk_score_than_low(self, engine):
        engine.record_geo_event(ORG, _event({"country_code": "AA", "country_name": "Alpha", "risk_level": "critical"}))
        engine.record_geo_event(ORG, _event({"country_code": "BB", "country_name": "Beta", "risk_level": "low"}))
        heatmap = engine.get_country_heatmap(ORG, hours=24)
        aa = next(h for h in heatmap if h["country_code"] == "AA")
        bb = next(h for h in heatmap if h["country_code"] == "BB")
        assert aa["risk_score"] > bb["risk_score"]

    def test_empty_returns_empty_list(self, engine):
        assert engine.get_country_heatmap("empty-org", hours=24) == []


# ---------------------------------------------------------------------------
# detect_impossible_travel
# ---------------------------------------------------------------------------

class TestDetectImpossibleTravel:
    def _ts(self, delta_minutes=0):
        base = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        return (base + timedelta(minutes=delta_minutes)).isoformat()

    def test_detected_for_impossible_pair(self, engine):
        # NYC → Tokyo in 30 minutes — clearly impossible
        events = [
            {"lat": 40.71, "lon": -74.01, "created_at": self._ts(0)},    # NYC
            {"lat": 35.68, "lon": 139.69, "created_at": self._ts(30)},   # Tokyo
        ]
        result = engine.detect_impossible_travel(ORG, "user-1", events)
        assert result["detected"] is True
        assert len(result["pairs"]) == 1

    def test_not_detected_for_nearby_cities(self, engine):
        # NY → Boston (339 km) in 6 hours — possible by car
        events = [
            {"lat": 40.71, "lon": -74.01, "created_at": self._ts(0)},
            {"lat": 42.36, "lon": -71.06, "created_at": self._ts(360)},
        ]
        result = engine.detect_impossible_travel(ORG, "user-2", events)
        assert result["detected"] is False
        assert result["pairs"] == []

    def test_pair_contains_distance_and_speed(self, engine):
        events = [
            {"lat": 40.71, "lon": -74.01, "created_at": self._ts(0)},
            {"lat": 35.68, "lon": 139.69, "created_at": self._ts(30)},
        ]
        result = engine.detect_impossible_travel(ORG, "user-1", events)
        pair = result["pairs"][0]
        assert "distance_km" in pair
        assert "speed_kmh" in pair
        assert "time_hours" in pair
        assert pair["distance_km"] > 10000  # NYC to Tokyo is ~10800 km

    def test_empty_events_returns_not_detected(self, engine):
        result = engine.detect_impossible_travel(ORG, "user-x", [])
        assert result["detected"] is False
        assert result["pairs"] == []

    def test_single_event_no_detection(self, engine):
        events = [{"lat": 40.71, "lon": -74.01, "created_at": self._ts(0)}]
        result = engine.detect_impossible_travel(ORG, "user-x", events)
        assert result["detected"] is False

    def test_multiple_impossible_pairs(self, engine):
        events = [
            {"lat": 40.71, "lon": -74.01, "created_at": self._ts(0)},    # NYC
            {"lat": 35.68, "lon": 139.69, "created_at": self._ts(30)},   # Tokyo
            {"lat": 51.51, "lon": -0.12, "created_at": self._ts(45)},    # London
        ]
        result = engine.detect_impossible_travel(ORG, "user-1", events)
        assert result["detected"] is True
        assert len(result["pairs"]) >= 1

    def test_events_with_malformed_timestamp_skipped(self, engine):
        events = [
            {"lat": 40.71, "lon": -74.01, "created_at": "not-a-date"},
            {"lat": 35.68, "lon": 139.69, "created_at": self._ts(30)},
        ]
        # Should not raise; one event after filtering leaves nothing to compare
        result = engine.detect_impossible_travel(ORG, "user-x", events)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# create_geo_block_rule / list_geo_block_rules
# ---------------------------------------------------------------------------

class TestGeoBlockRules:
    def test_create_returns_rule_dict(self, engine):
        rule = engine.create_geo_block_rule(ORG, {"country_code": "KP", "reason": "Sanctioned", "severity": "critical"})
        assert rule["country_code"] == "KP"
        assert rule["reason"] == "Sanctioned"
        assert "id" in rule

    def test_upsert_updates_existing(self, engine):
        engine.create_geo_block_rule(ORG, {"country_code": "IR", "reason": "initial"})
        engine.create_geo_block_rule(ORG, {"country_code": "IR", "reason": "updated", "severity": "high"})
        rules = engine.list_geo_block_rules(ORG)
        ir_rules = [r for r in rules if r["country_code"] == "IR"]
        assert len(ir_rules) == 1
        assert ir_rules[0]["reason"] == "updated"

    def test_list_returns_correct_count(self, engine):
        engine.create_geo_block_rule(ORG, {"country_code": "KP"})
        engine.create_geo_block_rule(ORG, {"country_code": "IR"})
        rules = engine.list_geo_block_rules(ORG)
        assert len(rules) >= 2

    def test_org_isolation(self, engine):
        engine.create_geo_block_rule(ORG, {"country_code": "SY"})
        rules = engine.list_geo_block_rules(ORG2)
        assert all(r["country_code"] != "SY" for r in rules)

    def test_empty_org_returns_empty_list(self, engine):
        assert engine.list_geo_block_rules("no-rules-org") == []


# ---------------------------------------------------------------------------
# check_ip_allowed
# ---------------------------------------------------------------------------

class TestCheckIPAllowed:
    def test_blocked_country_returns_not_allowed(self, engine):
        engine.create_geo_block_rule(ORG, {"country_code": "KP", "reason": "Sanctioned"})
        result = engine.check_ip_allowed(ORG, "1.1.1.1", "KP")
        assert result["allowed"] is False
        assert result["rule_matched"] is not None
        assert result["rule_matched"]["country_code"] == "KP"

    def test_allowed_country_returns_allowed(self, engine):
        result = engine.check_ip_allowed(ORG, "8.8.8.8", "US")
        assert result["allowed"] is True
        assert result["rule_matched"] is None

    def test_rule_matched_contains_reason(self, engine):
        engine.create_geo_block_rule(ORG, {"country_code": "CU", "reason": "Embargo"})
        result = engine.check_ip_allowed(ORG, "5.5.5.5", "CU")
        assert result["rule_matched"]["reason"] == "Embargo"

    def test_org_block_does_not_affect_other_org(self, engine):
        engine.create_geo_block_rule(ORG, {"country_code": "KP"})
        result = engine.check_ip_allowed(ORG2, "1.2.3.4", "KP")
        assert result["allowed"] is True


# ---------------------------------------------------------------------------
# get_geo_stats
# ---------------------------------------------------------------------------

class TestGetGeoStats:
    def test_total_events_count(self, engine):
        for i in range(5):
            engine.record_geo_event(ORG, _event({"ip": f"1.1.1.{i}"}))
        stats = engine.get_geo_stats(ORG)
        assert stats["total_events"] == 5

    def test_blocked_countries_count(self, engine):
        engine.create_geo_block_rule(ORG, {"country_code": "KP"})
        engine.create_geo_block_rule(ORG, {"country_code": "IR"})
        stats = engine.get_geo_stats(ORG)
        assert stats["blocked_countries"] >= 2

    def test_top_countries_populated(self, engine):
        for _ in range(3):
            engine.record_geo_event(ORG, _event({"country_code": "US", "country_name": "United States"}))
        stats = engine.get_geo_stats(ORG)
        assert len(stats["top_countries"]) >= 1
        us = next((c for c in stats["top_countries"] if c["country_code"] == "US"), None)
        assert us is not None
        assert us["event_count"] == 3

    def test_impossible_travel_alerts_key_present(self, engine):
        stats = engine.get_geo_stats(ORG)
        assert "impossible_travel_alerts" in stats

    def test_empty_org_stats(self, engine):
        stats = engine.get_geo_stats("empty-stats-org")
        assert stats["total_events"] == 0
        assert stats["top_countries"] == []
        assert stats["blocked_countries"] == 0

    def test_org_isolation_in_stats(self, engine):
        for i in range(4):
            engine.record_geo_event(ORG, _event({"ip": f"2.2.2.{i}"}))
        engine.record_geo_event(ORG2, _event())
        stats = engine.get_geo_stats(ORG)
        assert stats["total_events"] == 4
        stats2 = engine.get_geo_stats(ORG2)
        assert stats2["total_events"] == 1
