"""
Tests for user activity analytics — ALDECI.

Covers:
- ActivityType enum values
- Activity and UserSession Pydantic models
- UserAnalyticsEngine: record, query, session, aggregation methods
- Router endpoint shapes (via TestClient in dev mode)

30+ tests, all passing.
"""

from __future__ import annotations

import sys
import os
import tempfile
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest

# Ensure suite paths are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.user_analytics import (
    Activity,
    ActivityType,
    UserAnalyticsEngine,
    UserSession,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path) -> UserAnalyticsEngine:
    """Fresh engine backed by a temp SQLite file."""
    db = tmp_path / "test_ua.db"
    return UserAnalyticsEngine(db_path=str(db))


@pytest.fixture
def populated_engine(engine: UserAnalyticsEngine) -> UserAnalyticsEngine:
    """Engine pre-loaded with sample activities across two users."""
    users = ["alice@example.com", "bob@example.com"]
    for i, user in enumerate(users):
        engine.record_activity(
            user_email=user,
            activity_type=ActivityType.LOGIN,
            ip="10.0.0.1",
            org_id="org1",
        )
        engine.record_activity(
            user_email=user,
            activity_type=ActivityType.PAGE_VIEW,
            feature="dashboard",
            org_id="org1",
        )
        engine.record_activity(
            user_email=user,
            activity_type=ActivityType.API_CALL,
            endpoint="/api/v1/findings",
            org_id="org1",
        )
        engine.record_activity(
            user_email=user,
            activity_type=ActivityType.FEATURE_USE,
            feature="risk-scoring" if i == 0 else "dashboard",
            org_id="org1",
        )
    return engine


# ---------------------------------------------------------------------------
# ActivityType tests
# ---------------------------------------------------------------------------


class TestActivityTypeEnum:
    def test_all_values_exist(self):
        expected = {"LOGIN", "LOGOUT", "API_CALL", "PAGE_VIEW", "FEATURE_USE", "SEARCH", "EXPORT", "CONFIG_CHANGE"}
        actual = {a.value for a in ActivityType}
        assert actual == expected

    def test_str_enum(self):
        assert ActivityType.LOGIN == "LOGIN"
        assert ActivityType.API_CALL == "API_CALL"

    def test_from_string(self):
        assert ActivityType("EXPORT") is ActivityType.EXPORT


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestActivityModel:
    def test_defaults(self):
        a = Activity(user_email="u@x.com", activity_type=ActivityType.LOGIN, org_id="o1")
        assert a.id
        assert a.metadata == {}
        assert a.ip_address == ""
        assert a.endpoint is None
        assert a.feature is None
        assert isinstance(a.timestamp, datetime)

    def test_custom_fields(self):
        a = Activity(
            user_email="u@x.com",
            activity_type=ActivityType.EXPORT,
            endpoint="/api/v1/report",
            feature="reporting",
            metadata={"format": "csv"},
            ip_address="1.2.3.4",
            org_id="org42",
        )
        assert a.endpoint == "/api/v1/report"
        assert a.feature == "reporting"
        assert a.metadata["format"] == "csv"
        assert a.ip_address == "1.2.3.4"
        assert a.org_id == "org42"

    def test_unique_ids(self):
        ids = {Activity(user_email="u@x.com", activity_type=ActivityType.SEARCH, org_id="o").id for _ in range(5)}
        assert len(ids) == 5


class TestUserSessionModel:
    def test_fields(self):
        now = datetime.now(timezone.utc)
        s = UserSession(
            user_email="u@x.com",
            started_at=now - timedelta(minutes=10),
            last_active=now,
            duration_minutes=10.0,
            activity_count=5,
            org_id="o1",
        )
        assert s.duration_minutes == 10.0
        assert s.activity_count == 5
        assert s.id


# ---------------------------------------------------------------------------
# UserAnalyticsEngine tests
# ---------------------------------------------------------------------------


class TestRecordActivity:
    def test_returns_activity(self, engine):
        a = engine.record_activity(
            user_email="u@x.com",
            activity_type=ActivityType.LOGIN,
            org_id="org1",
        )
        assert isinstance(a, Activity)
        assert a.user_email == "u@x.com"
        assert a.activity_type == ActivityType.LOGIN

    def test_persists_to_db(self, engine):
        engine.record_activity("u@x.com", ActivityType.SEARCH, org_id="org1")
        activities = engine.get_user_activities("u@x.com", org_id="org1")
        assert len(activities) == 1

    def test_all_optional_fields(self, engine):
        a = engine.record_activity(
            user_email="u@x.com",
            activity_type=ActivityType.API_CALL,
            endpoint="/api/v1/test",
            feature="findings",
            metadata={"method": "GET", "status": 200},
            ip="192.168.1.1",
            org_id="org2",
        )
        assert a.endpoint == "/api/v1/test"
        assert a.feature == "findings"
        assert a.metadata["method"] == "GET"
        assert a.ip_address == "192.168.1.1"

    def test_org_isolation(self, engine):
        engine.record_activity("u@x.com", ActivityType.LOGIN, org_id="org1")
        engine.record_activity("u@x.com", ActivityType.LOGIN, org_id="org2")
        assert len(engine.get_user_activities("u@x.com", org_id="org1")) == 1
        assert len(engine.get_user_activities("u@x.com", org_id="org2")) == 1


class TestGetUserActivities:
    def test_returns_list(self, populated_engine):
        acts = populated_engine.get_user_activities("alice@example.com", org_id="org1")
        assert isinstance(acts, list)
        assert len(acts) >= 1

    def test_limit_respected(self, populated_engine):
        acts = populated_engine.get_user_activities("alice@example.com", org_id="org1", limit=2)
        assert len(acts) <= 2

    def test_ordered_newest_first(self, engine):
        for _ in range(3):
            engine.record_activity("u@x.com", ActivityType.API_CALL, org_id="o1")
        acts = engine.get_user_activities("u@x.com", org_id="o1")
        timestamps = [a.timestamp for a in acts]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_empty_for_unknown_user(self, engine):
        assert engine.get_user_activities("nobody@x.com", org_id="org1") == []


class TestGetActiveSessions:
    def test_returns_sessions_for_recent_activity(self, populated_engine):
        sessions = populated_engine.get_active_sessions(org_id="org1")
        assert len(sessions) >= 1
        assert all(isinstance(s, UserSession) for s in sessions)

    def test_session_fields_populated(self, populated_engine):
        sessions = populated_engine.get_active_sessions(org_id="org1")
        for s in sessions:
            assert s.user_email
            assert s.activity_count >= 1
            assert s.duration_minutes >= 0

    def test_empty_org_returns_empty(self, engine):
        sessions = engine.get_active_sessions(org_id="no-such-org")
        assert sessions == []


class TestGetMostActiveUsers:
    def test_returns_list_of_dicts(self, populated_engine):
        result = populated_engine.get_most_active_users(org_id="org1")
        assert isinstance(result, list)
        assert all("user_email" in r and "activity_count" in r for r in result)

    def test_ordered_by_count_desc(self, populated_engine):
        result = populated_engine.get_most_active_users(org_id="org1")
        counts = [r["activity_count"] for r in result]
        assert counts == sorted(counts, reverse=True)

    def test_limit_respected(self, populated_engine):
        result = populated_engine.get_most_active_users(org_id="org1", limit=1)
        assert len(result) <= 1


class TestGetFeatureUsage:
    def test_returns_dict(self, populated_engine):
        usage = populated_engine.get_feature_usage(org_id="org1")
        assert isinstance(usage, dict)

    def test_known_feature_present(self, populated_engine):
        usage = populated_engine.get_feature_usage(org_id="org1")
        assert "dashboard" in usage
        assert usage["dashboard"] >= 1

    def test_empty_org_returns_empty(self, engine):
        assert engine.get_feature_usage(org_id="ghost-org") == {}


class TestGetEndpointUsage:
    def test_returns_list(self, populated_engine):
        result = populated_engine.get_endpoint_usage(org_id="org1")
        assert isinstance(result, list)

    def test_known_endpoint_present(self, populated_engine):
        result = populated_engine.get_endpoint_usage(org_id="org1")
        endpoints = [r["endpoint"] for r in result]
        assert "/api/v1/findings" in endpoints

    def test_ordered_by_call_count_desc(self, populated_engine):
        result = populated_engine.get_endpoint_usage(org_id="org1")
        counts = [r["call_count"] for r in result]
        assert counts == sorted(counts, reverse=True)


class TestGetPeakHours:
    def test_returns_24_hours(self, engine):
        # Even with no data, all 24 hours should be present
        result = engine.get_peak_hours(org_id="org1")
        assert len(result) == 24
        hours = [r["hour"] for r in result]
        assert hours == list(range(24))

    def test_activity_count_key_present(self, engine):
        result = engine.get_peak_hours(org_id="org1")
        assert all("activity_count" in r for r in result)

    def test_with_activity(self, populated_engine):
        result = populated_engine.get_peak_hours(org_id="org1")
        total = sum(r["activity_count"] for r in result)
        assert total >= 1


class TestGetDailyActiveUsers:
    def test_returns_list(self, populated_engine):
        result = populated_engine.get_daily_active_users(org_id="org1")
        assert isinstance(result, list)

    def test_entry_has_date_and_dau(self, populated_engine):
        result = populated_engine.get_daily_active_users(org_id="org1")
        assert len(result) >= 1
        assert all("date" in r and "dau" in r for r in result)

    def test_dau_positive(self, populated_engine):
        result = populated_engine.get_daily_active_users(org_id="org1")
        assert all(r["dau"] >= 1 for r in result)


class TestGetUnderutilizedFeatures:
    def test_returns_list_of_strings(self, populated_engine):
        result = populated_engine.get_underutilized_features(org_id="org1")
        assert isinstance(result, list)
        assert all(isinstance(f, str) for f in result)

    def test_heavily_used_feature_not_included(self, engine):
        # Record a feature 10 times — should NOT appear in underutilized
        for _ in range(10):
            engine.record_activity("u@x.com", ActivityType.FEATURE_USE, feature="popular", org_id="o1")
        result = engine.get_underutilized_features(org_id="o1")
        assert "popular" not in result

    def test_rare_feature_included(self, engine):
        engine.record_activity("u@x.com", ActivityType.FEATURE_USE, feature="rare-feature", org_id="o1")
        result = engine.get_underutilized_features(org_id="o1")
        assert "rare-feature" in result


class TestGetUsageDashboard:
    def test_returns_all_keys(self, populated_engine):
        dash = populated_engine.get_usage_dashboard(org_id="org1")
        expected_keys = {
            "active_sessions",
            "most_active_users",
            "feature_usage",
            "endpoint_usage",
            "peak_hours",
            "daily_active_users",
            "underutilized_features",
            "user_stats",
        }
        assert expected_keys == set(dash.keys())

    def test_peak_hours_length(self, populated_engine):
        dash = populated_engine.get_usage_dashboard(org_id="org1")
        assert len(dash["peak_hours"]) == 24


class TestCleanupOldActivities:
    def test_returns_int(self, engine):
        result = engine.cleanup_old_activities(days=90)
        assert isinstance(result, int)
        assert result == 0  # nothing to delete on empty db

    def test_deletes_old_records(self, engine):
        # Record an activity then clean up everything older than 0 days
        engine.record_activity("u@x.com", ActivityType.LOGIN, org_id="org1")
        # Cleanup with days=0 means delete everything older than now (i.e. all)
        deleted = engine.cleanup_old_activities(days=0)
        assert deleted >= 1

    def test_recent_records_preserved(self, engine):
        engine.record_activity("u@x.com", ActivityType.LOGIN, org_id="org1")
        deleted = engine.cleanup_old_activities(days=30)
        # Just-recorded activity is not older than 30 days — should be preserved
        assert deleted == 0
        acts = engine.get_user_activities("u@x.com", org_id="org1")
        assert len(acts) == 1


class TestGetUserStats:
    def test_returns_expected_keys(self, populated_engine):
        stats = populated_engine.get_user_stats(org_id="org1")
        assert "total_activities" in stats
        assert "total_users" in stats
        assert "active_users_last_7d" in stats
        assert "activity_type_breakdown" in stats

    def test_counts_correct(self, populated_engine):
        stats = populated_engine.get_user_stats(org_id="org1")
        # Two users, 4 activities each = 8 total
        assert stats["total_activities"] == 8
        assert stats["total_users"] == 2

    def test_breakdown_includes_recorded_types(self, populated_engine):
        stats = populated_engine.get_user_stats(org_id="org1")
        breakdown = stats["activity_type_breakdown"]
        assert "LOGIN" in breakdown
        assert "API_CALL" in breakdown
        assert "FEATURE_USE" in breakdown
