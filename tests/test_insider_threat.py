"""
Tests for InsiderThreatDetector engine and insider_threat_router.

Covers:
- InsiderThreatDetector: record_activity, assess_user_risk, detect_anomalies,
  get_high_risk_users, get_user_timeline, get_risk_distribution,
  acknowledge_alert, get_detection_stats
- insider_threat_router: all 8 endpoints via FastAPI TestClient

30+ tests total.

Compliance: SOC2 CC6.3, NIST SP 800-53 AU-6
"""

from __future__ import annotations

import sys
import os
import json
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest

# Ensure suite-core and suite-api are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.insider_threat import (
    ActivityRecord,
    AlertLevel,
    DetectionStats,
    InsiderThreatDetector,
    RiskDistribution,
    ThreatIndicator,
    UserRiskProfile,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path) -> str:
    """Return a path to a fresh temporary SQLite database."""
    return str(tmp_path / "test_insider_threat.db")


@pytest.fixture
def detector(tmp_db: str) -> InsiderThreatDetector:
    """InsiderThreatDetector backed by a temp SQLite database."""
    return InsiderThreatDetector(db_path=tmp_db, org_id="test-org")


def _record(det: InsiderThreatDetector, user: str, atype: str, **kwargs) -> str:
    """Helper: record a single activity for user."""
    return det.record_activity(user_email=user, activity_type=atype, org_id="test-org", **kwargs)


# ============================================================================
# ENUM & MODEL TESTS
# ============================================================================


class TestEnumsAndModels:
    """Verify enum values and Pydantic model construction."""

    def test_threat_indicator_values(self) -> None:
        assert ThreatIndicator.UNUSUAL_ACCESS == "UNUSUAL_ACCESS"
        assert ThreatIndicator.DATA_HOARDING == "DATA_HOARDING"
        assert ThreatIndicator.OFF_HOURS_ACTIVITY == "OFF_HOURS_ACTIVITY"
        assert ThreatIndicator.PRIVILEGE_ABUSE == "PRIVILEGE_ABUSE"
        assert ThreatIndicator.RESIGNATION_RISK == "RESIGNATION_RISK"
        assert ThreatIndicator.POLICY_VIOLATION == "POLICY_VIOLATION"
        assert ThreatIndicator.ANOMALOUS_DOWNLOAD == "ANOMALOUS_DOWNLOAD"
        assert ThreatIndicator.UNAUTHORIZED_TOOL == "UNAUTHORIZED_TOOL"

    def test_alert_level_values(self) -> None:
        assert AlertLevel.LOW == "low"
        assert AlertLevel.MEDIUM == "medium"
        assert AlertLevel.HIGH == "high"
        assert AlertLevel.CRITICAL == "critical"

    def test_user_risk_profile_model(self) -> None:
        profile = UserRiskProfile(
            user_email="alice@example.com",
            risk_score=45.0,
            indicators=[ThreatIndicator.PRIVILEGE_ABUSE],
            alert_level=AlertLevel.MEDIUM,
            org_id="org-1",
        )
        assert profile.user_email == "alice@example.com"
        assert profile.risk_score == 45.0
        assert profile.alert_level == AlertLevel.MEDIUM

    def test_user_risk_profile_score_bounds(self) -> None:
        """risk_score must be in 0-100."""
        with pytest.raises(Exception):
            UserRiskProfile(
                user_email="x@x.com",
                risk_score=101,
                indicators=[],
                alert_level=AlertLevel.LOW,
                org_id="org-1",
            )


# ============================================================================
# RECORD_ACTIVITY TESTS
# ============================================================================


class TestRecordActivity:
    """Tests for InsiderThreatDetector.record_activity."""

    def test_record_returns_uuid(self, detector: InsiderThreatDetector) -> None:
        aid = _record(detector, "bob@example.com", "data_download")
        assert isinstance(aid, str)
        assert len(aid) == 36  # UUID4

    def test_record_multiple_activities(self, detector: InsiderThreatDetector) -> None:
        ids = [_record(detector, "carol@example.com", "data_download") for _ in range(3)]
        assert len(set(ids)) == 3  # all unique

    def test_record_with_details(self, detector: InsiderThreatDetector) -> None:
        aid = detector.record_activity(
            user_email="dave@example.com",
            activity_type="data_download",
            details={"bytes_transferred": 200 * 1024 * 1024, "resource": "s3://secret"},
            org_id="test-org",
        )
        assert aid is not None
        timeline = detector.get_user_timeline("dave@example.com", org_id="test-org")
        assert timeline[0].details["bytes_transferred"] == 200 * 1024 * 1024

    def test_record_defaults_org(self, tmp_db: str) -> None:
        det = InsiderThreatDetector(db_path=tmp_db, org_id="my-org")
        aid = det.record_activity(user_email="eve@example.com", activity_type="sudo")
        timeline = det.get_user_timeline("eve@example.com", org_id="my-org")
        assert len(timeline) == 1


# ============================================================================
# ASSESS_USER_RISK TESTS
# ============================================================================


class TestAssessUserRisk:
    """Tests for InsiderThreatDetector.assess_user_risk."""

    def test_no_activities_gives_zero_score(self, detector: InsiderThreatDetector) -> None:
        profile = detector.assess_user_risk("nobody@example.com", org_id="test-org")
        assert profile.risk_score == 0.0
        assert profile.indicators == []
        assert profile.alert_level == AlertLevel.LOW

    def test_privilege_abuse_detected(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "frank@example.com", "privilege_escalation")
        profile = detector.assess_user_risk("frank@example.com", org_id="test-org")
        assert ThreatIndicator.PRIVILEGE_ABUSE in profile.indicators
        assert profile.risk_score >= 25

    def test_policy_violation_detected(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "grace@example.com", "policy_violation")
        profile = detector.assess_user_risk("grace@example.com", org_id="test-org")
        assert ThreatIndicator.POLICY_VIOLATION in profile.indicators

    def test_unauthorized_tool_detected(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "heidi@example.com", "unauthorized_tool")
        profile = detector.assess_user_risk("heidi@example.com", org_id="test-org")
        assert ThreatIndicator.UNAUTHORIZED_TOOL in profile.indicators

    def test_data_hoarding_detected(self, detector: InsiderThreatDetector) -> None:
        for _ in range(5):
            _record(detector, "ivan@example.com", "data_download")
        profile = detector.assess_user_risk("ivan@example.com", org_id="test-org")
        assert ThreatIndicator.DATA_HOARDING in profile.indicators

    def test_anomalous_download_large_file(self, detector: InsiderThreatDetector) -> None:
        detector.record_activity(
            user_email="judy@example.com",
            activity_type="data_download",
            details={"bytes_transferred": 200 * 1024 * 1024},
            org_id="test-org",
        )
        profile = detector.assess_user_risk("judy@example.com", org_id="test-org")
        assert ThreatIndicator.ANOMALOUS_DOWNLOAD in profile.indicators

    def test_unusual_access_three_denials(self, detector: InsiderThreatDetector) -> None:
        for _ in range(3):
            _record(detector, "kyle@example.com", "access_denied")
        profile = detector.assess_user_risk("kyle@example.com", org_id="test-org")
        assert ThreatIndicator.UNUSUAL_ACCESS in profile.indicators

    def test_resignation_indicator_direct(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "lena@example.com", "resignation_indicator")
        profile = detector.assess_user_risk("lena@example.com", org_id="test-org")
        assert ThreatIndicator.RESIGNATION_RISK in profile.indicators

    def test_critical_alert_level_multiple_indicators(self, detector: InsiderThreatDetector) -> None:
        # privilege_abuse (25) + data_hoarding (20) + policy_violation (20) = 65 -> HIGH
        _record(detector, "max@example.com", "privilege_escalation")
        for _ in range(5):
            _record(detector, "max@example.com", "data_download")
        _record(detector, "max@example.com", "policy_violation")
        profile = detector.assess_user_risk("max@example.com", org_id="test-org")
        assert profile.risk_score >= 60
        assert profile.alert_level in (AlertLevel.HIGH, AlertLevel.CRITICAL)

    def test_assess_persists_profile(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "nina@example.com", "privilege_escalation")
        detector.assess_user_risk("nina@example.com", org_id="test-org")
        # Should appear in high-risk list if score >= 25
        highrisk = detector.get_high_risk_users(org_id="test-org", threshold=25)
        emails = [p.user_email for p in highrisk]
        assert "nina@example.com" in emails


# ============================================================================
# DETECT_ANOMALIES TESTS
# ============================================================================


class TestDetectAnomalies:
    """Tests for InsiderThreatDetector.detect_anomalies."""

    def test_empty_org_returns_empty(self, detector: InsiderThreatDetector) -> None:
        result = detector.detect_anomalies(org_id="test-org")
        assert result == []

    def test_detects_suspicious_user(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "oscar@example.com", "privilege_escalation")
        result = detector.detect_anomalies(org_id="test-org")
        emails = [p.user_email for p in result]
        assert "oscar@example.com" in emails

    def test_clean_user_not_in_results(self, detector: InsiderThreatDetector) -> None:
        # Record a harmless activity type not matching any heuristic
        _record(detector, "pat@example.com", "login_success")
        result = detector.detect_anomalies(org_id="test-org")
        emails = [p.user_email for p in result]
        assert "pat@example.com" not in emails

    def test_multiple_users_scanned(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "quinn@example.com", "privilege_escalation")
        _record(detector, "rose@example.com", "unauthorized_tool")
        result = detector.detect_anomalies(org_id="test-org")
        emails = [p.user_email for p in result]
        assert "quinn@example.com" in emails
        assert "rose@example.com" in emails


# ============================================================================
# GET_HIGH_RISK_USERS TESTS
# ============================================================================


class TestGetHighRiskUsers:
    """Tests for InsiderThreatDetector.get_high_risk_users."""

    def test_empty_when_no_profiles(self, detector: InsiderThreatDetector) -> None:
        result = detector.get_high_risk_users(org_id="test-org")
        assert result == []

    def test_returns_only_above_threshold(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "sam@example.com", "privilege_escalation")
        _record(detector, "tara@example.com", "login_success")  # no indicators
        detector.assess_user_risk("sam@example.com", org_id="test-org")
        detector.assess_user_risk("tara@example.com", org_id="test-org")
        result = detector.get_high_risk_users(org_id="test-org", threshold=20)
        emails = [p.user_email for p in result]
        assert "sam@example.com" in emails
        assert "tara@example.com" not in emails

    def test_sorted_by_score_descending(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "uma@example.com", "privilege_escalation")
        for _ in range(5):
            _record(detector, "vic@example.com", "data_download")
        _record(detector, "vic@example.com", "privilege_escalation")
        detector.assess_user_risk("uma@example.com", org_id="test-org")
        detector.assess_user_risk("vic@example.com", org_id="test-org")
        result = detector.get_high_risk_users(org_id="test-org", threshold=0)
        scores = [p.risk_score for p in result]
        assert scores == sorted(scores, reverse=True)


# ============================================================================
# GET_USER_TIMELINE TESTS
# ============================================================================


class TestGetUserTimeline:
    """Tests for InsiderThreatDetector.get_user_timeline."""

    def test_empty_timeline(self, detector: InsiderThreatDetector) -> None:
        result = detector.get_user_timeline("nobody@example.com", org_id="test-org")
        assert result == []

    def test_timeline_returns_all_activities(self, detector: InsiderThreatDetector) -> None:
        for i in range(4):
            _record(detector, "wendy@example.com", f"action_{i}")
        result = detector.get_user_timeline("wendy@example.com", org_id="test-org")
        assert len(result) == 4

    def test_timeline_limit(self, detector: InsiderThreatDetector) -> None:
        for _ in range(10):
            _record(detector, "xander@example.com", "data_download")
        result = detector.get_user_timeline("xander@example.com", org_id="test-org", limit=3)
        assert len(result) == 3

    def test_timeline_type(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "yara@example.com", "sudo")
        result = detector.get_user_timeline("yara@example.com", org_id="test-org")
        assert isinstance(result[0], ActivityRecord)
        assert result[0].activity_type == "sudo"


# ============================================================================
# GET_RISK_DISTRIBUTION TESTS
# ============================================================================


class TestGetRiskDistribution:
    """Tests for InsiderThreatDetector.get_risk_distribution."""

    def test_empty_distribution(self, detector: InsiderThreatDetector) -> None:
        dist = detector.get_risk_distribution(org_id="test-org")
        assert isinstance(dist, RiskDistribution)
        assert dist.total == 0

    def test_distribution_counts(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "zara@example.com", "privilege_escalation")
        detector.assess_user_risk("zara@example.com", org_id="test-org")
        dist = detector.get_risk_distribution(org_id="test-org")
        assert dist.total >= 1
        assert dist.low + dist.medium + dist.high + dist.critical == dist.total


# ============================================================================
# ACKNOWLEDGE_ALERT TESTS
# ============================================================================


class TestAcknowledgeAlert:
    """Tests for InsiderThreatDetector.acknowledge_alert."""

    def test_acknowledge_returns_true(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "alice@example.com", "sudo")
        result = detector.acknowledge_alert(
            user_email="alice@example.com",
            reviewer="security@example.com",
            org_id="test-org",
        )
        assert result is True

    def test_acknowledge_no_records_returns_false(self, detector: InsiderThreatDetector) -> None:
        result = detector.acknowledge_alert(
            user_email="ghost@example.com",
            reviewer="security@example.com",
            org_id="test-org",
        )
        assert result is False

    def test_acknowledge_sets_acknowledged_flag(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "bob@example.com", "policy_violation")
        detector.acknowledge_alert(
            user_email="bob@example.com",
            reviewer="reviewer@example.com",
            org_id="test-org",
        )
        timeline = detector.get_user_timeline("bob@example.com", org_id="test-org")
        assert all(r.acknowledged for r in timeline)

    def test_acknowledge_sets_reviewer(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "carol@example.com", "unauthorized_tool")
        detector.acknowledge_alert(
            user_email="carol@example.com",
            reviewer="ciso@example.com",
            org_id="test-org",
        )
        timeline = detector.get_user_timeline("carol@example.com", org_id="test-org")
        assert timeline[0].acknowledged_by == "ciso@example.com"

    def test_double_acknowledge_returns_false(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "dave@example.com", "sudo")
        detector.acknowledge_alert("dave@example.com", "sec@example.com", org_id="test-org")
        second = detector.acknowledge_alert("dave@example.com", "sec@example.com", org_id="test-org")
        assert second is False


# ============================================================================
# GET_DETECTION_STATS TESTS
# ============================================================================


class TestGetDetectionStats:
    """Tests for InsiderThreatDetector.get_detection_stats."""

    def test_empty_stats(self, detector: InsiderThreatDetector) -> None:
        stats = detector.get_detection_stats(org_id="test-org")
        assert isinstance(stats, DetectionStats)
        assert stats.total_activities == 0
        assert stats.total_alerts == 0

    def test_stats_counts_activities(self, detector: InsiderThreatDetector) -> None:
        for _ in range(3):
            _record(detector, "eve@example.com", "data_download")
        stats = detector.get_detection_stats(org_id="test-org")
        assert stats.total_activities == 3

    def test_stats_reflects_high_risk_users(self, detector: InsiderThreatDetector) -> None:
        # privilege_abuse(25) + data_hoarding(20) + policy_violation(20) = 65 → HIGH
        _record(detector, "frank@example.com", "privilege_escalation")
        _record(detector, "frank@example.com", "policy_violation")
        for _ in range(5):
            _record(detector, "frank@example.com", "data_download")
        detector.assess_user_risk("frank@example.com", org_id="test-org")
        stats = detector.get_detection_stats(org_id="test-org")
        assert stats.total_alerts >= 1

    def test_stats_reviewed_alerts(self, detector: InsiderThreatDetector) -> None:
        # privilege_abuse(25) + data_hoarding(20) + policy_violation(20) = 65 → HIGH
        _record(detector, "grace@example.com", "privilege_escalation")
        _record(detector, "grace@example.com", "policy_violation")
        for _ in range(5):
            _record(detector, "grace@example.com", "data_download")
        detector.assess_user_risk("grace@example.com", org_id="test-org")
        detector.acknowledge_alert("grace@example.com", "sec@example.com", org_id="test-org")
        stats = detector.get_detection_stats(org_id="test-org")
        assert stats.reviewed_alerts >= 1

    def test_stats_pending_alerts(self, detector: InsiderThreatDetector) -> None:
        _record(detector, "heidi@example.com", "privilege_escalation")
        detector.assess_user_risk("heidi@example.com", org_id="test-org")
        stats = detector.get_detection_stats(org_id="test-org")
        assert stats.pending_alerts >= 0  # pending = total - reviewed


# ============================================================================
# ROUTER TESTS (FastAPI TestClient)
# ============================================================================


@pytest.fixture
def client(tmp_db: str):
    """FastAPI TestClient using the real router with auth dependency overridden."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import apps.api.insider_threat_router as itr

    # Inject a fresh isolated detector for this test
    fresh = InsiderThreatDetector(db_path=tmp_db, org_id="default")
    itr._detector = fresh

    app = FastAPI()
    app.include_router(itr.router)

    # Override auth dependency with a no-op so tests don't need API keys
    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app)


class TestInsiderThreatRouter:
    """Tests for all 8 insider_threat_router endpoints."""

    def test_record_activity_endpoint(self, client) -> None:
        resp = client.post(
            "/api/v1/insider-threat/activities",
            json={
                "user_email": "router@example.com",
                "activity_type": "data_download",
                "details": {},
                "org_id": "default",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "activity_id" in data
        assert data["message"] == "Activity recorded"

    def test_assess_user_risk_endpoint(self, client) -> None:
        # Record first so there's data
        client.post(
            "/api/v1/insider-threat/activities",
            json={"user_email": "assess@example.com", "activity_type": "sudo", "org_id": "default"},
        )
        resp = client.post(
            "/api/v1/insider-threat/assess/assess@example.com",
            params={"org_id": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_email"] == "assess@example.com"
        assert "risk_score" in data
        assert "alert_level" in data

    def test_detect_endpoint(self, client) -> None:
        client.post(
            "/api/v1/insider-threat/activities",
            json={"user_email": "detect@example.com", "activity_type": "privilege_escalation", "org_id": "default"},
        )
        resp = client.post(
            "/api/v1/insider-threat/detect",
            json={"org_id": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "users_flagged" in data
        assert "profiles" in data

    def test_high_risk_endpoint(self, client) -> None:
        resp = client.get("/api/v1/insider-threat/high-risk", params={"org_id": "default"})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_timeline_endpoint(self, client) -> None:
        client.post(
            "/api/v1/insider-threat/activities",
            json={"user_email": "tl@example.com", "activity_type": "login", "org_id": "default"},
        )
        resp = client.get(
            "/api/v1/insider-threat/timeline/tl@example.com",
            params={"org_id": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_distribution_endpoint(self, client) -> None:
        resp = client.get("/api/v1/insider-threat/distribution", params={"org_id": "default"})
        assert resp.status_code == 200
        data = resp.json()
        assert "low" in data
        assert "medium" in data
        assert "high" in data
        assert "critical" in data
        assert "total" in data

    def test_acknowledge_endpoint(self, client) -> None:
        client.post(
            "/api/v1/insider-threat/activities",
            json={"user_email": "ack@example.com", "activity_type": "sudo", "org_id": "default"},
        )
        resp = client.post(
            "/api/v1/insider-threat/acknowledge/ack@example.com",
            json={"reviewer": "ciso@example.com", "org_id": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["acknowledged"] is True
        assert data["user_email"] == "ack@example.com"

    def test_acknowledge_404_no_alerts(self, client) -> None:
        resp = client.post(
            "/api/v1/insider-threat/acknowledge/ghost@example.com",
            json={"reviewer": "sec@example.com", "org_id": "default"},
        )
        assert resp.status_code == 404

    def test_stats_endpoint(self, client) -> None:
        resp = client.get("/api/v1/insider-threat/stats", params={"org_id": "default"})
        assert resp.status_code == 200
        data = resp.json()
        assert "total_activities" in data
        assert "total_alerts" in data
        assert "reviewed_alerts" in data
        assert "pending_alerts" in data

    def test_timeline_limit_param(self, client) -> None:
        for _ in range(5):
            client.post(
                "/api/v1/insider-threat/activities",
                json={"user_email": "limit@example.com", "activity_type": "login", "org_id": "default"},
            )
        resp = client.get(
            "/api/v1/insider-threat/timeline/limit@example.com",
            params={"org_id": "default", "limit": 2},
        )
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_high_risk_threshold_param(self, client) -> None:
        resp = client.get(
            "/api/v1/insider-threat/high-risk",
            params={"org_id": "default", "threshold": 0},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
