"""
Tests for suite-core/core/session_manager.py and suite-api/apps/api/session_router.py.

Coverage:
- Session model fields and defaults
- SessionManager.create_session
- SessionManager.validate_session (valid, expired, terminated, missing)
- SessionManager.refresh_session (with and without new TTL)
- SessionManager.terminate_session
- SessionManager.terminate_all_sessions
- SessionManager.get_active_sessions
- SessionManager.cleanup_expired
- SessionManager.get_session_stats
- SessionManager.detect_concurrent_sessions
- SessionManager.get_suspicious_sessions
- Router endpoints (all 8+)

Usage:
    pytest tests/test_session_manager.py -v --timeout=10
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

import pytest

# Ensure suite-core and suite-api are importable
for _p in (
    str(Path(__file__).parent.parent / "suite-core"),
    str(Path(__file__).parent.parent / "suite-api"),
):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.session_manager import Session, SessionManager, get_session_manager


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def mgr(tmp_path) -> SessionManager:
    """Fresh SessionManager backed by a temp SQLite file."""
    db_path = str(tmp_path / "sessions_test.db")
    return SessionManager(db_path=db_path)


def _make_session(
    mgr: SessionManager,
    email: str = "alice@example.com",
    ip: str = "10.0.0.1",
    agent: str = "TestAgent/1.0",
    org_id: str = "acme",
    ttl_hours: int = 1,
    metadata: dict | None = None,
) -> Session:
    return mgr.create_session(
        user_email=email,
        ip_address=ip,
        user_agent=agent,
        org_id=org_id,
        ttl_hours=ttl_hours,
        metadata=metadata or {},
    )


# ===========================================================================
# Session model
# ===========================================================================


class TestSessionModel:
    def test_fields_present(self, mgr):
        s = _make_session(mgr)
        assert s.id.startswith("sess_")
        assert s.user_email == "alice@example.com"
        assert s.ip_address == "10.0.0.1"
        assert s.user_agent == "TestAgent/1.0"
        assert s.org_id == "acme"
        assert s.is_active is True
        assert isinstance(s.created_at, datetime)
        assert isinstance(s.last_active, datetime)
        assert isinstance(s.expires_at, datetime)
        assert isinstance(s.metadata, dict)

    def test_metadata_stored(self, mgr):
        s = _make_session(mgr, metadata={"device": "mobile", "country": "US"})
        assert s.metadata["device"] == "mobile"
        assert s.metadata["country"] == "US"

    def test_expires_at_ttl(self, mgr):
        s = _make_session(mgr, ttl_hours=2)
        delta = (s.expires_at - s.created_at).total_seconds()
        assert 7190 < delta < 7210  # ~2 hours in seconds

    def test_unique_ids(self, mgr):
        ids = {_make_session(mgr).id for _ in range(10)}
        assert len(ids) == 10


# ===========================================================================
# create_session
# ===========================================================================


class TestCreateSession:
    def test_returns_session(self, mgr):
        s = _make_session(mgr)
        assert isinstance(s, Session)

    def test_default_metadata_empty(self, mgr):
        s = _make_session(mgr)
        assert s.metadata == {}

    def test_custom_ttl(self, mgr):
        s = _make_session(mgr, ttl_hours=48)
        delta = (s.expires_at - s.created_at).total_seconds()
        assert 48 * 3600 - 5 < delta < 48 * 3600 + 5

    def test_persisted_in_db(self, mgr):
        s = _make_session(mgr)
        retrieved = mgr.validate_session(s.id)
        assert retrieved is not None
        assert retrieved.id == s.id


# ===========================================================================
# validate_session
# ===========================================================================


class TestValidateSession:
    def test_valid_session_returned(self, mgr):
        s = _make_session(mgr)
        result = mgr.validate_session(s.id)
        assert result is not None
        assert result.id == s.id

    def test_nonexistent_returns_none(self, mgr):
        assert mgr.validate_session("sess_doesnotexist") is None

    def test_terminated_returns_none(self, mgr):
        s = _make_session(mgr)
        mgr.terminate_session(s.id)
        assert mgr.validate_session(s.id) is None

    def test_expired_returns_none(self, mgr):
        """Create a session then manually expire it in the DB."""
        s = _make_session(mgr, ttl_hours=1)
        # Force expiry by writing a past timestamp directly
        import sqlite3
        conn = sqlite3.connect(mgr._db_path)
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?", (past, s.id)
        )
        conn.commit()
        conn.close()
        assert mgr.validate_session(s.id) is None


# ===========================================================================
# refresh_session
# ===========================================================================


class TestRefreshSession:
    def test_updates_last_active(self, mgr):
        s = _make_session(mgr)
        original_last_active = s.last_active
        import time; time.sleep(0.01)
        refreshed = mgr.refresh_session(s.id)
        assert refreshed is not None
        assert refreshed.last_active >= original_last_active

    def test_extends_expiry_with_ttl(self, mgr):
        s = _make_session(mgr, ttl_hours=1)
        original_expires = s.expires_at
        refreshed = mgr.refresh_session(s.id, ttl_hours=2)
        assert refreshed is not None
        assert refreshed.expires_at > original_expires

    def test_no_ttl_keeps_original_expiry(self, mgr):
        s = _make_session(mgr, ttl_hours=1)
        original_expires = s.expires_at
        refreshed = mgr.refresh_session(s.id)
        assert refreshed is not None
        # Expiry should be unchanged (within 1 second tolerance)
        assert abs((refreshed.expires_at - original_expires).total_seconds()) < 1

    def test_invalid_session_returns_none(self, mgr):
        assert mgr.refresh_session("sess_missing") is None

    def test_terminated_session_returns_none(self, mgr):
        s = _make_session(mgr)
        mgr.terminate_session(s.id)
        assert mgr.refresh_session(s.id) is None


# ===========================================================================
# terminate_session
# ===========================================================================


class TestTerminateSession:
    def test_returns_true_on_success(self, mgr):
        s = _make_session(mgr)
        assert mgr.terminate_session(s.id) is True

    def test_returns_false_for_missing(self, mgr):
        assert mgr.terminate_session("sess_missing") is False

    def test_session_no_longer_valid(self, mgr):
        s = _make_session(mgr)
        mgr.terminate_session(s.id)
        assert mgr.validate_session(s.id) is None

    def test_idempotent_second_call(self, mgr):
        s = _make_session(mgr)
        mgr.terminate_session(s.id)
        # Second call — row exists but is already inactive, rowcount=0
        assert mgr.terminate_session(s.id) is False


# ===========================================================================
# terminate_all_sessions
# ===========================================================================


class TestTerminateAllSessions:
    def test_terminates_all(self, mgr):
        for _ in range(3):
            _make_session(mgr, email="bob@example.com")
        count = mgr.terminate_all_sessions("bob@example.com")
        assert count == 3

    def test_other_users_unaffected(self, mgr):
        _make_session(mgr, email="alice@example.com")
        _make_session(mgr, email="bob@example.com")
        mgr.terminate_all_sessions("alice@example.com")
        assert len(mgr.get_active_sessions("bob@example.com")) == 1

    def test_returns_zero_for_unknown_user(self, mgr):
        assert mgr.terminate_all_sessions("nobody@example.com") == 0

    def test_sessions_become_inactive(self, mgr):
        _make_session(mgr, email="carol@example.com")
        mgr.terminate_all_sessions("carol@example.com")
        assert mgr.get_active_sessions("carol@example.com") == []


# ===========================================================================
# get_active_sessions
# ===========================================================================


class TestGetActiveSessions:
    def test_returns_active_only(self, mgr):
        s1 = _make_session(mgr, email="dave@example.com")
        s2 = _make_session(mgr, email="dave@example.com")
        mgr.terminate_session(s2.id)
        active = mgr.get_active_sessions("dave@example.com")
        assert len(active) == 1
        assert active[0].id == s1.id

    def test_empty_for_no_sessions(self, mgr):
        assert mgr.get_active_sessions("nobody@example.com") == []

    def test_excludes_expired(self, mgr):
        s = _make_session(mgr, email="eve@example.com")
        import sqlite3
        conn = sqlite3.connect(mgr._db_path)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        conn.execute("UPDATE sessions SET expires_at = ? WHERE id = ?", (past, s.id))
        conn.commit()
        conn.close()
        assert mgr.get_active_sessions("eve@example.com") == []


# ===========================================================================
# cleanup_expired
# ===========================================================================


class TestCleanupExpired:
    def test_removes_expired(self, mgr):
        s = _make_session(mgr)
        import sqlite3
        conn = sqlite3.connect(mgr._db_path)
        past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn.execute("UPDATE sessions SET expires_at = ? WHERE id = ?", (past, s.id))
        conn.commit()
        conn.close()
        count = mgr.cleanup_expired()
        assert count >= 1

    def test_removes_inactive(self, mgr):
        s = _make_session(mgr)
        mgr.terminate_session(s.id)
        count = mgr.cleanup_expired()
        assert count >= 1

    def test_active_sessions_preserved(self, mgr):
        s = _make_session(mgr, email="frank@example.com")
        mgr.cleanup_expired()
        assert mgr.validate_session(s.id) is not None

    def test_returns_zero_when_nothing_to_clean(self, mgr):
        _make_session(mgr)
        count = mgr.cleanup_expired()
        assert count == 0


# ===========================================================================
# get_session_stats
# ===========================================================================


class TestGetSessionStats:
    def test_active_count(self, mgr):
        _make_session(mgr, org_id="org1")
        _make_session(mgr, org_id="org1")
        _make_session(mgr, org_id="org2")
        stats = mgr.get_session_stats("org1")
        assert stats["active_count"] == 2

    def test_by_user(self, mgr):
        _make_session(mgr, email="u1@example.com", org_id="orgA")
        _make_session(mgr, email="u1@example.com", org_id="orgA")
        _make_session(mgr, email="u2@example.com", org_id="orgA")
        stats = mgr.get_session_stats("orgA")
        assert stats["by_user"]["u1@example.com"] == 2
        assert stats["by_user"]["u2@example.com"] == 1

    def test_avg_duration_non_negative(self, mgr):
        _make_session(mgr, org_id="orgB")
        stats = mgr.get_session_stats("orgB")
        assert stats["avg_duration_seconds"] >= 0

    def test_empty_org_returns_zeros(self, mgr):
        stats = mgr.get_session_stats("nonexistent_org")
        assert stats["active_count"] == 0
        assert stats["avg_duration_seconds"] == 0.0
        assert stats["by_user"] == {}

    def test_org_id_in_response(self, mgr):
        stats = mgr.get_session_stats("myorg")
        assert stats["org_id"] == "myorg"


# ===========================================================================
# detect_concurrent_sessions
# ===========================================================================


class TestDetectConcurrentSessions:
    def test_single_session_not_concurrent(self, mgr):
        _make_session(mgr, email="g@example.com")
        result = mgr.detect_concurrent_sessions("g@example.com")
        assert result["has_concurrent"] is False
        assert result["session_count"] == 1

    def test_multiple_sessions_concurrent(self, mgr):
        _make_session(mgr, email="h@example.com")
        _make_session(mgr, email="h@example.com")
        result = mgr.detect_concurrent_sessions("h@example.com")
        assert result["has_concurrent"] is True
        assert result["session_count"] == 2

    def test_no_sessions_not_concurrent(self, mgr):
        result = mgr.detect_concurrent_sessions("nobody@example.com")
        assert result["has_concurrent"] is False
        assert result["session_count"] == 0

    def test_sessions_list_returned(self, mgr):
        _make_session(mgr, email="i@example.com")
        result = mgr.detect_concurrent_sessions("i@example.com")
        assert len(result["sessions"]) == 1
        assert isinstance(result["sessions"][0], Session)


# ===========================================================================
# get_suspicious_sessions
# ===========================================================================


class TestGetSuspiciousSessions:
    def test_normal_user_not_flagged(self, mgr):
        _make_session(mgr, email="normal@example.com", ip="10.0.0.1", org_id="orgS")
        results = mgr.get_suspicious_sessions("orgS")
        assert results == []

    def test_flagged_for_many_ips(self, mgr):
        for i in range(3):
            _make_session(
                mgr,
                email="suspect@example.com",
                ip=f"10.0.0.{i + 1}",
                org_id="orgS2",
            )
        results = mgr.get_suspicious_sessions("orgS2")
        assert len(results) == 1
        assert results[0]["user_email"] == "suspect@example.com"
        assert len(results[0]["distinct_ips"]) == 3

    def test_flagged_for_many_agents(self, mgr):
        agents = ["Chrome/100", "Firefox/99", "Safari/15"]
        for agent in agents:
            _make_session(
                mgr,
                email="multiagent@example.com",
                ip="10.0.0.1",
                agent=agent,
                org_id="orgS3",
            )
        results = mgr.get_suspicious_sessions("orgS3")
        assert len(results) == 1
        assert "distinct user agents" in results[0]["reason"]

    def test_empty_org_returns_empty(self, mgr):
        assert mgr.get_suspicious_sessions("no_such_org") == []

    def test_normal_and_suspicious_mixed(self, mgr):
        # Normal user
        _make_session(mgr, email="ok@example.com", org_id="orgS4")
        # Suspicious user
        for i in range(3):
            _make_session(
                mgr,
                email="bad@example.com",
                ip=f"192.168.{i}.1",
                org_id="orgS4",
            )
        results = mgr.get_suspicious_sessions("orgS4")
        emails = [r["user_email"] for r in results]
        assert "bad@example.com" in emails
        assert "ok@example.com" not in emails


# ===========================================================================
# Router endpoint tests (via FastAPI TestClient)
# ===========================================================================


@pytest.fixture
def client(tmp_path):
    """TestClient with a fresh in-memory session manager injected."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api import session_router as sr

    db_path = str(tmp_path / "router_test.db")
    test_mgr = SessionManager(db_path=db_path)
    sr._mgr = test_mgr  # inject test instance

    app = FastAPI()
    app.include_router(sr.router)

    yield TestClient(app)

    # Reset module-level singleton after test
    sr._mgr = None


def _session_payload(**kwargs):
    base = {
        "user_email": "test@example.com",
        "ip_address": "127.0.0.1",
        "user_agent": "pytest/1.0",
        "org_id": "testorg",
        "ttl_hours": 1,
    }
    base.update(kwargs)
    return base


class TestSessionRouter:
    def test_create_session_201(self, client):
        resp = client.post("/api/v1/sessions", json=_session_payload())
        assert resp.status_code == 201
        data = resp.json()
        assert data["id"].startswith("sess_")
        assert data["user_email"] == "test@example.com"
        assert data["is_active"] is True

    def test_create_session_with_metadata(self, client):
        payload = _session_payload(metadata={"device": "laptop"})
        resp = client.post("/api/v1/sessions", json=payload)
        assert resp.status_code == 201
        assert resp.json()["metadata"]["device"] == "laptop"

    def test_get_session_valid(self, client):
        create_resp = client.post("/api/v1/sessions", json=_session_payload())
        sid = create_resp.json()["id"]
        resp = client.get(f"/api/v1/sessions/{sid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == sid

    def test_get_session_missing_404(self, client):
        resp = client.get("/api/v1/sessions/sess_doesnotexist")
        assert resp.status_code == 404

    def test_refresh_session(self, client):
        create_resp = client.post("/api/v1/sessions", json=_session_payload())
        sid = create_resp.json()["id"]
        resp = client.post(f"/api/v1/sessions/{sid}/refresh", json={"ttl_hours": 2})
        assert resp.status_code == 200
        assert resp.json()["id"] == sid

    def test_refresh_missing_session_404(self, client):
        resp = client.post("/api/v1/sessions/sess_missing/refresh", json={})
        assert resp.status_code == 404

    def test_terminate_session_204(self, client):
        create_resp = client.post("/api/v1/sessions", json=_session_payload())
        sid = create_resp.json()["id"]
        resp = client.delete(f"/api/v1/sessions/{sid}")
        assert resp.status_code == 204

    def test_terminate_session_missing_404(self, client):
        resp = client.delete("/api/v1/sessions/sess_missing")
        assert resp.status_code == 404

    def test_terminate_all_sessions(self, client):
        for _ in range(2):
            client.post("/api/v1/sessions", json=_session_payload(user_email="bulk@example.com"))
        resp = client.delete("/api/v1/sessions/user/bulk@example.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["sessions_terminated"] == 2
        assert data["user_email"] == "bulk@example.com"

    def test_list_active_sessions(self, client):
        email = "listed@example.com"
        for _ in range(3):
            client.post("/api/v1/sessions", json=_session_payload(user_email=email))
        resp = client.get(f"/api/v1/sessions/user/{email}")
        assert resp.status_code == 200
        assert len(resp.json()) == 3

    def test_cleanup_expired(self, client):
        resp = client.post("/api/v1/sessions/cleanup")
        assert resp.status_code == 200
        assert "sessions_removed" in resp.json()

    def test_session_stats(self, client):
        client.post("/api/v1/sessions", json=_session_payload(org_id="statorg"))
        resp = client.get("/api/v1/sessions/stats/statorg")
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "statorg"
        assert data["active_count"] >= 1
        assert "by_user" in data

    def test_detect_concurrent_no_sessions(self, client):
        resp = client.get("/api/v1/sessions/concurrent/nobody@example.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_concurrent"] is False
        assert data["session_count"] == 0

    def test_detect_concurrent_multiple(self, client):
        email = "multi@example.com"
        for _ in range(2):
            client.post("/api/v1/sessions", json=_session_payload(user_email=email))
        resp = client.get(f"/api/v1/sessions/concurrent/{email}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_concurrent"] is True
        assert data["session_count"] == 2

    def test_get_suspicious_sessions_empty(self, client):
        resp = client.get("/api/v1/sessions/suspicious/cleanorg")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_suspicious_sessions_flagged(self, client):
        for i in range(3):
            client.post(
                "/api/v1/sessions",
                json=_session_payload(
                    user_email="hacker@example.com",
                    ip_address=f"10.10.{i}.1",
                    org_id="suspiciousorg",
                ),
            )
        resp = client.get("/api/v1/sessions/suspicious/suspiciousorg")
        assert resp.status_code == 200
        entries = resp.json()
        assert len(entries) == 1
        assert entries[0]["user_email"] == "hacker@example.com"
        assert len(entries[0]["distinct_ips"]) == 3
