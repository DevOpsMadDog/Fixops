"""Tests for GAP-016 dev-identity behavioral MERGE across 4 engines.

Covers:
  - 5 signal types in behavioral_analytics_engine.analyze_commit_signals
  - off-hours uses local tz from ISO timestamp
  - bulk_rename >50 files threshold
  - watchlist UNIQUE on active (re-watch after unwatch succeeds)
  - unwatch sets unwatched_at + dedup still works
  - lookback_days filter in uba.score_developer_behavior
  - org_id isolation across all 4 engines
  - dev_identity_router endpoint smoke tests
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Ensure suite-core + suite-api are importable
_REPO = Path(__file__).resolve().parents[1]
for _sub in ("suite-core", "suite-api"):
    p = str(_REPO / _sub)
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_behavioral_db(tmp_path):
    """Isolated behavioral_analytics.db for test."""
    return str(tmp_path / "behavioral_analytics.db")


@pytest.fixture
def tmp_access_anomaly_db(tmp_path):
    return str(tmp_path / "access_anomaly.db")


@pytest.fixture
def tmp_insider_db(tmp_path):
    return str(tmp_path / "insider_threat.db")


@pytest.fixture
def behavioral(tmp_behavioral_db):
    from core.behavioral_analytics_engine import BehavioralAnalyticsEngine
    return BehavioralAnalyticsEngine(db_path=tmp_behavioral_db)


@pytest.fixture
def uba(tmp_path):
    from core.uba_engine import UBAEngine
    return UBAEngine(db_path=str(tmp_path / "uba.db"))


@pytest.fixture
def access_anomaly(tmp_access_anomaly_db):
    from core.access_anomaly_engine import AccessAnomalyEngine
    return AccessAnomalyEngine(db_path=tmp_access_anomaly_db)


@pytest.fixture
def insider(tmp_insider_db):
    from core.insider_threat_engine import InsiderThreatEngine
    return InsiderThreatEngine(db_path=tmp_insider_db)


def _commit(sha: str, files=None, timestamp=None, force_push=False):
    return {
        "sha": sha,
        "files": files or [],
        "timestamp": timestamp or "2026-04-23T12:30:00+00:00",
        "force_push": force_push,
    }


# ---------------------------------------------------------------------------
# 1. analyze_commit_signals — 5 signal types
# ---------------------------------------------------------------------------


def test_signal_off_hours_detected(behavioral):
    """Commit at 23:00 local → off_hours signal."""
    commits = [_commit("abc", files=["README.md"], timestamp="2026-04-23T23:15:00+00:00")]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "off_hours" in types


def test_signal_off_hours_during_business_hours_not_detected(behavioral):
    """Commit at 10:00 local → no off_hours."""
    commits = [_commit("abc", files=["README.md"], timestamp="2026-04-23T10:15:00+00:00")]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "off_hours" not in types


def test_signal_off_hours_local_tz_from_iso_offset(behavioral):
    """Timestamp with -07:00 offset: 12:00-07:00 → hour=12 (on-hours); but with +00:00 23:00 → off_hours."""
    # Same absolute time (19:00 UTC), but expressed as 12:00-07:00 → on-hours
    commits = [_commit("abc", files=["README.md"], timestamp="2026-04-23T12:00:00-07:00")]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "off_hours" not in types


def test_signal_privilege_escalation_iam_file(behavioral):
    commits = [_commit("aaa", files=["suite-core/core/cloud_iam_policy.py"])]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "privilege_escalation" in types


def test_signal_privilege_escalation_rbac_file(behavioral):
    commits = [_commit("bbb", files=["apps/auth/rbac_manager.py"])]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "privilege_escalation" in types


def test_signal_privilege_escalation_permissions_file(behavioral):
    commits = [_commit("ccc", files=["src/permissions.py"])]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "privilege_escalation" in types


def test_signal_secret_file_env(behavioral):
    commits = [_commit("sec1", files=[".env"])]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "secret_file" in types


def test_signal_secret_file_pem(behavioral):
    commits = [_commit("sec2", files=["config/private.pem"])]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "secret_file" in types


def test_signal_secret_file_key(behavioral):
    commits = [_commit("sec3", files=["deploy/tls.key"])]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "secret_file" in types


def test_signal_secret_file_credentials(behavioral):
    commits = [_commit("sec4", files=["aws/credentials.json"])]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "secret_file" in types


def test_signal_bulk_rename_above_threshold(behavioral):
    """>50 files per commit → bulk_rename."""
    files = [f"path/file_{i}.py" for i in range(51)]
    commits = [_commit("bulk", files=files)]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "bulk_rename" in types


def test_signal_bulk_rename_at_threshold_not_detected(behavioral):
    """Exactly 50 files: NOT detected (strict > 50)."""
    files = [f"path/file_{i}.py" for i in range(50)]
    commits = [_commit("bulk50", files=files)]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "bulk_rename" not in types


def test_signal_force_push_detected(behavioral):
    commits = [_commit("fp", files=["README.md"], force_push=True)]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "force_push" in types


def test_signal_force_push_false_not_detected(behavioral):
    commits = [_commit("nofp", files=["README.md"], force_push=False)]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert "force_push" not in types


def test_all_five_signals_in_one_call(behavioral):
    files_priv_sec = ["src/rbac.py", ".env"]
    bulk_files = [f"f_{i}.py" for i in range(60)]
    commits = [
        _commit("a", files=files_priv_sec, timestamp="2026-04-23T03:00:00+00:00"),
        _commit("b", files=bulk_files, force_push=True),
    ]
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    types = {s["type"] for s in r["signals"]}
    assert {"off_hours", "privilege_escalation", "secret_file",
            "bulk_rename", "force_push"}.issubset(types)
    assert r["risk_score_delta"] > 0


def test_analyze_empty_commits(behavioral):
    r = behavioral.analyze_commit_signals("org1", "dev@example.com", [])
    assert r["total_commits"] == 0
    assert r["signals"] == []
    assert r["risk_score_delta"] == 0.0


def test_analyze_requires_author_email(behavioral):
    with pytest.raises(ValueError):
        behavioral.analyze_commit_signals("org1", "", [])


def test_analyze_persists_to_commit_signals_table(behavioral, tmp_behavioral_db):
    commits = [_commit("abc", files=[".env"])]
    behavioral.analyze_commit_signals("org1", "dev@example.com", commits)

    import sqlite3
    conn = sqlite3.connect(tmp_behavioral_db)
    try:
        rows = conn.execute(
            "SELECT signal_type FROM commit_signals WHERE org_id='org1' AND author_email='dev@example.com'"
        ).fetchall()
    finally:
        conn.close()
    assert any(r[0] == "secret_file" for r in rows)


# ---------------------------------------------------------------------------
# 2. uba.score_developer_behavior
# ---------------------------------------------------------------------------


def test_uba_score_zero_when_no_signals(uba, tmp_behavioral_db):
    r = uba.score_developer_behavior(
        "org1", "nobody@example.com", lookback_days=30,
        behavioral_db_path=tmp_behavioral_db,
    )
    assert r["risk_score"] == 0.0
    assert r["risk_level"] == "low"


def test_uba_score_lookback_days_filter(behavioral, uba, tmp_behavioral_db):
    # Create a commit signal
    behavioral.analyze_commit_signals(
        "org1", "dev@example.com",
        [_commit("a", files=[".env"])],
    )
    # Now rewind created_at >30 days
    import sqlite3
    old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    conn = sqlite3.connect(tmp_behavioral_db)
    try:
        conn.execute("UPDATE commit_signals SET created_at=?", (old,))
        conn.commit()
    finally:
        conn.close()

    # 30-day lookback should miss them
    r = uba.score_developer_behavior(
        "org1", "dev@example.com", lookback_days=30,
        behavioral_db_path=tmp_behavioral_db,
    )
    assert r["risk_score"] == 0.0

    # 90-day lookback should catch them
    r90 = uba.score_developer_behavior(
        "org1", "dev@example.com", lookback_days=90,
        behavioral_db_path=tmp_behavioral_db,
    )
    assert r90["risk_score"] > 0.0


def test_uba_score_weighted_aggregate(behavioral, uba, tmp_behavioral_db):
    commits = [_commit("a", files=[".env", "src/rbac.py"])]
    behavioral.analyze_commit_signals("org1", "dev@example.com", commits)
    r = uba.score_developer_behavior(
        "org1", "dev@example.com", lookback_days=30,
        behavioral_db_path=tmp_behavioral_db,
    )
    # secret_file (25) + privilege_escalation (15) = 40
    assert r["risk_score"] >= 40.0
    assert r["risk_level"] in ("medium", "high", "critical")


def test_uba_score_org_isolation(behavioral, uba, tmp_behavioral_db):
    behavioral.analyze_commit_signals(
        "orgA", "dev@example.com", [_commit("a", files=[".env"])],
    )
    r = uba.score_developer_behavior(
        "orgB", "dev@example.com", lookback_days=30,
        behavioral_db_path=tmp_behavioral_db,
    )
    assert r["risk_score"] == 0.0
    assert r["risk_level"] == "low"


def test_uba_score_missing_db_graceful(uba, tmp_path):
    """DB file doesn't exist → zero score, no crash."""
    missing = str(tmp_path / "does_not_exist.db")
    r = uba.score_developer_behavior(
        "org1", "x@y.com", lookback_days=30,
        behavioral_db_path=missing,
    )
    assert r["risk_score"] == 0.0


# ---------------------------------------------------------------------------
# 3. access_anomaly.record_scm_anomaly
# ---------------------------------------------------------------------------


def test_record_scm_anomaly_persists(access_anomaly):
    r = access_anomaly.record_scm_anomaly(
        "org1", "dev@example.com", "off_hours",
        {"sha": "abc", "hour": 23},
    )
    assert r["anomaly_type"] == "off_hours"
    assert r["author_email"] == "dev@example.com"
    assert r["evidence_json"]["hour"] == 23


def test_record_scm_anomaly_org_isolation(access_anomaly):
    access_anomaly.record_scm_anomaly("orgA", "dev@a.com", "off_hours", {})
    access_anomaly.record_scm_anomaly("orgB", "dev@b.com", "force_push", {})
    a = access_anomaly.list_scm_anomalies("orgA")
    b = access_anomaly.list_scm_anomalies("orgB")
    assert len(a) == 1 and a[0]["anomaly_type"] == "off_hours"
    assert len(b) == 1 and b[0]["anomaly_type"] == "force_push"


def test_record_scm_anomaly_accepts_str_evidence(access_anomaly):
    r = access_anomaly.record_scm_anomaly(
        "org1", "dev@example.com", "secret_file",
        '{"file": ".env"}',
    )
    assert r["evidence_json"]["file"] == ".env"


# ---------------------------------------------------------------------------
# 4. insider_threat watchlist: UNIQUE on active, unwatch, re-watch
# ---------------------------------------------------------------------------


def test_watch_developer_creates_row(insider):
    r = insider.watch_developer("org1", "dev@example.com", "suspicious", "analyst1")
    assert r["author_email"] == "dev@example.com"
    assert r["unwatched_at"] is None


def test_watch_developer_active_unique(insider):
    insider.watch_developer("org1", "dev@example.com", "r1", "a1")
    with pytest.raises(ValueError, match="already"):
        insider.watch_developer("org1", "dev@example.com", "r2", "a2")


def test_unwatch_sets_unwatched_at(insider):
    insider.watch_developer("org1", "dev@example.com", "r1", "a1")
    r = insider.unwatch_developer("org1", "dev@example.com", "a2")
    assert r["unwatched_at"] is not None


def test_unwatch_no_active_raises(insider):
    with pytest.raises(ValueError):
        insider.unwatch_developer("org1", "nobody@example.com", "a2")


def test_rewatch_after_unwatch_succeeds(insider):
    insider.watch_developer("org1", "dev@example.com", "r1", "a1")
    insider.unwatch_developer("org1", "dev@example.com", "a1")
    # Re-watching should create a new active row
    r2 = insider.watch_developer("org1", "dev@example.com", "r2", "a2")
    assert r2["unwatched_at"] is None


def test_list_watched_active_only_by_default(insider):
    insider.watch_developer("org1", "active@example.com", "r", "a")
    insider.watch_developer("org1", "inactive@example.com", "r", "a")
    insider.unwatch_developer("org1", "inactive@example.com", "a")
    actives = insider.list_watched_developers("org1")
    emails = {w["author_email"] for w in actives}
    assert "active@example.com" in emails
    assert "inactive@example.com" not in emails


def test_list_watched_include_inactive(insider):
    insider.watch_developer("org1", "dev@example.com", "r", "a")
    insider.unwatch_developer("org1", "dev@example.com", "a")
    all_rows = insider.list_watched_developers("org1", include_inactive=True)
    assert len(all_rows) == 1


def test_watch_org_isolation(insider):
    insider.watch_developer("orgA", "dev@example.com", "r", "a")
    lst = insider.list_watched_developers("orgB")
    assert lst == []


# ---------------------------------------------------------------------------
# 5. Router smoke tests (use FastAPI TestClient)
# ---------------------------------------------------------------------------


@pytest.fixture
def router_client(monkeypatch, tmp_path):
    """FastAPI client with router mounted and engines using tmp DBs."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Reset router-level engine singletons and point them at tmp DBs
    import apps.api.dev_identity_router as _r
    from apps.api.auth_deps import api_key_auth
    from core.behavioral_analytics_engine import BehavioralAnalyticsEngine
    from core.uba_engine import UBAEngine
    from core.access_anomaly_engine import AccessAnomalyEngine
    from core.insider_threat_engine import InsiderThreatEngine

    beh_db = str(tmp_path / "behavioral.db")
    _r._behavioral = BehavioralAnalyticsEngine(db_path=beh_db)
    _r._uba = UBAEngine(db_path=str(tmp_path / "uba.db"))
    _r._access_anomaly = AccessAnomalyEngine(db_path=str(tmp_path / "aa.db"))
    _r._insider = InsiderThreatEngine(db_path=str(tmp_path / "it.db"))

    # Patch UBA's default behavioral_db reference
    import core.uba_engine as _uba_mod
    monkeypatch.setattr(_uba_mod, "_BEHAVIORAL_DB", beh_db)

    app = FastAPI()
    app.include_router(_r.router)

    # Override api_key_auth via FastAPI's dependency_overrides (proper way)
    async def _noop_auth():
        return {"org_id": "default", "api_key_id": "test"}
    app.dependency_overrides[api_key_auth] = _noop_auth

    return TestClient(app)


def test_router_analyze_endpoint(router_client):
    resp = router_client.post(
        "/api/v1/dev-identity/analyze",
        json={
            "org_id": "org1",
            "author_email": "dev@example.com",
            "commits": [
                {
                    "sha": "abc123",
                    "files": [".env"],
                    "timestamp": "2026-04-23T12:00:00+00:00",
                    "force_push": False,
                }
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["author_email"] == "dev@example.com"
    assert any(s["type"] == "secret_file" for s in body["signals"])


def test_router_score_endpoint(router_client):
    # Seed a signal
    router_client.post(
        "/api/v1/dev-identity/analyze",
        json={
            "org_id": "org1", "author_email": "dev@example.com",
            "commits": [
                {"sha": "a", "files": [".env"],
                 "timestamp": "2026-04-23T12:00:00+00:00", "force_push": False}
            ],
        },
    )
    resp = router_client.get(
        "/api/v1/dev-identity/score",
        params={"org_id": "org1", "author_email": "dev@example.com",
                "lookback_days": 30},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["author_email"] == "dev@example.com"
    assert body["risk_score"] >= 25.0  # secret_file weight


def test_router_watchlist_flow(router_client):
    r = router_client.post(
        "/api/v1/dev-identity/watch",
        json={"org_id": "org1", "author_email": "dev@example.com",
              "reason": "r", "watched_by": "a"},
    )
    assert r.status_code == 200

    lst = router_client.get(
        "/api/v1/dev-identity/watchlist",
        params={"org_id": "org1"},
    )
    assert lst.status_code == 200
    assert any(w["author_email"] == "dev@example.com" for w in lst.json())

    u = router_client.post(
        "/api/v1/dev-identity/unwatch",
        json={"org_id": "org1", "author_email": "dev@example.com",
              "unwatched_by": "a"},
    )
    assert u.status_code == 200

    # No longer active
    active = router_client.get(
        "/api/v1/dev-identity/watchlist",
        params={"org_id": "org1"},
    )
    assert active.json() == []


def test_router_watch_duplicate_409(router_client):
    router_client.post(
        "/api/v1/dev-identity/watch",
        json={"org_id": "org1", "author_email": "dev@example.com",
              "reason": "r", "watched_by": "a"},
    )
    r2 = router_client.post(
        "/api/v1/dev-identity/watch",
        json={"org_id": "org1", "author_email": "dev@example.com",
              "reason": "r", "watched_by": "a"},
    )
    assert r2.status_code == 409
