"""GAP-049 + GAP-066 — Unified /issues federation + diff-mode tests."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.security_findings_engine import SecurityFindingsEngine
from core.unified_issues_engine import UnifiedIssuesEngine, get_unified_issues_engine


def _ts(offset_sec: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_sec)).isoformat()


# ---------------------------------------------------------------------------
# Fixtures — isolated per-test DB files
# ---------------------------------------------------------------------------


@pytest.fixture()
def findings_db(tmp_path: Path) -> str:
    return str(tmp_path / "security_findings_engine.db")


@pytest.fixture()
def alerts_db(tmp_path: Path) -> str:
    return str(tmp_path / "alert_triage.db")


@pytest.fixture()
def exposures_db(tmp_path: Path) -> str:
    return str(tmp_path / "fixops_exposure_cases.db")


@pytest.fixture()
def engine(findings_db, exposures_db, alerts_db) -> UnifiedIssuesEngine:
    return UnifiedIssuesEngine(
        findings_db=findings_db,
        exposures_db=exposures_db,
        alerts_db=alerts_db,
    )


# ---------------------------------------------------------------------------
# Data seeders (use raw SQL so tests don't depend on full engine semantics)
# ---------------------------------------------------------------------------


def _seed_findings_schema(db_path: str) -> None:
    # Use the real engine to lay down the canonical schema, then close.
    SecurityFindingsEngine(db_path=db_path)


def _insert_finding(
    db_path: str,
    *,
    org_id: str,
    correlation_key: str,
    scan_id: str,
    severity: str = "high",
    title: str = "SQL injection",
    status: str = "open",
    asset_id: str = "svc-a",
    first_seen_at: str = "",
    resolved_at: str = "",
) -> str:
    fid = str(uuid.uuid4())
    now = _ts()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO security_findings
               (id, org_id, title, finding_type, source_tool, severity, cvss_score,
                asset_id, asset_type, description, remediation, status,
                first_seen, last_seen, occurrence_count, assigned_to, created_at,
                correlation_key, scan_id, first_seen_at, previous_violation_id,
                resolved_at, unchanged_scan_count)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fid, org_id, title, "vulnerability", "SAST", severity, 8.0,
                asset_id, "service", "", "", status,
                now, now, 1, "", now,
                correlation_key, scan_id, first_seen_at or now, None,
                resolved_at or None, 0,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return fid


def _seed_alerts_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS at_alerts (
                id                TEXT PRIMARY KEY,
                org_id            TEXT NOT NULL,
                title             TEXT NOT NULL DEFAULT '',
                source_system     TEXT NOT NULL DEFAULT 'siem',
                severity          TEXT NOT NULL DEFAULT 'medium',
                priority          TEXT NOT NULL DEFAULT 'p3',
                raw_alert_json    TEXT NOT NULL DEFAULT '{}',
                status            TEXT NOT NULL DEFAULT 'new',
                assigned_to       TEXT NOT NULL DEFAULT '',
                triage_notes      TEXT NOT NULL DEFAULT '',
                escalation_reason TEXT NOT NULL DEFAULT '',
                ingested_at       DATETIME,
                triaged_at        DATETIME,
                resolved_at       DATETIME
            );
            """
        )
    finally:
        conn.close()


def _insert_alert(
    db_path: str,
    *,
    org_id: str,
    title: str = "Suspicious login",
    severity: str = "high",
    status: str = "new",
    source_system: str = "siem",
    ingested_at: str = "",
) -> str:
    aid = str(uuid.uuid4())
    priority = {"critical": "p1", "high": "p2", "medium": "p3", "low": "p4", "info": "p4"}[severity]
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO at_alerts
               (id, org_id, title, source_system, severity, priority,
                raw_alert_json, status, assigned_to, triage_notes,
                escalation_reason, ingested_at, triaged_at, resolved_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                aid, org_id, title, source_system, severity, priority,
                "{}", status, "", "", "",
                ingested_at or _ts(), None, None,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return aid


def _seed_exposures_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS exposure_cases (
                case_id         TEXT PRIMARY KEY,
                title           TEXT NOT NULL,
                description     TEXT NOT NULL DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'open',
                priority        TEXT NOT NULL DEFAULT 'medium',
                org_id          TEXT NOT NULL DEFAULT '',
                root_cve        TEXT,
                root_cwe        TEXT,
                root_component  TEXT,
                affected_assets TEXT NOT NULL DEFAULT '[]',
                cluster_ids     TEXT NOT NULL DEFAULT '[]',
                finding_count   INTEGER NOT NULL DEFAULT 0,
                risk_score      REAL NOT NULL DEFAULT 0.0,
                epss_score      REAL,
                in_kev          INTEGER NOT NULL DEFAULT 0,
                blast_radius    INTEGER NOT NULL DEFAULT 0,
                assigned_to     TEXT,
                assigned_team   TEXT,
                sla_due         TEXT,
                sla_breached    INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                resolved_at     TEXT,
                closed_at       TEXT,
                remediation_plan TEXT,
                playbook_id     TEXT,
                autofix_pr_url  TEXT,
                tags            TEXT NOT NULL DEFAULT '[]',
                metadata        TEXT NOT NULL DEFAULT '{}'
            );
            """
        )
    finally:
        conn.close()


def _insert_exposure(
    db_path: str,
    *,
    org_id: str,
    title: str = "CVE-2024-0001 in prod",
    priority: str = "critical",
    status: str = "open",
    root_cve: str = "CVE-2024-0001",
    assets: list | None = None,
    created_at: str = "",
) -> str:
    cid = f"EC-{uuid.uuid4().hex[:12].upper()}"
    now = _ts()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO exposure_cases (
                case_id, title, description, status, priority, org_id,
                root_cve, root_cwe, root_component,
                affected_assets, cluster_ids, finding_count,
                risk_score, epss_score, in_kev, blast_radius,
                assigned_to, assigned_team, sla_due, sla_breached,
                created_at, updated_at, resolved_at, closed_at,
                remediation_plan, playbook_id, autofix_pr_url, tags, metadata
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                cid, title, "", status, priority, org_id,
                root_cve, None, None,
                json.dumps(assets or ["svc-a"]), "[]", 3,
                7.5, None, 1, 2,
                None, None, None, 0,
                created_at or now, now, None, None,
                None, None, None, "[]", "{}",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return cid


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_unified_list_federates_three_sources(engine, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)

    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1")
    _insert_alert(alerts_db, org_id="o1")
    _insert_exposure(exposures_db, org_id="o1")

    issues = engine.unified_list("o1")
    sources = {i["source_engine"] for i in issues}
    assert sources == {"findings", "exposures", "alerts"}
    assert len(issues) == 3


def test_unified_list_empty_when_no_dbs(tmp_path):
    eng = UnifiedIssuesEngine(
        findings_db=str(tmp_path / "noop1.db"),
        exposures_db=str(tmp_path / "noop2.db"),
        alerts_db=str(tmp_path / "noop3.db"),
    )
    assert eng.unified_list("o1") == []


def test_filter_by_severity(engine, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1", severity="critical")
    _insert_finding(findings_db, org_id="o1", correlation_key="k2", scan_id="s1", severity="low")
    _insert_alert(alerts_db, org_id="o1", severity="critical")
    _insert_alert(alerts_db, org_id="o1", severity="low")

    crit = engine.unified_list("o1", filters={"severity": "critical"})
    assert all(i["severity"] == "critical" for i in crit)
    assert len(crit) == 2


def test_filter_by_status(engine, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1", status="open")
    _insert_finding(findings_db, org_id="o1", correlation_key="k2", scan_id="s1", status="resolved")

    opens = engine.unified_list("o1", filters={"status": "open"})
    assert len(opens) == 1
    assert opens[0]["status"] == "open"


def test_filter_by_source_only_findings(engine, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1")
    _insert_alert(alerts_db, org_id="o1")
    _insert_exposure(exposures_db, org_id="o1")

    only = engine.unified_list("o1", filters={"source": "findings"})
    assert len(only) == 1
    assert only[0]["source_engine"] == "findings"


def test_filter_by_source_only_exposures(engine, findings_db, exposures_db, alerts_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1")
    _insert_exposure(exposures_db, org_id="o1")
    _insert_alert(alerts_db, org_id="o1")

    only = engine.unified_list("o1", filters={"source": "exposures"})
    assert len(only) == 1
    assert only[0]["source_engine"] == "exposures"


def test_filter_invalid_source_raises(engine):
    with pytest.raises(ValueError):
        engine.unified_list("o1", filters={"source": "not-a-source"})


def test_missing_org_id_raises(engine):
    with pytest.raises(ValueError):
        engine.unified_list("")


def test_first_seen_window(engine, findings_db):
    _seed_findings_schema(findings_db)
    old = _ts(-86400)
    new = _ts()
    _insert_finding(findings_db, org_id="o1", correlation_key="old", scan_id="s1",
                    first_seen_at=old)
    _insert_finding(findings_db, org_id="o1", correlation_key="new", scan_id="s1",
                    first_seen_at=new)

    recent = engine.unified_list("o1", filters={"first_seen_after": _ts(-3600)})
    keys = [i["correlation_key"] for i in recent]
    assert "new" in keys and "old" not in keys


def test_counts_sum_equals_total(engine, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1")
    _insert_finding(findings_db, org_id="o1", correlation_key="k2", scan_id="s1")
    _insert_alert(alerts_db, org_id="o1")
    _insert_exposure(exposures_db, org_id="o1")
    _insert_exposure(exposures_db, org_id="o1", title="case2")

    counts = engine.issue_counts_by_source("o1")
    assert counts["findings"] == 2
    assert counts["alerts"] == 1
    assert counts["exposures"] == 2
    assert counts["total"] == 5


def test_counts_empty_org(engine, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    counts = engine.issue_counts_by_source("empty-org")
    assert counts == {"findings": 0, "exposures": 0, "alerts": 0, "total": 0}


def test_diff_three_scan_scenario(engine, findings_db):
    """Baseline has A+B; current has B+C. → new=[C], unchanged=[B], resolved=[A]."""
    _seed_findings_schema(findings_db)
    # Baseline
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="s1")
    _insert_finding(findings_db, org_id="o1", correlation_key="B", scan_id="s1")
    # Current
    _insert_finding(findings_db, org_id="o1", correlation_key="B", scan_id="s2")
    _insert_finding(findings_db, org_id="o1", correlation_key="C", scan_id="s2")

    diff = engine.compute_diff("o1", "s1", "s2")
    assert diff["summary"]["new_count"] == 1
    assert diff["summary"]["unchanged_count"] == 1
    assert diff["summary"]["resolved_count"] == 1
    assert diff["new"][0]["correlation_key"] == "C"
    assert diff["resolved"][0]["correlation_key"] == "A"


def test_diff_empty_baseline_all_new(engine, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="X", scan_id="s2")
    _insert_finding(findings_db, org_id="o1", correlation_key="Y", scan_id="s2")
    diff = engine.compute_diff("o1", "s1", "s2")
    assert diff["summary"]["new_count"] == 2
    assert diff["summary"]["unchanged_count"] == 0
    assert diff["summary"]["resolved_count"] == 0


def test_diff_empty_current_all_resolved(engine, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="X", scan_id="s1")
    _insert_finding(findings_db, org_id="o1", correlation_key="Y", scan_id="s1")
    diff = engine.compute_diff("o1", "s1", "s2")
    assert diff["summary"]["resolved_count"] == 2
    assert diff["summary"]["new_count"] == 0
    assert diff["summary"]["unchanged_count"] == 0


def test_diff_identical_scan_ids_raises(engine):
    with pytest.raises(ValueError):
        engine.compute_diff("o1", "same", "same")


def test_diff_missing_org_raises(engine):
    with pytest.raises(ValueError):
        engine.compute_diff("", "s1", "s2")


def test_diff_affected_components(engine, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="s1", asset_id="svc-1")
    _insert_finding(findings_db, org_id="o1", correlation_key="B", scan_id="s2", asset_id="svc-2")
    diff = engine.compute_diff("o1", "s1", "s2")
    assert set(diff["affected_components"]) == {"svc-1", "svc-2"}


def test_diff_no_correlation_key_is_new(engine, findings_db):
    """Rows without a correlation_key must fall into the 'new' bucket."""
    _seed_findings_schema(findings_db)
    # Empty correlation_key in current scan
    _insert_finding(findings_db, org_id="o1", correlation_key="", scan_id="s2")
    diff = engine.compute_diff("o1", "s1", "s2")
    assert diff["summary"]["new_count"] == 1


def test_diff_history_lists_scans(engine, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="s1")
    _insert_finding(findings_db, org_id="o1", correlation_key="B", scan_id="s2")
    _insert_finding(findings_db, org_id="o1", correlation_key="C", scan_id="s2")
    scans = engine.diff_history("o1")
    by_id = {s["scan_id"]: s for s in scans}
    assert "s1" in by_id and "s2" in by_id
    assert by_id["s2"]["finding_count"] == 2


def test_diff_history_skips_empty_scan_ids(engine, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="")
    scans = engine.diff_history("o1")
    assert scans == []


def test_org_isolation_findings(engine, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1")
    _insert_finding(findings_db, org_id="o2", correlation_key="k2", scan_id="s1")

    o1 = engine.unified_list("o1")
    o2 = engine.unified_list("o2")
    assert len(o1) == 1 and len(o2) == 1
    assert o1[0]["correlation_key"] != o2[0]["correlation_key"]


def test_org_isolation_counts(engine, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1")
    _insert_finding(findings_db, org_id="o2", correlation_key="k2", scan_id="s1")
    _insert_alert(alerts_db, org_id="o2")

    assert engine.issue_counts_by_source("o1")["total"] == 1
    assert engine.issue_counts_by_source("o2")["total"] == 2


def test_org_isolation_diff(engine, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="s1")
    _insert_finding(findings_db, org_id="o2", correlation_key="A", scan_id="s1")
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="s2")

    # For o1: A is unchanged between s1 and s2; for o2: A is only in s1 so resolved.
    d1 = engine.compute_diff("o1", "s1", "s2")
    d2 = engine.compute_diff("o2", "s1", "s2")
    assert d1["summary"]["unchanged_count"] == 1
    assert d2["summary"]["resolved_count"] == 1


def test_issue_stats_shape(engine, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1", severity="critical")
    _insert_alert(alerts_db, org_id="o1", severity="high", status="new")
    _insert_exposure(exposures_db, org_id="o1", priority="medium", status="triaging")

    stats = engine.issue_stats("o1")
    assert stats["counts"]["total"] == 3
    assert "critical" in stats["by_severity"]
    assert stats["by_status"].get("new", 0) >= 1


# ---------------------------------------------------------------------------
# Router smoke test
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(monkeypatch, findings_db, exposures_db, alerts_db):
    # Patch engine factory so the router reads our isolated DBs.
    from core import unified_issues_engine as ue
    test_engine = UnifiedIssuesEngine(
        findings_db=findings_db,
        exposures_db=exposures_db,
        alerts_db=alerts_db,
    )
    monkeypatch.setattr(ue, "get_unified_issues_engine", lambda *a, **kw: test_engine)

    # Disable API-key auth for this smoke test.
    from apps.api import auth_deps
    monkeypatch.setattr(auth_deps, "api_key_auth", lambda: None)

    from fastapi import FastAPI
    from apps.api.unified_issues_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_endpoint_list_smoke(client, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1")
    _insert_alert(alerts_db, org_id="o1")

    r = client.get("/api/v1/issues", params={"org_id": "o1"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert isinstance(body["issues"], list)


def test_endpoint_counts_smoke(client, findings_db, exposures_db, alerts_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1")

    r = client.get("/api/v1/issues/counts", params={"org_id": "o1"})
    assert r.status_code == 200
    assert r.json()["findings"] == 1


def test_endpoint_diff_smoke(client, findings_db, exposures_db, alerts_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="s1")
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="s2")
    _insert_finding(findings_db, org_id="o1", correlation_key="NEW", scan_id="s2")

    r = client.post(
        "/api/v1/issues/diff",
        params={"org_id": "o1"},
        json={"baseline_scan_id": "s1", "current_scan_id": "s2"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["new_count"] == 1
    assert body["summary"]["unchanged_count"] == 1


def test_endpoint_diff_identical_scans_rejected(client):
    r = client.post(
        "/api/v1/issues/diff",
        params={"org_id": "o1"},
        json={"baseline_scan_id": "same", "current_scan_id": "same"},
    )
    assert r.status_code == 400


def test_endpoint_diff_history_smoke(client, findings_db):
    _seed_findings_schema(findings_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="A", scan_id="s1")
    r = client.get("/api/v1/issues/diff-history", params={"org_id": "o1"})
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_endpoint_stats_smoke(client, findings_db, alerts_db, exposures_db):
    _seed_findings_schema(findings_db)
    _seed_alerts_schema(alerts_db)
    _seed_exposures_schema(exposures_db)
    _insert_finding(findings_db, org_id="o1", correlation_key="k1", scan_id="s1", severity="high")

    r = client.get("/api/v1/issues/stats", params={"org_id": "o1"})
    assert r.status_code == 200
    body = r.json()
    assert body["counts"]["total"] == 1
    assert "high" in body["by_severity"]
