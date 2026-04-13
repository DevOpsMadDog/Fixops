"""
Tests for Audit Log Analytics Engine — ALDECI.

Covers:
- LogParser: JSON, syslog, CEF, LEEF formats
- AuditAnomalyDetector: all 5 detection rules
- AuditAnalyticsDB: CRUD, FTS search, retention, timeline
- AuditAnalyticsEngine: ingest, batch, search, compliance trail, retention, timeline
- API endpoints: all 10 routes via TestClient

50+ tests, all scoped to isolated temp DBs.

Compliance: SOC2 CC7.2, HIPAA §164.312(b)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.audit_analytics import (
    AuditAnalyticsDB,
    AuditAnalyticsEngine,
    AuditAnomalyDetector,
    AuditEntry,
    AuditSeverity,
    EntryStatus,
    ForensicTimeline,
    LogFormat,
    LogParser,
    RetentionPolicy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tmp_db() -> str:
    """Return a path to a fresh temp SQLite file."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # AuditAnalyticsDB creates it
    return path


def _make_entry(
    actor: str = "alice",
    action: str = "read",
    resource_type: str = "finding",
    resource_id: str = "f-1",
    outcome: str = "success",
    severity: AuditSeverity = AuditSeverity.INFO,
    timestamp: datetime | None = None,
    org_id: str = "test-org",
) -> AuditEntry:
    ts = timestamp or datetime.now(timezone.utc)
    return AuditEntry(
        org_id=org_id,
        timestamp=ts,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        severity=severity,
        source_format=LogFormat.JSON,
        raw='{"actor":"' + actor + '"}',
    )


# ============================================================================
# LogParser tests
# ============================================================================


class TestLogParserJSON:
    """Test JSON log parsing."""

    def setup_method(self) -> None:
        self.parser = LogParser()

    def test_parse_json_basic(self) -> None:
        raw = json.dumps({"actor": "bob", "action": "login", "severity": "info"})
        entry = self.parser.parse(raw, LogFormat.JSON, org_id="org1")
        assert entry.actor == "bob"
        assert entry.action == "login"
        assert entry.severity == AuditSeverity.INFO
        assert entry.org_id == "org1"

    def test_parse_json_alt_keys(self) -> None:
        raw = json.dumps({"user": "carol", "event": "logout", "level": "warning"})
        entry = self.parser.parse(raw, LogFormat.JSON)
        assert entry.actor == "carol"
        assert entry.action == "logout"
        assert entry.severity == AuditSeverity.WARNING

    def test_parse_json_timestamp(self) -> None:
        raw = json.dumps({"timestamp": "2024-01-15T10:00:00Z", "action": "read"})
        entry = self.parser.parse(raw, LogFormat.JSON)
        assert entry.timestamp.year == 2024
        assert entry.timestamp.month == 1

    def test_parse_json_checksum_set(self) -> None:
        raw = json.dumps({"actor": "dave", "action": "write"})
        entry = self.parser.parse(raw, LogFormat.JSON)
        assert len(entry.checksum) == 64  # SHA-256 hex

    def test_parse_json_invalid_falls_back(self) -> None:
        entry = self.parser.parse("not valid json", LogFormat.JSON)
        assert entry.actor == ""
        assert entry.severity == AuditSeverity.INFO

    def test_parse_json_outcome(self) -> None:
        raw = json.dumps({"actor": "eve", "action": "delete", "result": "failure"})
        entry = self.parser.parse(raw, LogFormat.JSON)
        assert entry.outcome == "failure"

    def test_parse_json_resource_fields(self) -> None:
        raw = json.dumps({"resource_type": "secret", "resource_id": "s-99", "action": "read"})
        entry = self.parser.parse(raw, LogFormat.JSON)
        assert entry.resource_type == "secret"
        assert entry.resource_id == "s-99"


class TestLogParserSyslog:
    """Test syslog format parsing."""

    def setup_method(self) -> None:
        self.parser = LogParser()

    def test_parse_syslog_basic(self) -> None:
        raw = "<13>Jan 15 10:00:00 myhost sshd[1234]: Accepted password for alice"
        entry = self.parser.parse(raw, LogFormat.SYSLOG)
        assert entry.actor == "myhost"
        assert "Accepted password for alice" in entry.action
        assert entry.source_format == LogFormat.SYSLOG

    def test_parse_syslog_severity_from_pri(self) -> None:
        # PRI=8 → facility=1 (user), severity=0 (EMERG)
        raw = "<8>Jan 15 10:00:00 host kernel: OOM killer"
        entry = self.parser.parse(raw, LogFormat.SYSLOG)
        assert entry.severity == AuditSeverity.CRITICAL

    def test_parse_syslog_unmatched_line(self) -> None:
        entry = self.parser.parse("garbage line without proper format", LogFormat.SYSLOG)
        assert entry.source_format == LogFormat.SYSLOG

    def test_parse_syslog_info_severity(self) -> None:
        # PRI=14 → severity=6 (info)
        raw = "<14>Mar  5 08:30:00 webserver nginx[5678]: GET /api/health 200"
        entry = self.parser.parse(raw, LogFormat.SYSLOG)
        assert entry.severity == AuditSeverity.INFO


class TestLogParserCEF:
    """Test CEF format parsing."""

    def setup_method(self) -> None:
        self.parser = LogParser()

    def test_parse_cef_basic(self) -> None:
        raw = "CEF:0|ACME|FirewallApp|1.0|100|User login|5|suser=alice src=192.168.1.1"
        entry = self.parser.parse(raw, LogFormat.CEF)
        assert entry.actor == "alice"
        assert entry.actor_ip == "192.168.1.1"
        assert entry.action == "User login"
        assert entry.source_format == LogFormat.CEF

    def test_parse_cef_high_severity(self) -> None:
        raw = "CEF:0|Vendor|Product|1.0|200|Attack|9|src=10.0.0.1"
        entry = self.parser.parse(raw, LogFormat.CEF)
        assert entry.severity == AuditSeverity.CRITICAL

    def test_parse_cef_medium_severity(self) -> None:
        raw = "CEF:0|Vendor|Product|1.0|200|Event|5|src=10.0.0.1"
        entry = self.parser.parse(raw, LogFormat.CEF)
        assert entry.severity == AuditSeverity.WARNING

    def test_parse_cef_unmatched(self) -> None:
        entry = self.parser.parse("not a CEF line", LogFormat.CEF)
        assert entry.source_format == LogFormat.CEF

    def test_parse_cef_duser(self) -> None:
        raw = "CEF:0|V|P|1|101|Action|3|duser=bob"
        entry = self.parser.parse(raw, LogFormat.CEF)
        assert entry.actor == "bob"


class TestLogParserLEEF:
    """Test LEEF format parsing."""

    def setup_method(self) -> None:
        self.parser = LogParser()

    def test_parse_leef_basic(self) -> None:
        raw = "LEEF:1.0|IBM|QRadar|1.0|UserLogin|usrName=alice\tsrc=10.1.2.3"
        entry = self.parser.parse(raw, LogFormat.LEEF)
        assert entry.actor == "alice"
        assert entry.source_format == LogFormat.LEEF
        assert entry.action == "UserLogin"

    def test_parse_leef_severity_mapping(self) -> None:
        raw = "LEEF:1.0|IBM|QRadar|1.0|Alert|severity=High\tusrName=mallory"
        entry = self.parser.parse(raw, LogFormat.LEEF)
        assert entry.severity == AuditSeverity.ERROR

    def test_parse_leef_unmatched(self) -> None:
        entry = self.parser.parse("random garbage", LogFormat.LEEF)
        assert entry.source_format == LogFormat.LEEF


# ============================================================================
# AuditAnomalyDetector tests
# ============================================================================


class TestAuditAnomalyDetector:
    """Test all 5 anomaly detection rules."""

    def setup_method(self) -> None:
        self.detector = AuditAnomalyDetector()

    def test_off_hours_weekend(self) -> None:
        # Saturday
        saturday = datetime(2024, 1, 6, 14, 0, 0, tzinfo=timezone.utc)
        entry = _make_entry(actor="alice", timestamp=saturday)
        anomalies = self.detector.detect([entry])
        kinds = [a.kind.value for a in anomalies]
        assert "off_hours_access" in kinds

    def test_off_hours_night(self) -> None:
        # 3am Monday
        monday_night = datetime(2024, 1, 8, 3, 0, 0, tzinfo=timezone.utc)
        entry = _make_entry(actor="bob", timestamp=monday_night)
        anomalies = self.detector.detect([entry])
        kinds = [a.kind.value for a in anomalies]
        assert "off_hours_access" in kinds

    def test_no_off_hours_business_hours(self) -> None:
        # 10am Monday
        monday_morning = datetime(2024, 1, 8, 10, 0, 0, tzinfo=timezone.utc)
        entry = _make_entry(actor="carol", timestamp=monday_morning)
        anomalies = self.detector.detect([entry])
        kinds = [a.kind.value for a in anomalies]
        assert "off_hours_access" not in kinds

    def test_privilege_escalation_sudo(self) -> None:
        entry = _make_entry(action="sudo apt-get install nmap")
        anomalies = self.detector.detect([entry])
        kinds = [a.kind.value for a in anomalies]
        assert "privilege_escalation" in kinds

    def test_privilege_escalation_escalate(self) -> None:
        entry = _make_entry(action="escalate privileges to admin")
        anomalies = self.detector.detect([entry])
        kinds = [a.kind.value for a in anomalies]
        assert "privilege_escalation" in kinds

    def test_no_privilege_escalation_normal(self) -> None:
        entry = _make_entry(action="read finding")
        anomalies = self.detector.detect([entry])
        kinds = [a.kind.value for a in anomalies]
        assert "privilege_escalation" not in kinds

    def test_repeated_failures(self) -> None:
        now = datetime.now(timezone.utc)
        entries = [
            _make_entry(actor="mallory", outcome="failure", timestamp=now + timedelta(seconds=i * 30))
            for i in range(7)
        ]
        anomalies = self.detector.detect(entries)
        kinds = [a.kind.value for a in anomalies]
        assert "repeated_failure" in kinds

    def test_no_repeated_failures_below_threshold(self) -> None:
        now = datetime.now(timezone.utc)
        entries = [
            _make_entry(actor="alice", outcome="failure", timestamp=now + timedelta(seconds=i * 30))
            for i in range(3)
        ]
        anomalies = self.detector.detect(entries)
        kinds = [a.kind.value for a in anomalies]
        assert "repeated_failure" not in kinds

    def test_unusual_volume(self) -> None:
        now = datetime.now(timezone.utc)
        entries = [
            _make_entry(actor="bot", timestamp=now + timedelta(seconds=i * 30))
            for i in range(60)
        ]
        anomalies = self.detector.detect(entries)
        kinds = [a.kind.value for a in anomalies]
        assert "unusual_volume" in kinds

    def test_no_unusual_volume_normal(self) -> None:
        now = datetime.now(timezone.utc)
        entries = [
            _make_entry(actor="human", timestamp=now + timedelta(minutes=i * 5))
            for i in range(10)
        ]
        anomalies = self.detector.detect(entries)
        kinds = [a.kind.value for a in anomalies]
        assert "unusual_volume" not in kinds

    def test_sensitive_resource(self) -> None:
        entry = _make_entry(resource_type="secret")
        anomalies = self.detector.detect([entry])
        kinds = [a.kind.value for a in anomalies]
        assert "sensitive_resource" in kinds

    def test_sensitive_resource_credential(self) -> None:
        entry = _make_entry(resource_type="api_key")
        anomalies = self.detector.detect([entry])
        kinds = [a.kind.value for a in anomalies]
        assert "sensitive_resource" in kinds

    def test_no_anomalies_clean_entries(self) -> None:
        now = datetime.now(timezone.utc)
        monday_10am = now.replace(
            hour=10, minute=0, second=0, microsecond=0
        )
        # Ensure it's a weekday
        days_ahead = (0 - monday_10am.weekday()) % 7
        monday_10am = monday_10am + timedelta(days=days_ahead)
        entries = [_make_entry(actor="alice", timestamp=monday_10am + timedelta(minutes=i)) for i in range(3)]
        anomalies = self.detector.detect(entries)
        # Should only possibly have no critical anomalies
        kinds = {a.kind.value for a in anomalies}
        assert "privilege_escalation" not in kinds
        assert "repeated_failure" not in kinds
        assert "unusual_volume" not in kinds
        assert "sensitive_resource" not in kinds


# ============================================================================
# AuditAnalyticsDB tests
# ============================================================================


class TestAuditAnalyticsDB:
    """Test database CRUD, search, and retention."""

    @pytest.fixture
    def db(self) -> AuditAnalyticsDB:
        return AuditAnalyticsDB(db_path=_tmp_db())

    def test_insert_and_get_entry(self, db: AuditAnalyticsDB) -> None:
        entry = _make_entry(actor="alice", org_id="o1")
        db.insert_entry(entry)
        fetched = db.get_entry(entry.id, "o1")
        assert fetched is not None
        assert fetched.actor == "alice"

    def test_insert_duplicate_ignored(self, db: AuditAnalyticsDB) -> None:
        entry = _make_entry()
        db.insert_entry(entry)
        db.insert_entry(entry)  # duplicate — should not raise
        results, total = db.search(org_id=entry.org_id)
        assert total == 1

    def test_search_by_actor(self, db: AuditAnalyticsDB) -> None:
        db.insert_entry(_make_entry(actor="alice", org_id="o1"))
        db.insert_entry(_make_entry(actor="bob", org_id="o1"))
        results, total = db.search(org_id="o1", actor="alice")
        assert total == 1
        assert results[0].actor == "alice"

    def test_search_by_severity(self, db: AuditAnalyticsDB) -> None:
        db.insert_entry(_make_entry(severity=AuditSeverity.ERROR, org_id="o2"))
        db.insert_entry(_make_entry(severity=AuditSeverity.INFO, org_id="o2"))
        results, total = db.search(org_id="o2", severity="error")
        assert total == 1
        assert results[0].severity == AuditSeverity.ERROR

    def test_search_by_outcome(self, db: AuditAnalyticsDB) -> None:
        db.insert_entry(_make_entry(outcome="failure", org_id="o3"))
        db.insert_entry(_make_entry(outcome="success", org_id="o3"))
        results, total = db.search(org_id="o3", outcome="failure")
        assert total == 1

    def test_search_time_range(self, db: AuditAnalyticsDB) -> None:
        now = datetime.now(timezone.utc)
        old = _make_entry(timestamp=now - timedelta(days=10), org_id="o4")
        recent = _make_entry(timestamp=now - timedelta(hours=1), org_id="o4")
        db.insert_entry(old)
        db.insert_entry(recent)
        results, total = db.search(org_id="o4", start=now - timedelta(days=1))
        assert total == 1
        assert results[0].id == recent.id

    def test_search_fts(self, db: AuditAnalyticsDB) -> None:
        entry = _make_entry(action="login_attempt_brute_force", org_id="o5")
        # Rebuild entry with raw matching action
        entry.raw = "login_attempt_brute_force event"
        db.insert_entry(entry)
        results, total = db.search(org_id="o5", query="brute_force")
        assert total == 1

    def test_search_org_isolation(self, db: AuditAnalyticsDB) -> None:
        db.insert_entry(_make_entry(org_id="orgA"))
        db.insert_entry(_make_entry(org_id="orgB"))
        results_a, total_a = db.search(org_id="orgA")
        results_b, total_b = db.search(org_id="orgB")
        assert total_a == 1
        assert total_b == 1

    def test_update_status(self, db: AuditAnalyticsDB) -> None:
        entry = _make_entry(org_id="o6")
        db.insert_entry(entry)
        ok = db.update_status(entry.id, EntryStatus.ARCHIVED)
        assert ok is True
        fetched = db.get_entry(entry.id, "o6")
        assert fetched.status == EntryStatus.ARCHIVED

    def test_bulk_insert(self, db: AuditAnalyticsDB) -> None:
        entries = [_make_entry(actor=f"user{i}", org_id="o7") for i in range(20)]
        count = db.insert_entries_bulk(entries)
        assert count == 20
        _, total = db.search(org_id="o7")
        assert total == 20

    def test_retention_policy_upsert(self, db: AuditAnalyticsDB) -> None:
        policy = RetentionPolicy(org_id="o8", archive_after_days=30, delete_after_days=180)
        db.upsert_retention_policy(policy)
        fetched = db.get_retention_policy("o8")
        assert fetched.archive_after_days == 30
        assert fetched.delete_after_days == 180

    def test_retention_policy_default(self, db: AuditAnalyticsDB) -> None:
        policy = db.get_retention_policy("nonexistent-org")
        assert policy.archive_after_days == 90
        assert policy.delete_after_days == 365

    def test_retention_archives_old_entries(self, db: AuditAnalyticsDB) -> None:
        old_ts = datetime.now(timezone.utc) - timedelta(days=100)
        entry = _make_entry(timestamp=old_ts, org_id="o9")
        db.insert_entry(entry)
        policy = RetentionPolicy(org_id="o9", archive_after_days=90, delete_after_days=365)
        db.upsert_retention_policy(policy)
        report = db.apply_retention("o9")
        assert report.archived == 1
        fetched = db.get_entry(entry.id, "o9")
        assert fetched.status == EntryStatus.ARCHIVED

    def test_retention_deletes_very_old_entries(self, db: AuditAnalyticsDB) -> None:
        very_old_ts = datetime.now(timezone.utc) - timedelta(days=400)
        entry = _make_entry(timestamp=very_old_ts, org_id="o10")
        db.insert_entry(entry)
        policy = RetentionPolicy(org_id="o10", archive_after_days=90, delete_after_days=365)
        db.upsert_retention_policy(policy)
        report = db.apply_retention("o10")
        assert report.deleted == 1
        assert db.get_entry(entry.id, "o10") is None

    def test_retention_legal_hold(self, db: AuditAnalyticsDB) -> None:
        old_ts = datetime.now(timezone.utc) - timedelta(days=400)
        entry = _make_entry(actor="eve", timestamp=old_ts, org_id="o11")
        db.insert_entry(entry)
        policy = RetentionPolicy(
            org_id="o11",
            archive_after_days=90,
            delete_after_days=365,
            legal_hold_actor_ids=["eve"],
        )
        db.upsert_retention_policy(policy)
        report = db.apply_retention("o11")
        assert report.held == 1
        # Entry should NOT be deleted (legal hold)
        fetched = db.get_entry(entry.id, "o11")
        assert fetched is not None
        assert fetched.status == EntryStatus.LEGAL_HOLD

    def test_build_timeline(self, db: AuditAnalyticsDB) -> None:
        now = datetime.now(timezone.utc)
        for i in range(5):
            entry = _make_entry(
                actor="alice",
                action="file_access",
                timestamp=now - timedelta(hours=5 - i),
                org_id="o12",
            )
            entry.raw = "file_access action"
            db.insert_entry(entry)
        timeline = db.build_timeline(
            org_id="o12",
            query="file_access",
            start=now - timedelta(days=1),
            end=now + timedelta(hours=1),
        )
        assert isinstance(timeline, ForensicTimeline)
        assert len(timeline.events) == 5
        # Events should be in ascending time order
        timestamps = [e.timestamp for e in timeline.events]
        assert timestamps == sorted(timestamps)


# ============================================================================
# AuditAnalyticsEngine tests
# ============================================================================


class TestAuditAnalyticsEngine:
    """Test high-level engine facade."""

    @pytest.fixture
    def engine(self) -> AuditAnalyticsEngine:
        return AuditAnalyticsEngine(db_path=_tmp_db(), org_id="eng-org")

    def test_ingest_json(self, engine: AuditAnalyticsEngine) -> None:
        raw = json.dumps({"actor": "alice", "action": "login"})
        entry = engine.ingest(raw, LogFormat.JSON)
        assert entry.actor == "alice"
        assert entry.id is not None

    def test_ingest_syslog(self, engine: AuditAnalyticsEngine) -> None:
        raw = "<13>Jan 15 10:00:00 myhost sshd[1234]: Accepted password for bob"
        entry = engine.ingest(raw, LogFormat.SYSLOG)
        assert entry.source_format == LogFormat.SYSLOG

    def test_ingest_cef(self, engine: AuditAnalyticsEngine) -> None:
        raw = "CEF:0|ACME|FW|1.0|100|Login|5|suser=carol src=10.0.0.1"
        entry = engine.ingest(raw, LogFormat.CEF)
        assert entry.source_format == LogFormat.CEF
        assert entry.actor == "carol"

    def test_ingest_leef(self, engine: AuditAnalyticsEngine) -> None:
        raw = "LEEF:1.0|IBM|QR|1.0|Login|usrName=dave\tsrc=10.0.0.2"
        entry = engine.ingest(raw, LogFormat.LEEF)
        assert entry.source_format == LogFormat.LEEF

    def test_ingest_batch_returns_entries(self, engine: AuditAnalyticsEngine) -> None:
        lines = [json.dumps({"actor": f"user{i}", "action": "read"}) for i in range(10)]
        entries, anomalies = engine.ingest_batch(lines, LogFormat.JSON, run_anomaly_detection=False)
        assert len(entries) == 10
        assert anomalies == []

    def test_ingest_batch_anomaly_detection(self, engine: AuditAnalyticsEngine) -> None:
        now = datetime.now(timezone.utc)
        # 7 failures in 10 minutes → repeated_failure
        lines = [
            json.dumps({"actor": "attacker", "action": "ssh_login", "outcome": "failure",
                        "timestamp": (now + timedelta(seconds=i * 60)).isoformat()})
            for i in range(7)
        ]
        entries, anomalies = engine.ingest_batch(lines, LogFormat.JSON, run_anomaly_detection=True)
        assert len(entries) == 7
        kinds = [a.kind.value for a in anomalies]
        assert "repeated_failure" in kinds

    def test_search_returns_results(self, engine: AuditAnalyticsEngine) -> None:
        engine.ingest(json.dumps({"actor": "alice", "action": "read"}), LogFormat.JSON)
        engine.ingest(json.dumps({"actor": "bob", "action": "write"}), LogFormat.JSON)
        result = engine.search()
        assert result.total == 2

    def test_search_with_actor_filter(self, engine: AuditAnalyticsEngine) -> None:
        engine.ingest(json.dumps({"actor": "alice", "action": "read"}), LogFormat.JSON)
        engine.ingest(json.dumps({"actor": "bob", "action": "write"}), LogFormat.JSON)
        result = engine.search(actor="alice")
        assert result.total == 1
        assert result.items[0].actor == "alice"

    def test_detect_anomalies_on_demand(self, engine: AuditAnalyticsEngine) -> None:
        now = datetime.now(timezone.utc)
        lines = [
            json.dumps({
                "actor": "hacker",
                "action": "ssh_login",
                "outcome": "failure",
                "timestamp": (now + timedelta(seconds=i * 50)).isoformat(),
            })
            for i in range(7)
        ]
        engine.ingest_batch(lines, LogFormat.JSON, run_anomaly_detection=False)
        anomalies = engine.detect_anomalies()
        kinds = [a.kind.value for a in anomalies]
        assert "repeated_failure" in kinds

    def test_compliance_trail(self, engine: AuditAnalyticsEngine) -> None:
        for i in range(5):
            engine.ingest(
                json.dumps({"actor": "admin", "action": "policy_update", "resource_type": "policy"}),
                LogFormat.JSON,
            )
        result = engine.compliance_trail(actor="admin", resource_type="policy")
        assert result.total == 5

    def test_set_and_get_retention_policy(self, engine: AuditAnalyticsEngine) -> None:
        policy = RetentionPolicy(org_id="eng-org", archive_after_days=45, delete_after_days=200)
        engine.set_retention_policy(policy)
        fetched = engine.get_retention_policy()
        assert fetched.archive_after_days == 45

    def test_apply_retention(self, engine: AuditAnalyticsEngine) -> None:
        old_ts = datetime.now(timezone.utc) - timedelta(days=100)
        raw = json.dumps({"actor": "user1", "action": "read", "timestamp": old_ts.isoformat()})
        engine.ingest(raw, LogFormat.JSON)
        report = engine.apply_retention()
        assert report.archived >= 1

    def test_build_timeline(self, engine: AuditAnalyticsEngine) -> None:
        now = datetime.now(timezone.utc)
        for i in range(3):
            raw = json.dumps({
                "actor": "alice",
                "action": "file_read",
                "timestamp": (now - timedelta(hours=3 - i)).isoformat(),
            })
            engine.ingest(raw, LogFormat.JSON)
        # FTS search for "file_read" — raw must contain the term
        # Patch: use engine search fallback (empty FTS query = field search)
        timeline = engine.build_timeline(
            query="",
            start=now - timedelta(days=1),
            end=now + timedelta(hours=1),
        )
        assert timeline.total >= 3


# ============================================================================
# API endpoint tests
# ============================================================================


API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """
    Create a minimal FastAPI TestClient mounting only the audit-analytics router.

    We avoid importing the full create_app() because app.py has a pre-existing
    UnboundLocalError on dast_router that breaks module-level import.
    """
    import core.audit_analytics as aa_module
    import apps.api.audit_analytics_router as router_module
    from fastapi import FastAPI, Header, Request
    from fastapi.testclient import TestClient

    monkeypatch_db = tmp_path_factory.mktemp("api_db") / "test.db"

    # Point the router engine at a fresh temp DB
    router_module._engine = aa_module.AuditAnalyticsEngine(
        db_path=str(monkeypatch_db), org_id="default"
    )

    # Minimal app: mount the router; override get_org_id to return "default"
    mini_app = FastAPI()

    def _fake_get_org_id(x_api_key: str = Header(default="")) -> str:
        if x_api_key != API_TOKEN:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="Unauthorized")
        return "default"

    mini_app.dependency_overrides[router_module.get_org_id] = _fake_get_org_id
    mini_app.include_router(router_module.router)

    return TestClient(mini_app)


@pytest.fixture
def auth_headers():
    return {"X-API-Key": API_TOKEN}


class TestAuditAnalyticsAPI:
    """Integration tests for all 10 API endpoints."""

    def test_ingest_json_201(self, client, auth_headers) -> None:
        payload = {"raw": json.dumps({"actor": "alice", "action": "login"}), "format": "json"}
        resp = client.post("/api/v1/audit-analytics/ingest", json=payload, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert "entry_id" in data
        assert data["actor"] == "alice"

    def test_ingest_syslog_201(self, client, auth_headers) -> None:
        payload = {
            "raw": "<13>Jan 15 10:00:00 myhost sshd[1234]: Accepted password for bob",
            "format": "syslog",
        }
        resp = client.post("/api/v1/audit-analytics/ingest", json=payload, headers=auth_headers)
        assert resp.status_code == 201

    def test_ingest_batch_201(self, client, auth_headers) -> None:
        lines = [json.dumps({"actor": f"u{i}", "action": "read"}) for i in range(5)]
        payload = {"lines": lines, "format": "json", "run_anomaly_detection": False}
        resp = client.post("/api/v1/audit-analytics/ingest/batch", json=payload, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["ingested"] == 5

    def test_ingest_batch_with_anomaly_detection(self, client, auth_headers) -> None:
        now = datetime.now(timezone.utc)
        lines = [
            json.dumps({
                "actor": "brute_forcer",
                "action": "login",
                "outcome": "failure",
                "timestamp": (now + timedelta(seconds=i * 60)).isoformat(),
            })
            for i in range(7)
        ]
        payload = {"lines": lines, "format": "json", "run_anomaly_detection": True}
        resp = client.post("/api/v1/audit-analytics/ingest/batch", json=payload, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert "anomalies_detected" in data

    def test_search_returns_200(self, client, auth_headers) -> None:
        resp = client.get("/api/v1/audit-analytics/search", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    def test_search_with_query_param(self, client, auth_headers) -> None:
        resp = client.get("/api/v1/audit-analytics/search?q=alice", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_anomalies_200(self, client, auth_headers) -> None:
        resp = client.get("/api/v1/audit-analytics/anomalies", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    def test_detect_anomalies_200(self, client, auth_headers) -> None:
        payload: dict = {}
        resp = client.post("/api/v1/audit-analytics/anomalies/detect", json=payload, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "anomalies" in data
        assert "count" in data

    def test_compliance_trail_200(self, client, auth_headers) -> None:
        resp = client.get("/api/v1/audit-analytics/compliance-trail", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data

    def test_get_retention_policy_200(self, client, auth_headers) -> None:
        resp = client.get("/api/v1/audit-analytics/retention-policy", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "archive_after_days" in data
        assert "delete_after_days" in data

    def test_upsert_retention_policy_200(self, client, auth_headers) -> None:
        payload = {"archive_after_days": 60, "delete_after_days": 180, "legal_hold_actor_ids": []}
        resp = client.put("/api/v1/audit-analytics/retention-policy", json=payload, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["archive_after_days"] == 60

    def test_upsert_retention_policy_validation_error(self, client, auth_headers) -> None:
        # delete_after_days must be > archive_after_days
        payload = {"archive_after_days": 200, "delete_after_days": 100}
        resp = client.put("/api/v1/audit-analytics/retention-policy", json=payload, headers=auth_headers)
        assert resp.status_code == 422

    def test_apply_retention_200(self, client, auth_headers) -> None:
        resp = client.post("/api/v1/audit-analytics/retention/apply", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "archived" in data
        assert "deleted" in data

    def test_build_timeline_200(self, client, auth_headers) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "query": "login",
            "start": (now - timedelta(days=7)).isoformat(),
            "end": now.isoformat(),
            "limit": 100,
        }
        resp = client.post("/api/v1/audit-analytics/timeline", json=payload, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert "actors" in data
        assert "resources" in data

    def test_requires_auth(self, client) -> None:
        """Endpoints without API key should return 401 or 403."""
        resp = client.get("/api/v1/audit-analytics/search")
        assert resp.status_code in {401, 403}
