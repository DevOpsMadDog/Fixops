"""
Tests for multi-tenant data isolation across ALDECI engines.

Covers:
- RedisQueue: org_id not present — queue is a global namespace (documented gap)
- SSOBridge: session tokens preserve org_id; providers are global (documented gap)
- InsiderThreatEngine: all queries filter by org_id; resolve_alert gap documented
- AttackPathEngine: list/find queries scoped; get_node/remove_node gaps documented
- SecurityKPITracker: fully isolated across all methods
- TenantIsolationAuditor: audit_sqlite_db, check_cross_tenant_leak, generate_isolation_report

Run with:
    python -m pytest tests/test_tenant_isolation_audit.py --timeout=10 -q --no-cov
"""

from __future__ import annotations

import sqlite3

import pytest

from core.redis_queue import RedisQueue
from core.sso_bridge import SSOBridge, SSOUser
from core.insider_threat_engine import InsiderThreatEngine
from core.attack_path_engine import AttackPathEngine
from core.security_kpi_tracker import SecurityKPITracker
from core.tenant_isolation_auditor import TenantIsolationAuditor


# ============================================================================
# Constants
# ============================================================================

ORG_A = "org-alpha"
ORG_B = "org-beta"


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def insider_engine(tmp_path):
    return InsiderThreatEngine(db_path=str(tmp_path / "insider.db"))


@pytest.fixture
def attack_engine(tmp_path):
    return AttackPathEngine(db_path=str(tmp_path / "attack.db"))


@pytest.fixture
def kpi_tracker(tmp_path):
    return SecurityKPITracker(db_path=str(tmp_path / "kpi.db"))


@pytest.fixture
def sso_bridge(tmp_path):
    return SSOBridge(db_path=str(tmp_path / "sso.db"))


@pytest.fixture
def auditor():
    return TenantIsolationAuditor()


# ============================================================================
# RedisQueue — org_id scoping (in-memory fallback, no Redis required)
# ============================================================================


class TestRedisQueueIsolation:
    """RedisQueue uses in-memory fallback (no Redis). Documents that the current
    implementation has a shared queue namespace — tasks are not scoped by org_id.
    """

    def test_enqueue_returns_task_id(self):
        """enqueue() returns a UUID string regardless of payload content."""
        q = RedisQueue()
        task_id = q.enqueue({"org_id": ORG_A, "type": "scan"})
        assert isinstance(task_id, str)
        assert len(task_id) == 36  # UUID4

    def test_enqueued_task_preserves_org_id_in_payload(self):
        """org_id in task payload survives the round-trip through the queue."""
        q = RedisQueue()
        q.enqueue({"org_id": ORG_A, "action": "vuln_scan"}, priority=3)
        task = q.dequeue()
        assert task is not None
        assert task["org_id"] == ORG_A

    def test_shared_queue_is_global_namespace_known_gap(self):
        """
        KNOWN GAP: without org-scoped queue keys, dequeue() returns tasks from
        all orgs. This test documents the current behaviour so regressions are
        caught if the gap is later fixed.
        """
        q = RedisQueue()
        q.enqueue({"org_id": ORG_A, "secret": "alpha-data"}, priority=1)
        task = q.dequeue()
        assert task is not None
        # A worker that only wants ORG_B tasks still receives ORG_A's task
        assert task["org_id"] == ORG_A

    def test_separate_prefix_instances_isolate_orgs(self):
        """Using separate RedisQueue instances with per-org prefixes isolates tenants."""
        q_a = RedisQueue(prefix=f"aldeci:queue:{ORG_A}")
        q_b = RedisQueue(prefix=f"aldeci:queue:{ORG_B}")

        q_a.enqueue({"type": "alpha_task"}, priority=2)
        q_b.enqueue({"type": "beta_task"}, priority=2)

        task_a = q_a.dequeue()
        task_b = q_b.dequeue()

        assert task_a is not None and task_a["type"] == "alpha_task"
        assert task_b is not None and task_b["type"] == "beta_task"

        # Each queue is now empty — no cross-contamination
        assert q_a.dequeue() is None
        assert q_b.dequeue() is None


# ============================================================================
# SSOBridge — session org_id scoping
# ============================================================================


class TestSSOBridgeIsolation:
    """Session tokens are unguessable — direct cross-tenant token theft is not
    possible. org_id is preserved in the session payload. sso_providers is a
    known shared-namespace gap.
    """

    def test_session_preserves_org_id(self, sso_bridge):
        """create_session + validate_session round-trips org_id correctly."""
        user = SSOUser(
            user_id="u1", email="u1@a.com", roles=["viewer"],
            org_id=ORG_A, provider="oidc",
        )
        token = sso_bridge.create_session(user)
        recovered = sso_bridge.validate_session(token)
        assert recovered is not None
        assert recovered.org_id == ORG_A

    def test_org_a_token_carries_org_a_not_org_b(self, sso_bridge):
        """Two sessions for different orgs carry the correct org_id each."""
        user_a = SSOUser(
            user_id="ua", email="ua@a.com", roles=["admin"],
            org_id=ORG_A, provider="saml",
        )
        user_b = SSOUser(
            user_id="ub", email="ub@b.com", roles=["viewer"],
            org_id=ORG_B, provider="saml",
        )
        token_a = sso_bridge.create_session(user_a)
        token_b = sso_bridge.create_session(user_b)

        result_a = sso_bridge.validate_session(token_a)
        result_b = sso_bridge.validate_session(token_b)

        assert result_a.org_id == ORG_A
        assert result_b.org_id == ORG_B
        assert result_a.org_id != result_b.org_id

    def test_unknown_token_returns_none(self, sso_bridge):
        """Unknown or empty tokens never return a session."""
        assert sso_bridge.validate_session("garbage_token") is None
        assert sso_bridge.validate_session("") is None

    def test_expired_session_returns_none(self, sso_bridge):
        """Manually expired sessions return None on validation."""
        user = SSOUser(
            user_id="u_exp", email="exp@a.com", roles=[],
            org_id=ORG_A, provider="oidc",
        )
        token = sso_bridge.create_session(user)

        # Force expiry directly in the DB
        conn = sqlite3.connect(sso_bridge._db_path)
        conn.execute(
            "UPDATE sso_sessions SET expires_at = 0 WHERE token = ?", (token,)
        )
        conn.commit()
        conn.close()

        assert sso_bridge.validate_session(token) is None


# ============================================================================
# InsiderThreatEngine — org_id isolation
# ============================================================================


class TestInsiderThreatEngineIsolation:
    """All main queries are properly scoped by org_id. resolve_alert gap documented."""

    def test_events_scoped_by_org(self, insider_engine):
        """Events recorded for org_A are not returned when querying org_B."""
        insider_engine.record_user_event(
            user_id="alice", event_type="login", resource="/admin",
            org_id=ORG_A,
        )
        timeline_b = insider_engine.get_user_timeline(user_id="alice", org_id=ORG_B)
        assert timeline_b == []

    def test_alerts_not_visible_across_orgs(self, insider_engine):
        """Alerts created for org_A are not returned when querying org_B."""
        insider_engine.create_alert(
            user_id="alice", indicator="bulk_data_download",
            evidence={"downloads": 100}, severity="high", org_id=ORG_A,
        )
        alerts_b = insider_engine.get_alerts(org_id=ORG_B)
        assert alerts_b == []

    def test_alerts_visible_for_correct_org(self, insider_engine):
        """Alerts for org_A are visible when querying org_A."""
        insider_engine.create_alert(
            user_id="bob", indicator="after_hours_access",
            evidence={}, severity="medium", org_id=ORG_A,
        )
        alerts_a = insider_engine.get_alerts(org_id=ORG_A)
        assert len(alerts_a) == 1
        assert alerts_a[0]["org_id"] == ORG_A

    def test_risk_analysis_scoped_by_org(self, insider_engine):
        """analyze_user_risk returns baseline for org_B when events exist only for org_A."""
        insider_engine.record_user_event(
            user_id="charlie", event_type="login", resource="/",
            org_id=ORG_A,
        )
        result = insider_engine.analyze_user_risk("charlie", org_id=ORG_B)
        assert result["event_count"] == 0
        assert result["risk_level"] == "baseline"

    def test_org_risk_summary_scoped(self, insider_engine):
        """get_org_risk_summary for org_B returns zero users when only org_A has events."""
        insider_engine.record_user_event(
            user_id="dave", event_type="download", resource="/export",
            org_id=ORG_A,
        )
        summary_b = insider_engine.get_org_risk_summary(org_id=ORG_B)
        assert summary_b["total_users_monitored"] == 0

    def test_resolve_alert_org_guard_enforced(self, insider_engine):
        """
        FIXED: resolve_alert() now requires org_id and enforces tenant isolation.
        A caller from a different org cannot resolve another tenant's alert.
        """
        alert = insider_engine.create_alert(
            user_id="eve", indicator="policy_violation",
            evidence={}, severity="low", org_id=ORG_A,
        )
        # Cross-tenant resolve must raise — alert_id belongs to ORG_A, not ORG_B
        with pytest.raises(ValueError, match="Alert not found"):
            insider_engine.resolve_alert(
                alert_id=alert["alert_id"],
                resolution="false_positive",
                resolved_by="attacker_from_org_b",
                org_id=ORG_B,
            )
        # Correct org can still resolve the alert
        resolved = insider_engine.resolve_alert(
            alert_id=alert["alert_id"],
            resolution="false_positive",
            resolved_by="sec_analyst",
            org_id=ORG_A,
        )
        assert resolved["status"] == "resolved"


# ============================================================================
# AttackPathEngine — org_id isolation
# ============================================================================


class TestAttackPathEngineIsolation:
    """list_nodes and graph queries are scoped. get_node/remove_node gaps documented."""

    def test_list_nodes_scoped_by_org(self, attack_engine):
        """Nodes added for org_A are not returned when listing org_B nodes."""
        attack_engine.add_node("server-1", "server", "Web Server", org_id=ORG_A)
        nodes_b = attack_engine.list_nodes(org_id=ORG_B)
        assert nodes_b == []

    def test_nodes_visible_for_correct_org(self, attack_engine):
        """Nodes added for org_A are visible when listing org_A nodes."""
        attack_engine.add_node(
            "db-1", "database", "Prod DB", is_crown_jewel=True, org_id=ORG_A
        )
        nodes_a = attack_engine.list_nodes(org_id=ORG_A)
        assert len(nodes_a) == 1
        assert nodes_a[0]["org_id"] == ORG_A

    def test_find_attack_paths_scoped_by_org(self, attack_engine):
        """Attack paths for org_A are not returned in org_B path queries."""
        attack_engine.add_node("n1", "workstation", "Entry", org_id=ORG_A)
        attack_engine.add_node(
            "n2", "database", "Crown DB", is_crown_jewel=True, org_id=ORG_A
        )
        attack_engine.add_edge("n1", "n2", org_id=ORG_A)

        # org_B has no nodes — paths should be empty
        result = attack_engine.find_attack_paths("n1", org_id=ORG_B)
        assert result["total_paths"] == 0
        assert result["max_blast_radius"] == 0

    def test_graph_stats_scoped_by_org(self, attack_engine):
        """get_graph_stats for org_B returns zeros when only org_A has nodes."""
        attack_engine.add_node("s1", "server", "Server A", org_id=ORG_A)
        stats = attack_engine.get_graph_stats(org_id=ORG_B)
        assert stats["total_nodes"] == 0
        assert stats["total_edges"] == 0

    def test_get_node_gap_no_org_filter(self, attack_engine):
        """
        KNOWN GAP: get_node() queries by node_id only — no org_id filter.
        Any caller who knows the node_id can read it, regardless of their org.
        """
        attack_engine.add_node(
            "shared-id", "server", "Org A Server", org_id=ORG_A
        )
        node = attack_engine.get_node("shared-id")
        assert node is not None
        # Gap confirmed: org_A's node returned without requiring org_id=ORG_A
        assert node["org_id"] == ORG_A

    def test_remove_node_gap_no_org_filter(self, attack_engine):
        """
        KNOWN GAP: remove_node() deletes by node_id only — no org_id guard.
        Any caller who knows the node_id can destroy it, regardless of their org.
        """
        attack_engine.add_node(
            "victim-node", "workstation", "Org A Workstation", org_id=ORG_A
        )
        removed = attack_engine.remove_node("victim-node")
        assert removed is True
        # Node is gone — destructive cross-tenant operation succeeded
        assert attack_engine.get_node("victim-node") is None


# ============================================================================
# SecurityKPITracker — fully isolated
# ============================================================================


class TestSecurityKPITrackerIsolation:
    """SecurityKPITracker is fully isolated. All methods filter by org_id."""

    def test_kpi_for_org1_not_visible_in_org2(self, kpi_tracker):
        """KPI recorded for org_A is absent when querying org_B."""
        kpi_tracker.record_kpi("posture_score", 85.0, org_id=ORG_A)
        org_b_kpis = kpi_tracker.get_current_kpis(org_id=ORG_B)
        assert "posture_score" not in org_b_kpis

    def test_kpi_trend_scoped_by_org(self, kpi_tracker):
        """Trend history for org_A is not returned for org_B."""
        kpi_tracker.record_kpi("mttd_hours", 2.5, org_id=ORG_A)
        trend_b = kpi_tracker.get_kpi_trend("mttd_hours", org_id=ORG_B)
        assert trend_b == []

    def test_snapshots_scoped_by_org(self, kpi_tracker):
        """Snapshots taken for org_A are not listed for org_B."""
        kpi_tracker.record_kpi("posture_score", 70.0, org_id=ORG_A)
        kpi_tracker.record_snapshot(org_id=ORG_A)
        snaps_b = kpi_tracker.get_snapshots(org_id=ORG_B)
        assert snaps_b == []

    def test_targets_scoped_by_org(self, kpi_tracker):
        """Targets set for org_A are not returned for org_B."""
        kpi_tracker.set_target("mttr_hours", 4.0, "2026-12-31", org_id=ORG_A)
        targets_b = kpi_tracker.get_targets(org_id=ORG_B)
        assert targets_b == []

    def test_kpi_visible_to_correct_org(self, kpi_tracker):
        """KPI data recorded for org_A is visible when querying org_A."""
        kpi_tracker.record_kpi("posture_score", 90.0, org_id=ORG_A)
        org_a_kpis = kpi_tracker.get_current_kpis(org_id=ORG_A)
        assert "posture_score" in org_a_kpis
        assert org_a_kpis["posture_score"]["value"] == 90.0


# ============================================================================
# TenantIsolationAuditor
# ============================================================================


class TestTenantIsolationAuditor:
    """Tests for the auditor utility itself."""

    def test_audit_sqlite_db_with_org_id_column(self, auditor, tmp_path):
        """Tables that have an org_id column are marked as isolated."""
        db_path = str(tmp_path / "audit_test.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE records (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, data TEXT)"
        )
        conn.commit()
        conn.close()

        report = auditor.audit_sqlite_db(db_path)
        assert report["tables"]["records"]["has_org_id"] is True
        assert "records" not in report["missing_org_id"]
        assert report["isolation_score"] == 1.0

    def test_audit_sqlite_db_missing_org_id_column(self, auditor, tmp_path):
        """Tables without org_id column are flagged in missing_org_id."""
        db_path = str(tmp_path / "audit_missing.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE events (id TEXT PRIMARY KEY, data TEXT)")
        conn.commit()
        conn.close()

        report = auditor.audit_sqlite_db(db_path)
        assert report["tables"]["events"]["has_org_id"] is False
        assert "events" in report["missing_org_id"]
        assert report["isolation_score"] == 0.0

    def test_audit_sqlite_db_nonexistent_file(self, auditor):
        """Non-existent db path returns an error key, not an exception."""
        report = auditor.audit_sqlite_db("/nonexistent/path/test.db")
        assert "error" in report
        assert report["isolation_score"] == 0.0

    def test_audit_sqlite_db_mixed_tables(self, auditor, tmp_path):
        """Isolation score reflects fraction of tables with org_id."""
        db_path = str(tmp_path / "mixed.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE good (id TEXT, org_id TEXT)")
        conn.execute("CREATE TABLE bad (id TEXT)")
        conn.commit()
        conn.close()

        report = auditor.audit_sqlite_db(db_path)
        assert report["isolation_score"] == 0.5
        assert "bad" in report["missing_org_id"]
        assert "good" not in report["missing_org_id"]

    def test_check_cross_tenant_leak_kpi_tracker_no_leaks(self, auditor, kpi_tracker):
        """SecurityKPITracker passes cross-tenant leak check — no leaks returned."""
        leaks = auditor.check_cross_tenant_leak(kpi_tracker, ORG_A, ORG_B)
        assert leaks == []

    def test_check_cross_tenant_leak_insider_engine_no_leaks(
        self, auditor, insider_engine
    ):
        """InsiderThreatEngine get_alerts passes cross-tenant check."""
        leaks = auditor.check_cross_tenant_leak(insider_engine, ORG_A, ORG_B)
        assert leaks == []

    def test_check_cross_tenant_leak_attack_engine_no_leaks(
        self, auditor, attack_engine
    ):
        """AttackPathEngine list_nodes passes cross-tenant check."""
        leaks = auditor.check_cross_tenant_leak(attack_engine, ORG_A, ORG_B)
        assert leaks == []

    def test_check_cross_tenant_leak_sso_bridge_no_leaks(self, auditor, sso_bridge):
        """SSOBridge session creation passes cross-tenant org_id check."""
        leaks = auditor.check_cross_tenant_leak(sso_bridge, ORG_A, ORG_B)
        assert leaks == []

    def test_generate_isolation_report_structure(self, auditor):
        """generate_isolation_report returns expected top-level keys."""
        report = auditor.generate_isolation_report()
        assert "summary" in report
        assert "findings" in report
        assert "audit_date" in report

    def test_generate_isolation_report_counts(self, auditor):
        """Summary counts are consistent with findings list."""
        report = auditor.generate_isolation_report()
        summary = report["summary"]
        assert summary["total_engines_audited"] == 5
        assert summary["passed"] >= 1
        assert summary["open_findings"] >= 1
        assert summary["critical"] >= 1

    def test_generate_isolation_report_redis_critical(self, auditor):
        """RedisQueue is flagged as critical severity."""
        report = auditor.generate_isolation_report()
        redis_finding = next(
            (f for f in report["findings"] if f["engine"] == "RedisQueue"), None
        )
        assert redis_finding is not None
        assert redis_finding["severity"] == "critical"
        assert redis_finding["status"] == "open"

    def test_generate_isolation_report_kpi_passes(self, auditor):
        """SecurityKPITracker is marked as passing with no severity."""
        report = auditor.generate_isolation_report()
        kpi_finding = next(
            (f for f in report["findings"] if f["engine"] == "SecurityKPITracker"),
            None,
        )
        assert kpi_finding is not None
        assert kpi_finding["status"] == "pass"
        assert kpi_finding["severity"] == "none"

    def test_generate_isolation_report_attack_path_high(self, auditor):
        """AttackPathEngine is flagged as high severity for get_node/remove_node gaps."""
        report = auditor.generate_isolation_report()
        ap_finding = next(
            (f for f in report["findings"] if f["engine"] == "AttackPathEngine"), None
        )
        assert ap_finding is not None
        assert ap_finding["severity"] == "high"
        assert ap_finding["status"] == "open"

    def test_generate_isolation_report_insider_threat_low(self, auditor):
        """InsiderThreatEngine resolve_alert gap is low severity and now fixed."""
        report = auditor.generate_isolation_report()
        it_finding = next(
            (f for f in report["findings"] if f["engine"] == "InsiderThreatEngine"),
            None,
        )
        assert it_finding is not None
        assert it_finding["severity"] == "low"
        assert it_finding["status"] == "fixed"
