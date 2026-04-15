"""Tests for VulnWorkflowEngine — 33 tests covering full lifecycle."""

from __future__ import annotations

import threading
import pytest

from core.vuln_workflow_engine import VulnWorkflowEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    """Fresh engine instance per test."""
    db_path = str(tmp_path / "test_vuln_workflow.db")
    eng = VulnWorkflowEngine.__new__(VulnWorkflowEngine)
    eng.org_id = "org_test"
    eng.db_path = db_path
    eng._lock = threading.RLock()
    eng._init_db()
    return eng


@pytest.fixture()
def engine2(tmp_path):
    """Second org engine for isolation tests."""
    db_path = str(tmp_path / "test_vuln_workflow2.db")
    eng = VulnWorkflowEngine.__new__(VulnWorkflowEngine)
    eng.org_id = "org_other"
    eng.db_path = db_path
    eng._lock = threading.RLock()
    eng._init_db()
    return eng


ORG = "org_test"
ORG2 = "org_other"


def _make_ticket(engine, **kwargs):
    data = {
        "title": "CVE-2024-1234 in nginx",
        "severity": "high",
        "priority": "p2",
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.1,
    }
    data.update(kwargs)
    return engine.create_ticket(ORG, data)


# ---------------------------------------------------------------------------
# Ticket CRUD
# ---------------------------------------------------------------------------

class TestTicketCRUD:
    def test_create_ticket_minimal(self, engine):
        t = engine.create_ticket(ORG, {"title": "Test vuln"})
        assert t["id"]
        assert t["status"] == "open"
        assert t["org_id"] == ORG
        assert t["due_date"] is not None

    def test_create_ticket_full(self, engine):
        t = _make_ticket(engine, assignee_id="user1", assignee_team="red-team", tags=["nginx", "rce"])
        assert t["cve_id"] == "CVE-2024-1234"
        assert t["cvss_score"] == 8.1
        assert "nginx" in t["tags"]

    def test_create_ticket_missing_title(self, engine):
        with pytest.raises(ValueError, match="title"):
            engine.create_ticket(ORG, {"severity": "high"})

    def test_create_ticket_invalid_severity(self, engine):
        with pytest.raises(ValueError, match="severity"):
            engine.create_ticket(ORG, {"title": "x", "severity": "extreme"})

    def test_create_ticket_invalid_priority(self, engine):
        with pytest.raises(ValueError, match="priority"):
            engine.create_ticket(ORG, {"title": "x", "priority": "p99"})

    def test_list_tickets(self, engine):
        _make_ticket(engine)
        _make_ticket(engine, title="Another vuln", severity="critical")
        tickets = engine.list_tickets(ORG)
        assert len(tickets) == 2

    def test_get_ticket_with_comments(self, engine):
        t = _make_ticket(engine)
        result = engine.get_ticket(ORG, t["id"])
        assert result is not None
        assert "comments" in result
        assert isinstance(result["comments"], list)

    def test_get_ticket_not_found(self, engine):
        result = engine.get_ticket(ORG, "no-such-id")
        assert result is None

    def test_update_ticket_status(self, engine):
        t = _make_ticket(engine)
        updated = engine.update_ticket(ORG, t["id"], {"status": "in_progress"})
        assert updated["status"] == "in_progress"

    def test_update_ticket_logs_status_comment(self, engine):
        t = _make_ticket(engine)
        engine.update_ticket(ORG, t["id"], {"status": "in_progress"})
        result = engine.get_ticket(ORG, t["id"])
        comments = result["comments"]
        assert any(c["comment_type"] == "status_change" for c in comments)

    def test_update_ticket_resolution_sets_date(self, engine):
        t = _make_ticket(engine)
        updated = engine.update_ticket(ORG, t["id"], {"status": "resolved"})
        assert updated["resolved_date"] is not None

    def test_update_ticket_not_found(self, engine):
        result = engine.update_ticket(ORG, "no-such-id", {"status": "resolved"})
        assert result is None


# ---------------------------------------------------------------------------
# SLA auto due-date
# ---------------------------------------------------------------------------

class TestSLADueDate:
    def test_p1_sla_7_days(self, engine):
        t = engine.create_ticket(ORG, {"title": "Critical", "severity": "critical", "priority": "p1"})
        # Due date should be ~7 days out
        from datetime import datetime, timezone, timedelta
        due = datetime.fromisoformat(t["due_date"].replace("Z", "+00:00"))
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        delta = due - datetime.now(timezone.utc)
        assert 5 <= delta.days <= 8

    def test_p4_sla_180_days(self, engine):
        t = engine.create_ticket(ORG, {"title": "Low", "severity": "low", "priority": "p4"})
        from datetime import datetime, timezone
        due = datetime.fromisoformat(t["due_date"].replace("Z", "+00:00"))
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        delta = due - datetime.now(timezone.utc)
        assert delta.days >= 170

    def test_custom_sla_overrides_default(self, engine):
        engine.set_sla_config(ORG, "high", sla_days=14, escalation_days=3, owner_team="sec")
        t = engine.create_ticket(ORG, {"title": "High vuln", "severity": "high", "priority": "p2"})
        from datetime import datetime, timezone
        due = datetime.fromisoformat(t["due_date"].replace("Z", "+00:00"))
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        delta = due - datetime.now(timezone.utc)
        assert 12 <= delta.days <= 15

    def test_explicit_due_date_not_overridden(self, engine):
        t = engine.create_ticket(ORG, {
            "title": "Custom due",
            "due_date": "2099-12-31T00:00:00+00:00",
        })
        assert "2099" in t["due_date"]


# ---------------------------------------------------------------------------
# Overdue detection
# ---------------------------------------------------------------------------

class TestOverdueDetection:
    def test_past_due_date_is_overdue(self, engine):
        t = engine.create_ticket(ORG, {
            "title": "Overdue vuln",
            "due_date": "2020-01-01T00:00:00+00:00",
        })
        result = engine.get_ticket(ORG, t["id"])
        assert result["overdue"] is True

    def test_future_due_date_not_overdue(self, engine):
        t = engine.create_ticket(ORG, {"title": "Future vuln"})
        result = engine.get_ticket(ORG, t["id"])
        assert result["overdue"] is False

    def test_resolved_ticket_not_overdue(self, engine):
        t = engine.create_ticket(ORG, {
            "title": "Old resolved",
            "due_date": "2020-01-01T00:00:00+00:00",
        })
        engine.update_ticket(ORG, t["id"], {"status": "resolved"})
        result = engine.get_ticket(ORG, t["id"])
        assert result["overdue"] is False

    def test_list_overdue_only(self, engine):
        engine.create_ticket(ORG, {"title": "Overdue", "due_date": "2020-01-01T00:00:00+00:00"})
        engine.create_ticket(ORG, {"title": "Future vuln"})
        overdue = engine.list_tickets(ORG, overdue_only=True)
        assert len(overdue) == 1
        assert overdue[0]["title"] == "Overdue"


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

class TestComments:
    def test_add_comment(self, engine):
        t = _make_ticket(engine)
        c = engine.add_comment(ORG, t["id"], "alice", "Looking into this.", "comment")
        assert c["id"]
        assert c["author_id"] == "alice"

    def test_add_comment_invalid_type(self, engine):
        t = _make_ticket(engine)
        with pytest.raises(ValueError, match="comment_type"):
            engine.add_comment(ORG, t["id"], "alice", "body", "invalid_type")

    def test_comments_appear_in_get_ticket(self, engine):
        t = _make_ticket(engine)
        engine.add_comment(ORG, t["id"], "bob", "Investigating now.")
        result = engine.get_ticket(ORG, t["id"])
        assert any(c["author_id"] == "bob" for c in result["comments"])


# ---------------------------------------------------------------------------
# Assignment
# ---------------------------------------------------------------------------

class TestAssignment:
    def test_assign_ticket(self, engine):
        t = _make_ticket(engine)
        result = engine.assign_ticket(ORG, t["id"], "carol", "appsec-team", "manager")
        assert result["assignee_id"] == "carol"
        assert result["assignee_team"] == "appsec-team"

    def test_assign_logs_comment(self, engine):
        t = _make_ticket(engine)
        engine.assign_ticket(ORG, t["id"], "dave", "infra", "lead")
        result = engine.get_ticket(ORG, t["id"])
        assert any(c["comment_type"] == "assignment" for c in result["comments"])

    def test_assign_not_found(self, engine):
        result = engine.assign_ticket(ORG, "no-such-id", "x", "y", "z")
        assert result is None


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------

class TestBulkOperations:
    def test_bulk_assign(self, engine):
        t1 = _make_ticket(engine, title="A")
        t2 = _make_ticket(engine, title="B")
        result = engine.bulk_assign(ORG, [t1["id"], t2["id"]], "team_lead", "soc", "admin")
        assert result["affected_tickets"] == 2

    def test_bulk_assign_empty_list(self, engine):
        with pytest.raises(ValueError, match="empty"):
            engine.bulk_assign(ORG, [], "lead", "soc", "admin")

    def test_bulk_close(self, engine):
        t1 = _make_ticket(engine, title="X")
        t2 = _make_ticket(engine, title="Y")
        result = engine.bulk_close(ORG, [t1["id"], t2["id"]], "admin", "Patched in 1.2.3")
        assert result["affected_tickets"] == 2
        tickets = engine.list_tickets(ORG, status="resolved")
        assert len(tickets) == 2

    def test_bulk_close_empty_list(self, engine):
        with pytest.raises(ValueError, match="empty"):
            engine.bulk_close(ORG, [], "admin", "reason")

    def test_accept_risk(self, engine):
        t = _make_ticket(engine)
        result = engine.accept_risk(ORG, t["id"], "ciso", "Third-party dependency, no fix available", "2025-12-31")
        assert result["status"] == "accepted_risk"

    def test_accept_risk_not_found(self, engine):
        result = engine.accept_risk(ORG, "no-such", "ciso", "reason")
        assert result is None


# ---------------------------------------------------------------------------
# SLA config
# ---------------------------------------------------------------------------

class TestSLAConfig:
    def test_set_and_get_sla(self, engine):
        engine.set_sla_config(ORG, "critical", 5, 2, "security")
        configs = engine.get_sla_config(ORG)
        critical_cfg = next(c for c in configs if c["severity"] == "critical")
        assert critical_cfg["sla_days"] == 5
        assert critical_cfg["owner_team"] == "security"

    def test_upsert_sla_config(self, engine):
        engine.set_sla_config(ORG, "high", 30, 7, "team_a")
        engine.set_sla_config(ORG, "high", 21, 5, "team_b")
        configs = engine.get_sla_config(ORG)
        high_cfgs = [c for c in configs if c["severity"] == "high"]
        assert len(high_cfgs) == 1
        assert high_cfgs[0]["sla_days"] == 21
        assert high_cfgs[0]["owner_team"] == "team_b"

    def test_set_sla_invalid_severity(self, engine):
        with pytest.raises(ValueError):
            engine.set_sla_config(ORG, "super_critical", 1, 1, "team")

    def test_get_sla_empty(self, engine):
        configs = engine.get_sla_config(ORG)
        assert configs == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestWorkflowStats:
    def test_stats_empty(self, engine):
        stats = engine.get_workflow_stats(ORG)
        assert stats["total_open"] == 0
        assert stats["overdue_count"] == 0
        assert stats["avg_resolution_days"] == 0.0

    def test_stats_open_tickets(self, engine):
        _make_ticket(engine, severity="critical")
        _make_ticket(engine, severity="high")
        _make_ticket(engine, severity="medium")
        stats = engine.get_workflow_stats(ORG)
        assert stats["total_open"] == 3
        assert stats["by_severity"]["critical"] == 1

    def test_stats_overdue_count(self, engine):
        engine.create_ticket(ORG, {"title": "Overdue", "due_date": "2020-01-01T00:00:00+00:00"})
        stats = engine.get_workflow_stats(ORG)
        assert stats["overdue_count"] >= 1

    def test_stats_by_team(self, engine):
        t = _make_ticket(engine, assignee_team="red-team")
        stats = engine.get_workflow_stats(ORG)
        assert stats["by_team"].get("red-team", 0) >= 1

    def test_stats_by_source(self, engine):
        engine.create_ticket(ORG, {"title": "Scanner finding", "source_engine": "scanner"})
        stats = engine.get_workflow_stats(ORG)
        assert stats["by_source"].get("scanner", 0) >= 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_tickets_isolated_by_org(self, engine, engine2):
        _make_ticket(engine)
        tickets_org2 = engine2.list_tickets(ORG2)
        assert len(tickets_org2) == 0

    def test_comments_isolated_by_org(self, engine, engine2):
        t = _make_ticket(engine)
        engine.add_comment(ORG, t["id"], "alice", "comment")
        # engine2 is a different DB, can't see org1's ticket
        result = engine2.get_ticket(ORG2, t["id"])
        assert result is None
