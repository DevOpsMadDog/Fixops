"""Tests for AuditManagementEngine.

Covers: audit CRUD, start/complete lifecycle, finding recording with
severity/category validation, findings_count increment, resolve finding,
resolution_rate calculation, stats by_type/by_status, org isolation.
"""

from __future__ import annotations

import pytest

from core.audit_management_engine import (
    AuditComplete,
    AuditCreate,
    AuditManagementEngine,
    FindingCreate,
    FindingResolve,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return AuditManagementEngine(db_path=str(tmp_path / "test_audit.db"))


def _audit(
    name="Q1 Security Audit",
    audit_type="internal",
    scope="All web services",
    auditor="Alice",
    planned_date="2026-06-01",
    **kw,
) -> AuditCreate:
    return AuditCreate(
        name=name,
        audit_type=audit_type,
        scope=scope,
        auditor=auditor,
        planned_date=planned_date,
        **kw,
    )


def _finding(
    title="Missing MFA",
    severity="high",
    category="access_control",
    description="Admin accounts lack MFA enforcement",
    **kw,
) -> FindingCreate:
    return FindingCreate(
        title=title, severity=severity, category=category, description=description, **kw
    )


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "audit.db"
    AuditManagementEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "audit.db")
    AuditManagementEngine(db_path=db)
    AuditManagementEngine(db_path=db)  # should not raise


# ---------------------------------------------------------------------------
# 2. Create audit
# ---------------------------------------------------------------------------


def test_create_audit_returns_record(engine):
    a = engine.create_audit("org1", _audit())
    assert a["name"] == "Q1 Security Audit"
    assert a["audit_type"] == "internal"
    assert a["status"] == "planned"
    assert a["findings_count"] == 0
    assert a["started_at"] is None
    assert a["completed_at"] is None
    assert "id" in a


def test_create_audit_generates_unique_ids(engine):
    a1 = engine.create_audit("org1", _audit(name="A"))
    a2 = engine.create_audit("org1", _audit(name="B"))
    assert a1["id"] != a2["id"]


@pytest.mark.parametrize("atype", [
    "internal", "external", "compliance", "security", "financial", "operational"
])
def test_create_audit_all_valid_types(engine, atype):
    a = engine.create_audit("org1", _audit(audit_type=atype))
    assert a["audit_type"] == atype


def test_create_audit_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="audit_type"):
        engine.create_audit("org1", _audit(audit_type="hacker"))


def test_create_audit_missing_scope_raises(engine):
    with pytest.raises((ValueError, Exception)):
        engine.create_audit("org1", AuditCreate(
            name="A", audit_type="internal", scope="",
            auditor="Alice", planned_date="2026-01-01"
        ))


# ---------------------------------------------------------------------------
# 3. List and get audit
# ---------------------------------------------------------------------------


def test_list_audits_empty(engine):
    assert engine.list_audits("org1") == []


def test_list_audits_returns_all(engine):
    engine.create_audit("org1", _audit(name="A"))
    engine.create_audit("org1", _audit(name="B"))
    assert len(engine.list_audits("org1")) == 2


def test_list_audits_filtered_by_type(engine):
    engine.create_audit("org1", _audit(name="A", audit_type="internal"))
    engine.create_audit("org1", _audit(name="B", audit_type="external"))
    result = engine.list_audits("org1", audit_type="internal")
    assert len(result) == 1
    assert result[0]["audit_type"] == "internal"


def test_list_audits_filtered_by_status(engine):
    a = engine.create_audit("org1", _audit(name="A"))
    engine.create_audit("org1", _audit(name="B"))
    engine.start_audit("org1", a["id"])
    result = engine.list_audits("org1", status="in_progress")
    assert len(result) == 1


def test_get_audit_returns_record(engine):
    a = engine.create_audit("org1", _audit())
    fetched = engine.get_audit("org1", a["id"])
    assert fetched["id"] == a["id"]


def test_get_audit_wrong_org_raises(engine):
    a = engine.create_audit("org1", _audit())
    with pytest.raises(ValueError):
        engine.get_audit("org2", a["id"])


# ---------------------------------------------------------------------------
# 4. Audit lifecycle
# ---------------------------------------------------------------------------


def test_start_audit_transitions_status(engine):
    a = engine.create_audit("org1", _audit())
    started = engine.start_audit("org1", a["id"])
    assert started["status"] == "in_progress"
    assert started["started_at"] is not None


def test_complete_audit_transitions_status(engine):
    a = engine.create_audit("org1", _audit())
    engine.start_audit("org1", a["id"])
    completed = engine.complete_audit("org1", a["id"], summary="All controls tested")
    assert completed["status"] == "completed"
    assert completed["completed_at"] is not None
    assert completed["summary"] == "All controls tested"


def test_start_audit_wrong_org_raises(engine):
    a = engine.create_audit("org1", _audit())
    with pytest.raises(ValueError):
        engine.start_audit("org2", a["id"])


def test_complete_audit_wrong_org_raises(engine):
    a = engine.create_audit("org1", _audit())
    with pytest.raises(ValueError):
        engine.complete_audit("org2", a["id"], "done")


# ---------------------------------------------------------------------------
# 5. Record findings
# ---------------------------------------------------------------------------


def test_record_finding_returns_record(engine):
    a = engine.create_audit("org1", _audit())
    f = engine.record_finding("org1", a["id"], _finding())
    assert f["title"] == "Missing MFA"
    assert f["severity"] == "high"
    assert f["category"] == "access_control"
    assert f["status"] == "open"
    assert f["found_at"] is not None
    assert "id" in f


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_record_finding_all_severities(engine, severity):
    a = engine.create_audit("org1", _audit())
    f = engine.record_finding("org1", a["id"], _finding(severity=severity))
    assert f["severity"] == severity


@pytest.mark.parametrize("category", [
    "access_control", "data_protection", "config", "process", "compliance", "technical"
])
def test_record_finding_all_categories(engine, category):
    a = engine.create_audit("org1", _audit())
    f = engine.record_finding("org1", a["id"], _finding(category=category))
    assert f["category"] == category


def test_record_finding_invalid_severity_raises(engine):
    a = engine.create_audit("org1", _audit())
    with pytest.raises(ValueError, match="severity"):
        engine.record_finding("org1", a["id"], _finding(severity="extreme"))


def test_record_finding_invalid_category_raises(engine):
    a = engine.create_audit("org1", _audit())
    with pytest.raises(ValueError, match="category"):
        engine.record_finding("org1", a["id"], _finding(category="other"))


def test_record_finding_increments_findings_count(engine):
    a = engine.create_audit("org1", _audit())
    assert engine.get_audit("org1", a["id"])["findings_count"] == 0
    engine.record_finding("org1", a["id"], _finding(title="F1"))
    assert engine.get_audit("org1", a["id"])["findings_count"] == 1
    engine.record_finding("org1", a["id"], _finding(title="F2"))
    assert engine.get_audit("org1", a["id"])["findings_count"] == 2


def test_record_finding_wrong_org_audit_raises(engine):
    a = engine.create_audit("org1", _audit())
    with pytest.raises(ValueError):
        engine.record_finding("org2", a["id"], _finding())


# ---------------------------------------------------------------------------
# 6. Resolve findings
# ---------------------------------------------------------------------------


def test_resolve_finding_transitions_status(engine):
    a = engine.create_audit("org1", _audit())
    f = engine.record_finding("org1", a["id"], _finding())
    resolved = engine.resolve_finding("org1", f["id"], "Enforced via policy", "bob")
    assert resolved["status"] == "resolved"
    assert resolved["resolution"] == "Enforced via policy"
    assert resolved["resolved_by"] == "bob"
    assert resolved["resolved_at"] is not None


def test_resolve_finding_wrong_org_raises(engine):
    a = engine.create_audit("org1", _audit())
    f = engine.record_finding("org1", a["id"], _finding())
    with pytest.raises(ValueError):
        engine.resolve_finding("org2", f["id"], "fixed", "alice")


# ---------------------------------------------------------------------------
# 7. Stats
# ---------------------------------------------------------------------------


def test_stats_empty(engine):
    stats = engine.get_audit_stats("org1")
    assert stats["total_audits"] == 0
    assert stats["by_type"] == {}
    assert stats["by_status"] == {}
    assert stats["total_findings"] == 0
    assert stats["open_findings"] == 0
    assert stats["critical_findings"] == 0
    assert stats["resolution_rate"] == 0.0


def test_stats_by_type(engine):
    engine.create_audit("org1", _audit(name="A", audit_type="internal"))
    engine.create_audit("org1", _audit(name="B", audit_type="internal"))
    engine.create_audit("org1", _audit(name="C", audit_type="external"))
    stats = engine.get_audit_stats("org1")
    assert stats["by_type"]["internal"] == 2
    assert stats["by_type"]["external"] == 1


def test_stats_by_status(engine):
    a = engine.create_audit("org1", _audit(name="A"))
    engine.create_audit("org1", _audit(name="B"))
    engine.start_audit("org1", a["id"])
    stats = engine.get_audit_stats("org1")
    assert stats["by_status"]["planned"] == 1
    assert stats["by_status"]["in_progress"] == 1


def test_stats_open_and_critical_findings(engine):
    a = engine.create_audit("org1", _audit())
    engine.record_finding("org1", a["id"], _finding(severity="critical"))
    engine.record_finding("org1", a["id"], _finding(severity="high"))
    stats = engine.get_audit_stats("org1")
    assert stats["total_findings"] == 2
    assert stats["open_findings"] == 2
    assert stats["critical_findings"] == 1


def test_stats_resolution_rate(engine):
    a = engine.create_audit("org1", _audit())
    f1 = engine.record_finding("org1", a["id"], _finding(title="F1"))
    f2 = engine.record_finding("org1", a["id"], _finding(title="F2"))
    engine.record_finding("org1", a["id"], _finding(title="F3"))
    engine.resolve_finding("org1", f1["id"], "fixed", "alice")
    engine.resolve_finding("org1", f2["id"], "patched", "bob")
    stats = engine.get_audit_stats("org1")
    assert stats["resolution_rate"] == pytest.approx(66.67, abs=0.1)
    assert stats["open_findings"] == 1


def test_stats_resolution_rate_100(engine):
    a = engine.create_audit("org1", _audit())
    f = engine.record_finding("org1", a["id"], _finding())
    engine.resolve_finding("org1", f["id"], "done", "alice")
    stats = engine.get_audit_stats("org1")
    assert stats["resolution_rate"] == 100.0
    assert stats["open_findings"] == 0


# ---------------------------------------------------------------------------
# 8. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_audits(engine):
    engine.create_audit("org1", _audit(name="A"))
    engine.create_audit("org2", _audit(name="B"))
    assert len(engine.list_audits("org1")) == 1
    assert len(engine.list_audits("org2")) == 1


def test_org_isolation_findings(engine):
    a1 = engine.create_audit("org1", _audit())
    a2 = engine.create_audit("org2", _audit())
    engine.record_finding("org1", a1["id"], _finding())
    engine.record_finding("org2", a2["id"], _finding())
    s1 = engine.get_audit_stats("org1")
    s2 = engine.get_audit_stats("org2")
    assert s1["total_findings"] == 1
    assert s2["total_findings"] == 1


def test_org_isolation_stats(engine):
    engine.create_audit("org1", _audit(name="A"))
    engine.create_audit("org1", _audit(name="B"))
    engine.create_audit("org2", _audit(name="C"))
    s1 = engine.get_audit_stats("org1")
    s2 = engine.get_audit_stats("org2")
    assert s1["total_audits"] == 2
    assert s2["total_audits"] == 1
