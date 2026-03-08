"""Comprehensive tests for core.analytics_db — CRUD, queries, dashboard, MTTR."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from core.analytics_db import AnalyticsDB
from core.analytics_models import (
    Decision,
    DecisionOutcome,
    Finding,
    FindingSeverity,
    FindingStatus,
    Metric,
)


@pytest.fixture
def db(tmp_path):
    """Create a fresh AnalyticsDB in a temp directory."""
    db_path = str(tmp_path / "test_analytics.db")
    return AnalyticsDB(db_path=db_path)


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        id=str(uuid.uuid4()),
        application_id="app-1",
        service_id="svc-1",
        rule_id="RULE-001",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="Test finding",
        description="A test vulnerability",
        source="sast",
        cve_id="CVE-2024-0001",
        cvss_score=8.5,
        epss_score=0.42,
        exploitable=True,
        metadata={"scanner": "test"},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        resolved_at=None,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_decision(finding_id: str, **overrides) -> Decision:
    defaults = dict(
        id=str(uuid.uuid4()),
        finding_id=finding_id,
        outcome=DecisionOutcome.BLOCK,
        confidence=0.92,
        reasoning="High CVSS + exploitable in the wild",
        llm_votes={"gpt4": "block", "claude": "block"},
        policy_matched="critical-block",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return Decision(**defaults)


def _make_metric(**overrides) -> Metric:
    defaults = dict(
        id=str(uuid.uuid4()),
        metric_type="coverage",
        metric_name="branch_coverage",
        value=78.5,
        unit="percent",
        timestamp=datetime.now(timezone.utc),
        metadata={"module": "core"},
    )
    defaults.update(overrides)
    return Metric(**defaults)


# ─── Finding CRUD ───────────────────────────────────────────────────────


class TestFindingCRUD:
    def test_create_finding(self, db):
        f = _make_finding()
        result = db.create_finding(f)
        assert result.id == f.id

    def test_create_finding_auto_id(self, db):
        f = _make_finding(id="")
        result = db.create_finding(f)
        assert result.id  # auto-generated

    def test_get_finding(self, db):
        f = _make_finding()
        db.create_finding(f)
        result = db.get_finding(f.id)
        assert result is not None
        assert result.id == f.id
        assert result.title == f.title
        assert result.severity == FindingSeverity.HIGH

    def test_get_finding_not_found(self, db):
        assert db.get_finding("nonexistent") is None

    def test_list_findings_empty(self, db):
        assert db.list_findings() == []

    def test_list_findings_all(self, db):
        for _ in range(5):
            db.create_finding(_make_finding())
        assert len(db.list_findings()) == 5

    def test_list_findings_filter_severity(self, db):
        db.create_finding(_make_finding(severity=FindingSeverity.CRITICAL))
        db.create_finding(_make_finding(severity=FindingSeverity.LOW))
        db.create_finding(_make_finding(severity=FindingSeverity.CRITICAL))
        results = db.list_findings(severity="critical")
        assert len(results) == 2

    def test_list_findings_filter_status(self, db):
        db.create_finding(_make_finding(status=FindingStatus.OPEN))
        db.create_finding(_make_finding(status=FindingStatus.RESOLVED))
        results = db.list_findings(status="resolved")
        assert len(results) == 1

    def test_list_findings_pagination(self, db):
        for _ in range(10):
            db.create_finding(_make_finding())
        page1 = db.list_findings(limit=3, offset=0)
        page2 = db.list_findings(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0].id != page2[0].id

    def test_update_finding(self, db):
        f = _make_finding()
        db.create_finding(f)
        f.status = FindingStatus.RESOLVED
        f.resolved_at = datetime.now(timezone.utc)
        result = db.update_finding(f)
        assert result.status == FindingStatus.RESOLVED
        reloaded = db.get_finding(f.id)
        assert reloaded.status == FindingStatus.RESOLVED

    def test_delete_finding(self, db):
        f = _make_finding()
        db.create_finding(f)
        assert db.delete_finding(f.id) is True
        assert db.get_finding(f.id) is None

    def test_delete_finding_not_found(self, db):
        assert db.delete_finding("nonexistent") is False

    def test_finding_with_none_fields(self, db):
        f = _make_finding(cve_id=None, cvss_score=None, epss_score=None)
        db.create_finding(f)
        result = db.get_finding(f.id)
        assert result.cve_id is None
        assert result.cvss_score is None

    def test_finding_metadata_roundtrip(self, db):
        meta = {"tags": ["rce", "critical"], "scanner_version": "2.0"}
        f = _make_finding(metadata=meta)
        db.create_finding(f)
        result = db.get_finding(f.id)
        assert result.metadata == meta


# ─── Decision CRUD ──────────────────────────────────────────────────────


class TestDecisionCRUD:
    def test_create_decision(self, db):
        f = _make_finding()
        db.create_finding(f)
        d = _make_decision(f.id)
        result = db.create_decision(d)
        assert result.id == d.id

    def test_create_decision_auto_id(self, db):
        f = _make_finding()
        db.create_finding(f)
        d = _make_decision(f.id, id="")
        result = db.create_decision(d)
        assert result.id  # auto-generated

    def test_list_decisions_all(self, db):
        f = _make_finding()
        db.create_finding(f)
        for _ in range(3):
            db.create_decision(_make_decision(f.id))
        results = db.list_decisions()
        assert len(results) == 3

    def test_list_decisions_by_finding(self, db):
        f1 = _make_finding()
        f2 = _make_finding()
        db.create_finding(f1)
        db.create_finding(f2)
        db.create_decision(_make_decision(f1.id))
        db.create_decision(_make_decision(f1.id))
        db.create_decision(_make_decision(f2.id))
        results = db.list_decisions(finding_id=f1.id)
        assert len(results) == 2

    def test_list_decisions_pagination(self, db):
        f = _make_finding()
        db.create_finding(f)
        for _ in range(5):
            db.create_decision(_make_decision(f.id))
        page = db.list_decisions(limit=2, offset=0)
        assert len(page) == 2

    def test_decision_outcomes(self, db):
        f = _make_finding()
        db.create_finding(f)
        for outcome in DecisionOutcome:
            db.create_decision(_make_decision(f.id, outcome=outcome))
        results = db.list_decisions()
        outcomes = {d.outcome for d in results}
        assert outcomes == set(DecisionOutcome)


# ─── Metric CRUD ────────────────────────────────────────────────────────


class TestMetricCRUD:
    def test_create_metric(self, db):
        m = _make_metric()
        result = db.create_metric(m)
        assert result.id == m.id

    def test_create_metric_auto_id(self, db):
        m = _make_metric(id="")
        result = db.create_metric(m)
        assert result.id

    def test_list_metrics_all(self, db):
        for _ in range(4):
            db.create_metric(_make_metric())
        results = db.list_metrics()
        assert len(results) == 4

    def test_list_metrics_filter_type(self, db):
        db.create_metric(_make_metric(metric_type="coverage"))
        db.create_metric(_make_metric(metric_type="performance"))
        db.create_metric(_make_metric(metric_type="coverage"))
        results = db.list_metrics(metric_type="coverage")
        assert len(results) == 2

    def test_list_metrics_filter_time_range(self, db):
        now = datetime.now(timezone.utc)
        db.create_metric(_make_metric(timestamp=now - timedelta(days=5)))
        db.create_metric(_make_metric(timestamp=now - timedelta(days=1)))
        db.create_metric(_make_metric(timestamp=now))
        results = db.list_metrics(start_time=now - timedelta(days=2))
        assert len(results) == 2

    def test_list_metrics_filter_end_time(self, db):
        now = datetime.now(timezone.utc)
        db.create_metric(_make_metric(timestamp=now - timedelta(days=5)))
        db.create_metric(_make_metric(timestamp=now))
        results = db.list_metrics(end_time=now - timedelta(days=3))
        assert len(results) == 1

    def test_list_metrics_limit(self, db):
        for _ in range(10):
            db.create_metric(_make_metric())
        results = db.list_metrics(limit=3)
        assert len(results) == 3


# ─── Dashboard & Analytics ──────────────────────────────────────────────


class TestDashboard:
    def test_dashboard_overview_empty(self, db):
        overview = db.get_dashboard_overview()
        assert overview["total_findings"] == 0
        assert overview["open_findings"] == 0
        assert overview["critical_findings"] == 0
        assert "timestamp" in overview

    def test_dashboard_overview_with_data(self, db):
        db.create_finding(_make_finding(severity=FindingSeverity.CRITICAL, status=FindingStatus.OPEN))
        db.create_finding(_make_finding(severity=FindingSeverity.HIGH, status=FindingStatus.OPEN))
        db.create_finding(_make_finding(severity=FindingSeverity.CRITICAL, status=FindingStatus.RESOLVED))
        overview = db.get_dashboard_overview()
        assert overview["total_findings"] == 3
        assert overview["open_findings"] == 2
        assert overview["critical_findings"] == 1

    def test_top_risks_empty(self, db):
        assert db.get_top_risks() == []

    def test_top_risks_ordered(self, db):
        db.create_finding(_make_finding(severity=FindingSeverity.LOW, cvss_score=2.0))
        db.create_finding(_make_finding(severity=FindingSeverity.CRITICAL, cvss_score=9.8))
        db.create_finding(_make_finding(severity=FindingSeverity.HIGH, cvss_score=7.5))
        risks = db.get_top_risks(limit=10)
        assert len(risks) == 3
        assert risks[0]["severity"] == "critical"

    def test_top_risks_limit(self, db):
        for _ in range(5):
            db.create_finding(_make_finding())
        risks = db.get_top_risks(limit=2)
        assert len(risks) == 2

    def test_mttr_no_resolved(self, db):
        db.create_finding(_make_finding(status=FindingStatus.OPEN))
        assert db.calculate_mttr() is None

    def test_mttr_with_resolved(self, db):
        now = datetime.now(timezone.utc)
        f = _make_finding(
            created_at=now - timedelta(hours=10),
            updated_at=now,
            resolved_at=now,
            status=FindingStatus.RESOLVED,
        )
        db.create_finding(f)
        mttr = db.calculate_mttr()
        assert mttr is not None
        assert 9.5 <= mttr <= 10.5  # ~10 hours

    def test_mttr_multiple_resolved(self, db):
        now = datetime.now(timezone.utc)
        for hours in [2, 4, 6]:
            f = _make_finding(
                created_at=now - timedelta(hours=hours),
                updated_at=now,
                resolved_at=now,
                status=FindingStatus.RESOLVED,
            )
            db.create_finding(f)
        mttr = db.calculate_mttr()
        assert mttr is not None
        assert 3.5 <= mttr <= 4.5  # avg of 2,4,6 = 4


# ─── Model conversion helpers ──────────────────────────────────────────


class TestModelConversion:
    def test_finding_to_dict(self):
        f = _make_finding()
        d = f.to_dict()
        assert d["id"] == f.id
        assert d["severity"] == "high"
        assert d["status"] == "open"
        assert d["exploitable"] is True

    def test_decision_to_dict(self):
        d = _make_decision("finding-1")
        result = d.to_dict()
        assert result["outcome"] == "block"
        assert result["confidence"] == 0.92

    def test_metric_to_dict(self):
        m = _make_metric()
        result = m.to_dict()
        assert result["metric_type"] == "coverage"
        assert result["value"] == 78.5

    def test_finding_severities(self):
        for sev in FindingSeverity:
            assert sev.value in ("critical", "high", "medium", "low", "info")

    def test_finding_statuses(self):
        for st in FindingStatus:
            assert st.value in ("open", "in_progress", "resolved", "false_positive", "accepted_risk")

    def test_decision_outcomes(self):
        for o in DecisionOutcome:
            assert o.value in ("block", "alert", "allow", "review")
