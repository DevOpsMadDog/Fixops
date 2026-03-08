"""Comprehensive tests for core.services.deduplication — DeduplicationService."""

import pytest

from core.services.deduplication import ClusterStatus, DeduplicationService


@pytest.fixture
def svc(tmp_path):
    db_path = tmp_path / "dedup_test.db"
    return DeduplicationService(db_path=db_path)


def _make_finding(**overrides):
    defaults = dict(
        title="SQL Injection in /api/v1/search",
        severity="high",
        cve_id="CVE-2024-0001",
        rule_id="CWE-89",
        category="sast",
        message="SQL injection vulnerability detected",
        location={"file": "src/search.py", "line": 42},
        metadata={"scanner": "semgrep"},
    )
    defaults.update(overrides)
    return defaults


# ─── Cluster Status Enum ────────────────────────────────────────────────


class TestClusterStatus:
    def test_statuses(self):
        assert ClusterStatus.OPEN.value == "open"
        assert ClusterStatus.IN_PROGRESS.value == "in_progress"
        assert ClusterStatus.RESOLVED.value == "resolved"
        assert ClusterStatus.ACCEPTED_RISK.value == "accepted_risk"
        assert ClusterStatus.FALSE_POSITIVE.value == "false_positive"


# ─── Init & DB ──────────────────────────────────────────────────────────


class TestInit:
    def test_creates_db(self, tmp_path):
        db_path = tmp_path / "new_dedup.db"
        DeduplicationService(db_path=db_path)
        assert db_path.exists()

    def test_creates_parent_dirs(self, tmp_path):
        db_path = tmp_path / "nested" / "dir" / "dedup.db"
        DeduplicationService(db_path=db_path)
        assert db_path.exists()


# ─── Process Finding ────────────────────────────────────────────────────


class TestProcessFinding:
    def test_new_finding(self, svc):
        finding = _make_finding()
        result = svc.process_finding(finding, run_id="run-1", org_id="org-1")
        assert result["is_new"] is True
        assert result["occurrence_count"] == 1
        assert "cluster_id" in result
        assert "correlation_key" in result
        assert "fingerprint" in result

    def test_duplicate_finding(self, svc):
        finding = _make_finding()
        r1 = svc.process_finding(finding, run_id="run-1", org_id="org-1")
        r2 = svc.process_finding(finding, run_id="run-2", org_id="org-1")
        assert r1["is_new"] is True
        assert r2["is_new"] is False
        assert r2["occurrence_count"] == 2
        assert r1["cluster_id"] == r2["cluster_id"]

    def test_different_findings_different_clusters(self, svc):
        f1 = _make_finding(title="SQLi", cve_id="CVE-2024-0001", rule_id="CWE-89")
        f2 = _make_finding(title="XSS", cve_id="CVE-2024-0002", rule_id="CWE-79")
        r1 = svc.process_finding(f1, run_id="run-1", org_id="org-1")
        r2 = svc.process_finding(f2, run_id="run-1", org_id="org-1")
        assert r1["cluster_id"] != r2["cluster_id"]

    def test_finding_enriches_app_id(self, svc):
        finding = _make_finding()
        svc.process_finding(finding, run_id="run-1", org_id="org-1")
        # Should have app_id set by identity resolver
        assert "app_id" in finding

    def test_finding_with_source(self, svc):
        finding = _make_finding()
        result = svc.process_finding(finding, run_id="run-1", org_id="org-1", source="semgrep")
        assert result["is_new"] is True


# ─── Process Findings Batch ─────────────────────────────────────────────


class TestProcessFindingsBatch:
    def test_batch_processing(self, svc):
        findings = [_make_finding(title=f"Finding {i}", rule_id=f"CWE-{i}") for i in range(5)]
        result = svc.process_findings_batch(findings, run_id="run-1", org_id="org-1")
        assert result["total_findings"] == 5
        assert result["unique_clusters"] == 5
        assert result["new_clusters"] == 5
        assert result["existing_clusters"] == 0

    def test_batch_with_duplicates(self, svc):
        # First batch
        finding = _make_finding()
        svc.process_finding(finding, run_id="run-1", org_id="org-1")
        # Second batch with same finding
        findings = [finding, _make_finding(title="New XSS", rule_id="CWE-79")]
        result = svc.process_findings_batch(findings, run_id="run-2", org_id="org-1")
        assert result["existing_clusters"] >= 1
        assert result["new_clusters"] >= 1

    def test_batch_noise_reduction(self, svc):
        # All same finding = maximum noise reduction
        finding = _make_finding()
        findings = [finding] * 10
        result = svc.process_findings_batch(findings, run_id="run-1", org_id="org-1")
        assert result["unique_clusters"] == 1
        assert result["noise_reduction_percent"] == 90.0

    def test_batch_empty(self, svc):
        result = svc.process_findings_batch([], run_id="run-1", org_id="org-1")
        assert result["total_findings"] == 0
        assert result["noise_reduction_percent"] == 0


# ─── Get Cluster ────────────────────────────────────────────────────────


class TestGetCluster:
    def test_get_existing_cluster(self, svc):
        finding = _make_finding()
        r = svc.process_finding(finding, run_id="run-1", org_id="org-1")
        cluster = svc.get_cluster(r["cluster_id"])
        assert cluster is not None
        assert cluster["cluster_id"] == r["cluster_id"]
        assert cluster["status"] == "open"

    def test_get_nonexistent_cluster(self, svc):
        assert svc.get_cluster("nonexistent") is None


# ─── Get Cluster Events ────────────────────────────────────────────────


class TestGetClusterEvents:
    def test_get_events(self, svc):
        finding = _make_finding()
        r1 = svc.process_finding(finding, run_id="run-1", org_id="org-1")
        svc.process_finding(finding, run_id="run-2", org_id="org-1")
        events = svc.get_cluster_events(r1["cluster_id"])
        assert len(events) == 2

    def test_get_events_empty(self, svc):
        events = svc.get_cluster_events("nonexistent")
        assert events == []

    def test_get_events_limit(self, svc):
        finding = _make_finding()
        for i in range(5):
            svc.process_finding(finding, run_id=f"run-{i}", org_id="org-1")
        events = svc.get_cluster_events(
            svc.get_clusters("org-1")[0]["cluster_id"], limit=2
        )
        assert len(events) == 2

    def test_get_events_for_clusters_batch(self, svc):
        f1 = _make_finding(title="F1", rule_id="CWE-1")
        f2 = _make_finding(title="F2", rule_id="CWE-2")
        r1 = svc.process_finding(f1, run_id="run-1", org_id="org-1")
        r2 = svc.process_finding(f2, run_id="run-1", org_id="org-1")
        events = svc.get_events_for_clusters([r1["cluster_id"], r2["cluster_id"]])
        assert r1["cluster_id"] in events
        assert r2["cluster_id"] in events

    def test_get_events_for_empty_list(self, svc):
        events = svc.get_events_for_clusters([])
        assert events == {}


# ─── Get Clusters ───────────────────────────────────────────────────────


class TestGetClusters:
    def test_get_clusters_by_org(self, svc):
        for i in range(3):
            svc.process_finding(
                _make_finding(title=f"F{i}", rule_id=f"CWE-{i}"),
                run_id="run-1", org_id="org-1"
            )
        clusters = svc.get_clusters("org-1")
        assert len(clusters) == 3

    def test_get_clusters_filter_status(self, svc):
        r = svc.process_finding(_make_finding(), run_id="run-1", org_id="org-1")
        svc.update_cluster_status(r["cluster_id"], "resolved")
        svc.process_finding(
            _make_finding(title="Other", rule_id="CWE-99"),
            run_id="run-1", org_id="org-1"
        )
        open_clusters = svc.get_clusters("org-1", status="open")
        resolved_clusters = svc.get_clusters("org-1", status="resolved")
        assert len(open_clusters) == 1
        assert len(resolved_clusters) == 1

    def test_get_clusters_filter_severity(self, svc):
        svc.process_finding(
            _make_finding(severity="critical", rule_id="CWE-1"),
            run_id="run-1", org_id="org-1"
        )
        svc.process_finding(
            _make_finding(severity="low", rule_id="CWE-2"),
            run_id="run-1", org_id="org-1"
        )
        critical = svc.get_clusters("org-1", severity="critical")
        assert len(critical) == 1

    def test_get_clusters_pagination(self, svc):
        for i in range(10):
            svc.process_finding(
                _make_finding(title=f"F{i}", rule_id=f"CWE-{i}"),
                run_id="run-1", org_id="org-1"
            )
        page1 = svc.get_clusters("org-1", limit=3, offset=0)
        page2 = svc.get_clusters("org-1", limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3


# ─── Update Cluster Status ─────────────────────────────────────────────


class TestUpdateStatus:
    def test_update_status(self, svc):
        r = svc.process_finding(_make_finding(), run_id="run-1", org_id="org-1")
        assert svc.update_cluster_status(r["cluster_id"], "resolved") is True
        cluster = svc.get_cluster(r["cluster_id"])
        assert cluster["status"] == "resolved"

    def test_update_status_nonexistent(self, svc):
        assert svc.update_cluster_status("nonexistent", "resolved") is False

    def test_update_status_invalid(self, svc):
        r = svc.process_finding(_make_finding(), run_id="run-1", org_id="org-1")
        with pytest.raises(ValueError):
            svc.update_cluster_status(r["cluster_id"], "invalid_status")

    def test_update_status_with_audit(self, svc):
        r = svc.process_finding(_make_finding(), run_id="run-1", org_id="org-1")
        svc.update_cluster_status(
            r["cluster_id"], "resolved",
            changed_by="admin@example.com",
            reason="Fixed in PR #123"
        )
        cluster = svc.get_cluster(r["cluster_id"])
        assert cluster["status"] == "resolved"


# ─── Link to Ticket ────────────────────────────────────────────────────


class TestLinkToTicket:
    def test_link_ticket(self, svc):
        r = svc.process_finding(_make_finding(), run_id="run-1", org_id="org-1")
        assert svc.link_to_ticket(r["cluster_id"], "JIRA-123", "https://jira.example.com/JIRA-123") is True
        cluster = svc.get_cluster(r["cluster_id"])
        assert cluster["ticket_id"] == "JIRA-123"
        assert cluster["ticket_url"] == "https://jira.example.com/JIRA-123"

    def test_link_ticket_nonexistent(self, svc):
        assert svc.link_to_ticket("nonexistent", "JIRA-999") is False


# ─── Assign Cluster ────────────────────────────────────────────────────


class TestAssignCluster:
    def test_assign(self, svc):
        r = svc.process_finding(_make_finding(), run_id="run-1", org_id="org-1")
        assert svc.assign_cluster(r["cluster_id"], "security-team@example.com") is True
        cluster = svc.get_cluster(r["cluster_id"])
        assert cluster["assignee"] == "security-team@example.com"

    def test_assign_nonexistent(self, svc):
        assert svc.assign_cluster("nonexistent", "nobody") is False


# ─── Correlation Links ─────────────────────────────────────────────────


class TestCorrelationLinks:
    def test_create_link(self, svc):
        r1 = svc.process_finding(_make_finding(title="F1", rule_id="CWE-1"), run_id="run-1", org_id="org-1")
        r2 = svc.process_finding(_make_finding(title="F2", rule_id="CWE-2"), run_id="run-1", org_id="org-1")
        link_id = svc.create_correlation_link(
            r1["cluster_id"], r2["cluster_id"],
            link_type="related",
            confidence=0.85,
            reason="Same component affected",
        )
        assert link_id is not None
        assert len(link_id) == 36  # UUID format
