"""Tests for CloudSecurityFindingsEngine.

Covers:
- ingest_finding: valid, dedup (same resource+title not ingested twice), invalid provider/severity/type
- resolve_finding: sets status=resolved, resolved_at; not found; org isolation
- suppress_finding: sets status=suppressed, creates suppression record; not found; org isolation
- assign_remediation: creates record; not found
- update_remediation: updates status/notes; invalid status; not found; org isolation
- get_findings: all, by provider, by severity, by status, org isolation
- get_finding_summary: totals, by_provider, by_severity, by_status, critical_open, overdue_remediations
- get_top_affected_resources: ordered by count, respects limit
- bulk_ingest: ingested count, skipped_duplicates count
- All 6 providers accepted
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.cloud_security_findings_engine import CloudSecurityFindingsEngine

ORG = "org-csf-test"
ORG2 = "org-csf-other"


@pytest.fixture
def engine(tmp_path):
    return CloudSecurityFindingsEngine(db_path=str(tmp_path / "csf.db"))


def _finding(overrides=None):
    base = {
        "provider": "aws",
        "account_id": "123456789",
        "region": "us-east-1",
        "resource_type": "s3",
        "resource_id": "my-bucket",
        "finding_title": "Public S3 bucket",
        "finding_type": "misconfiguration",
        "severity": "high",
        "cvss_score": 7.5,
        "remediation": "Disable public access",
    }
    if overrides:
        base.update(overrides)
    return base


def _past_iso(days=1):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _future_iso(days=7):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# ingest_finding
# ---------------------------------------------------------------------------

class TestIngestFinding:
    def test_returns_dict_with_id(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        assert "id" in r and len(r["id"]) == 36

    def test_status_is_open(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        assert r["status"] == "open"

    def test_dedup_returns_existing(self, engine):
        r1 = engine.ingest_finding(ORG, **_finding())
        r2 = engine.ingest_finding(ORG, **_finding())
        assert r1["id"] == r2["id"]

    def test_dedup_same_title_diff_resource_allowed(self, engine):
        r1 = engine.ingest_finding(ORG, **_finding({"resource_id": "bucket-a"}))
        r2 = engine.ingest_finding(ORG, **_finding({"resource_id": "bucket-b"}))
        assert r1["id"] != r2["id"]

    def test_dedup_same_resource_diff_title_allowed(self, engine):
        r1 = engine.ingest_finding(ORG, **_finding({"finding_title": "Title A"}))
        r2 = engine.ingest_finding(ORG, **_finding({"finding_title": "Title B"}))
        assert r1["id"] != r2["id"]

    def test_all_six_providers(self, engine):
        for p in ["aws", "azure", "gcp", "alibaba", "oci", "ibm"]:
            r = engine.ingest_finding(ORG, **_finding({"provider": p, "resource_id": f"res-{p}"}))
            assert r["provider"] == p

    def test_invalid_provider_raises(self, engine):
        with pytest.raises(ValueError, match="provider"):
            engine.ingest_finding(ORG, **_finding({"provider": "digitalocean"}))

    def test_invalid_severity_raises(self, engine):
        with pytest.raises(ValueError, match="severity"):
            engine.ingest_finding(ORG, **_finding({"severity": "extreme"}))

    def test_invalid_finding_type_raises(self, engine):
        with pytest.raises(ValueError, match="finding_type"):
            engine.ingest_finding(ORG, **_finding({"finding_type": "unknown"}))

    def test_cvss_score_clamped_high(self, engine):
        r = engine.ingest_finding(ORG, **_finding({"cvss_score": 99.9}))
        assert r["cvss_score"] == 10.0

    def test_cvss_score_clamped_low(self, engine):
        r = engine.ingest_finding(ORG, **_finding({"cvss_score": -5.0}))
        assert r["cvss_score"] == 0.0

    def test_org_isolation_no_dedup(self, engine):
        r1 = engine.ingest_finding(ORG, **_finding())
        r2 = engine.ingest_finding(ORG2, **_finding())
        assert r1["id"] != r2["id"]


# ---------------------------------------------------------------------------
# resolve_finding
# ---------------------------------------------------------------------------

class TestResolveFinding:
    def test_sets_status_resolved(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        resolved = engine.resolve_finding(r["id"], ORG)
        assert resolved["status"] == "resolved"

    def test_sets_resolved_at(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        resolved = engine.resolve_finding(r["id"], ORG)
        assert resolved["resolved_at"] is not None and resolved["resolved_at"] != ""

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.resolve_finding("no-such-id", ORG)

    def test_org_isolation(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        with pytest.raises(KeyError):
            engine.resolve_finding(r["id"], ORG2)

    def test_resolved_finding_allows_new_ingest(self, engine):
        r1 = engine.ingest_finding(ORG, **_finding())
        engine.resolve_finding(r1["id"], ORG)
        # Same key but resolved — new ingest should create a new finding
        r2 = engine.ingest_finding(ORG, **_finding())
        assert r1["id"] != r2["id"]


# ---------------------------------------------------------------------------
# suppress_finding
# ---------------------------------------------------------------------------

class TestSuppressFinding:
    def test_sets_status_suppressed(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        sup = engine.suppress_finding(r["id"], ORG, "alice", "accepted risk", "")
        assert sup["status"] == "suppressed"

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.suppress_finding("no-such-id", ORG, "alice", "reason", "")

    def test_org_isolation(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        with pytest.raises(KeyError):
            engine.suppress_finding(r["id"], ORG2, "alice", "reason", "")

    def test_suppressed_finding_dedup_lifted(self, engine):
        r1 = engine.ingest_finding(ORG, **_finding())
        engine.suppress_finding(r1["id"], ORG, "alice", "accepted", "")
        # Now status is suppressed (not open), so new ingest should create new record
        r2 = engine.ingest_finding(ORG, **_finding())
        assert r1["id"] != r2["id"]


# ---------------------------------------------------------------------------
# assign_remediation
# ---------------------------------------------------------------------------

class TestAssignRemediation:
    def test_creates_remediation_record(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        rem = engine.assign_remediation(r["id"], ORG, "bob", _future_iso(), "fix ASAP")
        assert rem["finding_id"] == r["id"]
        assert rem["status"] == "assigned"

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.assign_remediation("no-such-id", ORG, "bob", _future_iso())

    def test_org_isolation(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        with pytest.raises(KeyError):
            engine.assign_remediation(r["id"], ORG2, "bob", _future_iso())


# ---------------------------------------------------------------------------
# update_remediation
# ---------------------------------------------------------------------------

class TestUpdateRemediation:
    def test_updates_status(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        rem = engine.assign_remediation(r["id"], ORG, "bob", _future_iso())
        updated = engine.update_remediation(rem["id"], ORG, "completed", "done")
        assert updated["status"] == "completed"
        assert updated["notes"] == "done"

    def test_invalid_status_raises(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        rem = engine.assign_remediation(r["id"], ORG, "bob", _future_iso())
        with pytest.raises(ValueError):
            engine.update_remediation(rem["id"], ORG, "done-invalid")

    def test_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.update_remediation("no-such-id", ORG, "completed")

    def test_org_isolation(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        rem = engine.assign_remediation(r["id"], ORG, "bob", _future_iso())
        with pytest.raises(KeyError):
            engine.update_remediation(rem["id"], ORG2, "completed")


# ---------------------------------------------------------------------------
# get_findings
# ---------------------------------------------------------------------------

class TestGetFindings:
    def test_returns_all_for_org(self, engine):
        engine.ingest_finding(ORG, **_finding({"resource_id": "r1"}))
        engine.ingest_finding(ORG, **_finding({"resource_id": "r2"}))
        findings = engine.get_findings(ORG)
        assert len(findings) == 2

    def test_filter_by_provider(self, engine):
        engine.ingest_finding(ORG, **_finding({"provider": "aws", "resource_id": "a1"}))
        engine.ingest_finding(ORG, **_finding({"provider": "azure", "resource_id": "a2"}))
        aws = engine.get_findings(ORG, provider="aws")
        assert all(f["provider"] == "aws" for f in aws)
        assert len(aws) == 1

    def test_filter_by_severity(self, engine):
        engine.ingest_finding(ORG, **_finding({"severity": "critical", "resource_id": "c1"}))
        engine.ingest_finding(ORG, **_finding({"severity": "low", "resource_id": "c2"}))
        crits = engine.get_findings(ORG, severity="critical")
        assert len(crits) == 1

    def test_filter_by_status(self, engine):
        r = engine.ingest_finding(ORG, **_finding({"resource_id": "s1"}))
        engine.ingest_finding(ORG, **_finding({"resource_id": "s2"}))
        engine.resolve_finding(r["id"], ORG)
        resolved = engine.get_findings(ORG, status="resolved")
        assert len(resolved) == 1

    def test_org_isolation(self, engine):
        engine.ingest_finding(ORG, **_finding())
        findings = engine.get_findings(ORG2)
        assert findings == []


# ---------------------------------------------------------------------------
# get_finding_summary
# ---------------------------------------------------------------------------

class TestGetFindingSummary:
    def test_total_count(self, engine):
        engine.ingest_finding(ORG, **_finding({"resource_id": "r1"}))
        engine.ingest_finding(ORG, **_finding({"resource_id": "r2"}))
        s = engine.get_finding_summary(ORG)
        assert s["total"] == 2

    def test_by_provider(self, engine):
        engine.ingest_finding(ORG, **_finding({"provider": "aws", "resource_id": "a1"}))
        engine.ingest_finding(ORG, **_finding({"provider": "gcp", "resource_id": "a2"}))
        s = engine.get_finding_summary(ORG)
        assert s["by_provider"]["aws"] == 1
        assert s["by_provider"]["gcp"] == 1

    def test_by_severity(self, engine):
        engine.ingest_finding(ORG, **_finding({"severity": "critical", "resource_id": "c1"}))
        engine.ingest_finding(ORG, **_finding({"severity": "low", "resource_id": "c2"}))
        s = engine.get_finding_summary(ORG)
        assert s["by_severity"]["critical"] == 1
        assert s["by_severity"]["low"] == 1

    def test_by_status(self, engine):
        r = engine.ingest_finding(ORG, **_finding({"resource_id": "s1"}))
        engine.ingest_finding(ORG, **_finding({"resource_id": "s2"}))
        engine.resolve_finding(r["id"], ORG)
        s = engine.get_finding_summary(ORG)
        assert s["by_status"]["open"] == 1
        assert s["by_status"]["resolved"] == 1

    def test_critical_open(self, engine):
        engine.ingest_finding(ORG, **_finding({"severity": "critical", "resource_id": "c1"}))
        r = engine.ingest_finding(ORG, **_finding({"severity": "critical", "resource_id": "c2"}))
        engine.resolve_finding(r["id"], ORG)
        s = engine.get_finding_summary(ORG)
        assert s["critical_open"] == 1

    def test_overdue_remediations(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        # Past due date, not completed
        engine.assign_remediation(r["id"], ORG, "bob", _past_iso(2))
        s = engine.get_finding_summary(ORG)
        assert s["overdue_remediations"] == 1

    def test_overdue_not_counted_if_completed(self, engine):
        r = engine.ingest_finding(ORG, **_finding())
        rem = engine.assign_remediation(r["id"], ORG, "bob", _past_iso(2))
        engine.update_remediation(rem["id"], ORG, "completed")
        s = engine.get_finding_summary(ORG)
        assert s["overdue_remediations"] == 0

    def test_org_isolation(self, engine):
        engine.ingest_finding(ORG, **_finding())
        s = engine.get_finding_summary(ORG2)
        assert s["total"] == 0


# ---------------------------------------------------------------------------
# get_top_affected_resources
# ---------------------------------------------------------------------------

class TestGetTopAffectedResources:
    def test_orders_by_count_desc(self, engine):
        for i in range(3):
            engine.ingest_finding(ORG, **_finding({"resource_id": "hot", "finding_title": f"T{i}"}))
        engine.ingest_finding(ORG, **_finding({"resource_id": "cold", "finding_title": "Solo"}))
        top = engine.get_top_affected_resources(ORG)
        assert top[0]["resource_id"] == "hot"
        assert top[0]["finding_count"] == 3

    def test_respects_limit(self, engine):
        for i in range(5):
            engine.ingest_finding(ORG, **_finding({"resource_id": f"res-{i}", "finding_title": "T"}))
        top = engine.get_top_affected_resources(ORG, limit=3)
        assert len(top) <= 3

    def test_org_isolation(self, engine):
        engine.ingest_finding(ORG, **_finding())
        top = engine.get_top_affected_resources(ORG2)
        assert top == []


# ---------------------------------------------------------------------------
# bulk_ingest
# ---------------------------------------------------------------------------

class TestBulkIngest:
    def test_ingests_new_findings(self, engine):
        findings = [
            _finding({"resource_id": f"r{i}", "finding_title": f"T{i}"})
            for i in range(4)
        ]
        result = engine.bulk_ingest(ORG, findings)
        assert result["ingested"] == 4
        assert result["skipped_duplicates"] == 0

    def test_skips_duplicates(self, engine):
        engine.ingest_finding(ORG, **_finding())
        result = engine.bulk_ingest(ORG, [_finding()])  # same key
        assert result["skipped_duplicates"] == 1
        assert result["ingested"] == 0

    def test_mixed_ingest_and_skip(self, engine):
        engine.ingest_finding(ORG, **_finding({"resource_id": "existing"}))
        findings = [
            _finding({"resource_id": "existing"}),  # dup
            _finding({"resource_id": "new1"}),       # new
            _finding({"resource_id": "new2"}),       # new
        ]
        result = engine.bulk_ingest(ORG, findings)
        assert result["ingested"] == 2
        assert result["skipped_duplicates"] == 1

    def test_empty_list(self, engine):
        result = engine.bulk_ingest(ORG, [])
        assert result["ingested"] == 0
        assert result["skipped_duplicates"] == 0
