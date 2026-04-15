"""Tests for VulnScanEngine — 35+ tests."""

from __future__ import annotations

import pytest
from core.vuln_scan_engine import VulnScanEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_vuln_scan.db")
    return VulnScanEngine(db_path=db)


ORG = "org-test"
ORG2 = "org-other"


def _make_scan(engine, name="Weekly Scan", target="10.0.0.0/24",
               scanner_type="nessus", scan_status="pending"):
    return engine.create_scan(ORG, {
        "scan_name": name,
        "target": target,
        "scanner_type": scanner_type,
        "scan_status": scan_status,
    })


def _make_finding(engine, scan_id, title="SQL Injection", severity="high",
                  status="open"):
    return engine.add_finding(ORG, scan_id, {
        "title": title,
        "severity": severity,
        "finding_status": status,
    })


# ---------------------------------------------------------------------------
# create_scan
# ---------------------------------------------------------------------------

class TestCreateScan:
    def test_create_scan_minimal(self, engine):
        s = _make_scan(engine)
        assert s["id"]
        assert s["scan_name"] == "Weekly Scan"
        assert s["scanner_type"] == "nessus"
        assert s["scan_status"] == "pending"
        assert s["findings_count"] == 0
        assert s["critical_count"] == 0
        assert s["high_count"] == 0

    def test_create_scan_all_fields(self, engine):
        s = engine.create_scan(ORG, {
            "scan_name": "Full Scan",
            "target": "192.168.1.0/24",
            "scanner_type": "qualys",
            "scan_status": "running",
            "scanner_version": "2.5.1",
            "started_at": "2026-01-01T00:00:00Z",
        })
        assert s["scanner_version"] == "2.5.1"
        assert s["scanner_type"] == "qualys"
        assert s["scan_status"] == "running"

    def test_create_scan_missing_name(self, engine):
        with pytest.raises(ValueError, match="scan_name"):
            engine.create_scan(ORG, {"target": "10.0.0.1"})

    def test_create_scan_missing_target(self, engine):
        with pytest.raises(ValueError, match="target"):
            engine.create_scan(ORG, {"scan_name": "Test"})

    def test_create_scan_invalid_scanner_type(self, engine):
        with pytest.raises(ValueError, match="scanner_type"):
            engine.create_scan(ORG, {
                "scan_name": "X", "target": "Y", "scanner_type": "badscanner",
            })

    def test_create_scan_invalid_status(self, engine):
        with pytest.raises(ValueError, match="scan_status"):
            engine.create_scan(ORG, {
                "scan_name": "X", "target": "Y", "scan_status": "unknown",
            })

    def test_create_scan_all_scanner_types(self, engine):
        types = ["nessus", "qualys", "rapid7", "openvas", "nuclei", "trivy", "grype", "custom"]
        for st in types:
            s = engine.create_scan(ORG, {
                "scan_name": f"scan-{st}", "target": "t", "scanner_type": st,
            })
            assert s["scanner_type"] == st

    def test_create_scan_default_scanner(self, engine):
        s = engine.create_scan(ORG, {"scan_name": "X", "target": "Y"})
        assert s["scanner_type"] == "custom"


# ---------------------------------------------------------------------------
# list_scans / get_scan
# ---------------------------------------------------------------------------

class TestListGetScans:
    def _seed(self, engine):
        s1 = _make_scan(engine, "Scan A", scanner_type="nessus", scan_status="completed")
        s2 = _make_scan(engine, "Scan B", scanner_type="qualys", scan_status="running")
        s3 = _make_scan(engine, "Scan C", scanner_type="nessus", scan_status="pending")
        return s1, s2, s3

    def test_list_all(self, engine):
        self._seed(engine)
        scans = engine.list_scans(ORG)
        assert len(scans) == 3

    def test_list_filter_scanner_type(self, engine):
        self._seed(engine)
        scans = engine.list_scans(ORG, scanner_type="nessus")
        assert len(scans) == 2
        assert all(s["scanner_type"] == "nessus" for s in scans)

    def test_list_filter_status(self, engine):
        self._seed(engine)
        scans = engine.list_scans(ORG, scan_status="completed")
        assert len(scans) == 1
        assert scans[0]["scan_name"] == "Scan A"

    def test_list_filter_both(self, engine):
        self._seed(engine)
        scans = engine.list_scans(ORG, scanner_type="nessus", scan_status="pending")
        assert len(scans) == 1

    def test_list_org_isolation(self, engine):
        self._seed(engine)
        engine.create_scan(ORG2, {"scan_name": "Z", "target": "Z"})
        assert len(engine.list_scans(ORG)) == 3
        assert len(engine.list_scans(ORG2)) == 1

    def test_get_scan_found(self, engine):
        s1, _, _ = self._seed(engine)
        s = engine.get_scan(ORG, s1["id"])
        assert s is not None
        assert s["scan_name"] == "Scan A"

    def test_get_scan_not_found(self, engine):
        assert engine.get_scan(ORG, "nonexistent") is None

    def test_get_scan_org_isolation(self, engine):
        s1, _, _ = self._seed(engine)
        assert engine.get_scan(ORG2, s1["id"]) is None


# ---------------------------------------------------------------------------
# update_scan_status
# ---------------------------------------------------------------------------

class TestUpdateScanStatus:
    def test_update_status(self, engine):
        s = _make_scan(engine)
        updated = engine.update_scan_status(ORG, s["id"], "running")
        assert updated["scan_status"] == "running"

    def test_update_status_with_completed_at(self, engine):
        s = _make_scan(engine)
        updated = engine.update_scan_status(
            ORG, s["id"], "completed", completed_at="2026-01-01T12:00:00Z"
        )
        assert updated["scan_status"] == "completed"
        assert updated["completed_at"] == "2026-01-01T12:00:00Z"

    def test_update_status_invalid(self, engine):
        s = _make_scan(engine)
        with pytest.raises(ValueError, match="scan_status"):
            engine.update_scan_status(ORG, s["id"], "bogus")

    def test_update_status_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.update_scan_status(ORG, "bad-id", "completed")

    def test_update_all_statuses(self, engine):
        s = _make_scan(engine)
        for status in ["running", "completed", "failed", "cancelled", "pending"]:
            updated = engine.update_scan_status(ORG, s["id"], status)
            assert updated["scan_status"] == status


# ---------------------------------------------------------------------------
# add_finding
# ---------------------------------------------------------------------------

class TestAddFinding:
    def test_add_finding_minimal(self, engine):
        s = _make_scan(engine)
        f = _make_finding(engine, s["id"])
        assert f["id"]
        assert f["title"] == "SQL Injection"
        assert f["severity"] == "high"
        assert f["finding_status"] == "open"
        assert f["cvss_score"] == 0.0

    def test_add_finding_all_fields(self, engine):
        s = _make_scan(engine)
        f = engine.add_finding(ORG, s["id"], {
            "title": "Log4Shell",
            "severity": "critical",
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "finding_status": "in_progress",
            "affected_asset": "app-server-01",
            "plugin_id": "nessus-123456",
            "description": "Critical JNDI injection",
            "remediation": "Update log4j to 2.17.1",
        })
        assert f["cve_id"] == "CVE-2021-44228"
        assert f["cvss_score"] == 10.0
        assert f["affected_asset"] == "app-server-01"

    def test_add_finding_missing_title(self, engine):
        s = _make_scan(engine)
        with pytest.raises(ValueError, match="title"):
            engine.add_finding(ORG, s["id"], {"severity": "high"})

    def test_add_finding_missing_severity(self, engine):
        s = _make_scan(engine)
        with pytest.raises(ValueError, match="severity"):
            engine.add_finding(ORG, s["id"], {"title": "Test"})

    def test_add_finding_invalid_severity(self, engine):
        s = _make_scan(engine)
        with pytest.raises(ValueError, match="severity"):
            engine.add_finding(ORG, s["id"], {"title": "X", "severity": "extreme"})

    def test_add_finding_invalid_status(self, engine):
        s = _make_scan(engine)
        with pytest.raises(ValueError, match="finding_status"):
            engine.add_finding(ORG, s["id"], {
                "title": "X", "severity": "high", "finding_status": "bad",
            })

    def test_add_finding_increments_findings_count(self, engine):
        s = _make_scan(engine)
        _make_finding(engine, s["id"])
        _make_finding(engine, s["id"])
        updated = engine.get_scan(ORG, s["id"])
        assert updated["findings_count"] == 2

    def test_add_finding_increments_critical_count(self, engine):
        s = _make_scan(engine)
        _make_finding(engine, s["id"], severity="critical")
        _make_finding(engine, s["id"], severity="critical")
        _make_finding(engine, s["id"], severity="high")
        updated = engine.get_scan(ORG, s["id"])
        assert updated["critical_count"] == 2
        assert updated["high_count"] == 1
        assert updated["findings_count"] == 3

    def test_add_finding_non_critical_no_increment(self, engine):
        s = _make_scan(engine)
        _make_finding(engine, s["id"], severity="medium")
        _make_finding(engine, s["id"], severity="low")
        _make_finding(engine, s["id"], severity="info")
        updated = engine.get_scan(ORG, s["id"])
        assert updated["critical_count"] == 0
        assert updated["high_count"] == 0

    def test_add_finding_all_severities(self, engine):
        s = _make_scan(engine)
        for sev in ["critical", "high", "medium", "low", "info"]:
            f = engine.add_finding(ORG, s["id"], {"title": sev, "severity": sev})
            assert f["severity"] == sev


# ---------------------------------------------------------------------------
# list_findings / update_finding_status
# ---------------------------------------------------------------------------

class TestListFindingsAndUpdateStatus:
    def _seed(self, engine):
        s1 = _make_scan(engine, "S1")
        s2 = _make_scan(engine, "S2")
        f1 = _make_finding(engine, s1["id"], "F1", severity="critical", status="open")
        f2 = _make_finding(engine, s1["id"], "F2", severity="high", status="in_progress")
        f3 = _make_finding(engine, s2["id"], "F3", severity="critical", status="open")
        return s1, s2, f1, f2, f3

    def test_list_findings_all(self, engine):
        self._seed(engine)
        findings = engine.list_findings(ORG)
        assert len(findings) == 3

    def test_list_findings_filter_scan(self, engine):
        s1, s2, f1, f2, f3 = self._seed(engine)
        findings = engine.list_findings(ORG, scan_id=s1["id"])
        assert len(findings) == 2

    def test_list_findings_filter_severity(self, engine):
        self._seed(engine)
        findings = engine.list_findings(ORG, severity="critical")
        assert len(findings) == 2

    def test_list_findings_filter_status(self, engine):
        self._seed(engine)
        findings = engine.list_findings(ORG, finding_status="in_progress")
        assert len(findings) == 1

    def test_list_findings_filter_multiple(self, engine):
        s1, s2, f1, f2, f3 = self._seed(engine)
        findings = engine.list_findings(
            ORG, scan_id=s1["id"], severity="critical"
        )
        assert len(findings) == 1
        assert findings[0]["title"] == "F1"

    def test_list_findings_org_isolation(self, engine):
        self._seed(engine)
        engine.create_scan.__doc__  # just a call to ensure engine is used
        s_other = engine.create_scan(ORG2, {"scan_name": "Z", "target": "Z"})
        engine.add_finding(ORG2, s_other["id"], {"title": "X", "severity": "low"})
        assert len(engine.list_findings(ORG)) == 3
        assert len(engine.list_findings(ORG2)) == 1

    def test_update_finding_status(self, engine):
        s = _make_scan(engine)
        f = _make_finding(engine, s["id"])
        updated = engine.update_finding_status(ORG, f["id"], "resolved")
        assert updated["finding_status"] == "resolved"
        assert updated["resolved_at"] is not None

    def test_update_finding_status_non_resolved_no_resolved_at(self, engine):
        s = _make_scan(engine)
        f = _make_finding(engine, s["id"])
        updated = engine.update_finding_status(ORG, f["id"], "in_progress")
        assert updated["resolved_at"] is None

    def test_update_finding_status_invalid(self, engine):
        s = _make_scan(engine)
        f = _make_finding(engine, s["id"])
        with pytest.raises(ValueError, match="finding_status"):
            engine.update_finding_status(ORG, f["id"], "bogus")

    def test_update_finding_status_not_found(self, engine):
        with pytest.raises(KeyError):
            engine.update_finding_status(ORG, "bad-id", "resolved")

    def test_update_finding_all_statuses(self, engine):
        s = _make_scan(engine)
        f = _make_finding(engine, s["id"])
        for status in ["in_progress", "resolved", "accepted_risk", "false_positive", "open"]:
            updated = engine.update_finding_status(ORG, f["id"], status)
            assert updated["finding_status"] == status


# ---------------------------------------------------------------------------
# get_scan_stats
# ---------------------------------------------------------------------------

class TestScanStats:
    def test_empty_stats(self, engine):
        stats = engine.get_scan_stats(ORG)
        assert stats["total_scans"] == 0
        assert stats["completed_scans"] == 0
        assert stats["total_findings"] == 0
        assert stats["open_findings"] == 0
        assert stats["critical_open"] == 0
        assert stats["by_scanner"] == {}
        assert stats["by_severity"] == {}

    def test_stats_total_scans(self, engine):
        _make_scan(engine)
        _make_scan(engine, "S2")
        stats = engine.get_scan_stats(ORG)
        assert stats["total_scans"] == 2

    def test_stats_completed_scans(self, engine):
        s1 = _make_scan(engine, "S1")
        s2 = _make_scan(engine, "S2")
        engine.update_scan_status(ORG, s1["id"], "completed")
        stats = engine.get_scan_stats(ORG)
        assert stats["completed_scans"] == 1

    def test_stats_total_and_open_findings(self, engine):
        s = _make_scan(engine)
        _make_finding(engine, s["id"], severity="high", status="open")
        _make_finding(engine, s["id"], severity="medium", status="resolved")
        stats = engine.get_scan_stats(ORG)
        assert stats["total_findings"] == 2
        assert stats["open_findings"] == 1

    def test_stats_critical_open(self, engine):
        s = _make_scan(engine)
        _make_finding(engine, s["id"], severity="critical", status="open")
        _make_finding(engine, s["id"], severity="critical", status="resolved")
        _make_finding(engine, s["id"], severity="high", status="open")
        stats = engine.get_scan_stats(ORG)
        assert stats["critical_open"] == 1

    def test_stats_by_scanner(self, engine):
        _make_scan(engine, "A", scanner_type="nessus")
        _make_scan(engine, "B", scanner_type="nessus")
        _make_scan(engine, "C", scanner_type="trivy")
        stats = engine.get_scan_stats(ORG)
        assert stats["by_scanner"]["nessus"] == 2
        assert stats["by_scanner"]["trivy"] == 1

    def test_stats_by_severity(self, engine):
        s = _make_scan(engine)
        _make_finding(engine, s["id"], severity="critical")
        _make_finding(engine, s["id"], severity="critical")
        _make_finding(engine, s["id"], severity="high")
        stats = engine.get_scan_stats(ORG)
        assert stats["by_severity"]["critical"] == 2
        assert stats["by_severity"]["high"] == 1

    def test_stats_org_isolation(self, engine):
        _make_scan(engine)
        engine.create_scan(ORG2, {"scan_name": "Z", "target": "Z"})
        assert engine.get_scan_stats(ORG)["total_scans"] == 1
        assert engine.get_scan_stats(ORG2)["total_scans"] == 1
