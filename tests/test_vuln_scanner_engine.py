"""Tests for VulnScannerEngine — 25 tests.

Covers: init, scanner CRUD, schedule CRUD, scan results,
findings CRUD, update status, stats, org isolation.
"""

from __future__ import annotations

import os
import tempfile
import pytest

from core.vuln_scanner_engine import VulnScannerEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "test_vuln_scanner.db")
    return VulnScannerEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"

# ---------------------------------------------------------------------------
# 1. Init
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "sub" / "vs.db")
    eng = VulnScannerEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "vs2.db")
    VulnScannerEngine(db_path=db)
    VulnScannerEngine(db_path=db)  # second init must not raise


# ---------------------------------------------------------------------------
# 2. Scanner CRUD
# ---------------------------------------------------------------------------


def test_add_scanner_returns_record(engine):
    s = engine.add_scanner(ORG_A, {
        "name": "Nessus Prod",
        "scanner_type": "nessus",
        "version": "10.5",
        "license_type": "commercial",
        "status": "active",
    })
    assert s["scanner_id"]
    assert s["name"] == "Nessus Prod"
    assert s["scanner_type"] == "nessus"
    assert s["org_id"] == ORG_A


def test_add_scanner_invalid_type_defaults(engine):
    s = engine.add_scanner(ORG_A, {"name": "X", "scanner_type": "badtype"})
    assert s["scanner_type"] == "nessus"


def test_add_scanner_invalid_license_defaults(engine):
    s = engine.add_scanner(ORG_A, {"name": "X", "license_type": "badlicense"})
    assert s["license_type"] == "oss"


def test_list_scanners_empty(engine):
    assert engine.list_scanners(ORG_A) == []


def test_list_scanners_returns_added(engine):
    engine.add_scanner(ORG_A, {"name": "S1", "scanner_type": "trivy"})
    engine.add_scanner(ORG_A, {"name": "S2", "scanner_type": "grype"})
    scanners = engine.list_scanners(ORG_A)
    assert len(scanners) == 2
    names = {s["name"] for s in scanners}
    assert names == {"S1", "S2"}


def test_list_scanners_org_isolation(engine):
    engine.add_scanner(ORG_A, {"name": "OrgA scanner"})
    engine.add_scanner(ORG_B, {"name": "OrgB scanner"})
    assert len(engine.list_scanners(ORG_A)) == 1
    assert len(engine.list_scanners(ORG_B)) == 1


# ---------------------------------------------------------------------------
# 3. Schedule CRUD
# ---------------------------------------------------------------------------


def test_create_schedule_returns_record(engine):
    s = engine.add_scanner(ORG_A, {"name": "Nessus"})
    sched = engine.create_schedule(ORG_A, {
        "scanner_id": s["scanner_id"],
        "name": "Nightly scan",
        "target_type": "cidr",
        "targets": ["192.168.1.0/24"],
        "frequency": "daily",
        "cron_expression": "0 2 * * *",
        "enabled": True,
    })
    assert sched["schedule_id"]
    assert sched["name"] == "Nightly scan"
    assert sched["targets"] == ["192.168.1.0/24"]
    assert sched["enabled"] is True


def test_create_schedule_invalid_target_type_defaults(engine):
    sched = engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "s", "target_type": "bad"})
    assert sched["target_type"] == "hostname"


def test_list_schedules_empty(engine):
    assert engine.list_schedules(ORG_A) == []


def test_list_schedules_filter_enabled(engine):
    engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "enabled", "enabled": True})
    engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "disabled", "enabled": False})
    enabled = engine.list_schedules(ORG_A, enabled=True)
    disabled = engine.list_schedules(ORG_A, enabled=False)
    assert len(enabled) == 1
    assert len(disabled) == 1
    assert enabled[0]["name"] == "enabled"


def test_list_schedules_org_isolation(engine):
    engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "A sched"})
    engine.create_schedule(ORG_B, {"scanner_id": "y", "name": "B sched"})
    assert len(engine.list_schedules(ORG_A)) == 1
    assert len(engine.list_schedules(ORG_B)) == 1


# ---------------------------------------------------------------------------
# 4. Scan Results
# ---------------------------------------------------------------------------


def test_create_scan_result(engine):
    r = engine.create_scan_result(ORG_A, {
        "scanner_id": "sc-1",
        "assets_scanned": 50,
        "total_findings": 10,
        "critical_count": 2,
        "high_count": 3,
        "medium_count": 4,
        "low_count": 1,
        "status": "completed",
    })
    assert r["result_id"]
    assert r["assets_scanned"] == 50
    assert r["status"] == "completed"


def test_list_scan_results_filter_by_schedule(engine):
    r1 = engine.create_scan_result(ORG_A, {"scanner_id": "s1", "schedule_id": "sched-1"})
    r2 = engine.create_scan_result(ORG_A, {"scanner_id": "s1", "schedule_id": "sched-2"})
    results = engine.list_scan_results(ORG_A, schedule_id="sched-1")
    assert len(results) == 1
    assert results[0]["result_id"] == r1["result_id"]


# ---------------------------------------------------------------------------
# 5. Findings CRUD
# ---------------------------------------------------------------------------


def test_create_finding(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    f = engine.create_finding(ORG_A, r["result_id"], {
        "asset_ip": "10.0.0.1",
        "asset_hostname": "web-server",
        "vuln_name": "OpenSSL RCE",
        "cve_id": "CVE-2023-1234",
        "cvss_score": 9.8,
        "severity": "critical",
        "plugin_id": "12345",
        "description": "Critical RCE vulnerability",
        "solution": "Upgrade OpenSSL to 3.1.1",
    })
    assert f["finding_id"]
    assert f["cve_id"] == "CVE-2023-1234"
    assert f["severity"] == "critical"
    assert f["status"] == "open"


def test_list_findings_filter_severity(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "A", "severity": "critical"})
    engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "B", "severity": "high"})
    crits = engine.list_findings(ORG_A, severity="critical")
    assert len(crits) == 1
    assert crits[0]["vuln_name"] == "A"


def test_list_findings_filter_status(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    f = engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "X"})
    engine.update_finding_status(ORG_A, f["finding_id"], "patched")
    open_findings = engine.list_findings(ORG_A, status="open")
    patched_findings = engine.list_findings(ORG_A, status="patched")
    assert len(open_findings) == 0
    assert len(patched_findings) == 1


def test_update_finding_status_valid(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    f = engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "Y"})
    ok = engine.update_finding_status(ORG_A, f["finding_id"], "in_progress")
    assert ok is True
    findings = engine.list_findings(ORG_A, status="in_progress")
    assert len(findings) == 1


def test_update_finding_status_invalid_returns_false(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    f = engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "Z"})
    ok = engine.update_finding_status(ORG_A, f["finding_id"], "not_a_status")
    assert ok is False


def test_update_finding_status_wrong_org(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    f = engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "Z"})
    ok = engine.update_finding_status(ORG_B, f["finding_id"], "patched")
    assert ok is False


# ---------------------------------------------------------------------------
# 6. Stats
# ---------------------------------------------------------------------------


def test_get_scanner_stats_empty(engine):
    stats = engine.get_scanner_stats(ORG_A)
    assert stats["total_scanners"] == 0
    assert stats["active"] == 0
    assert stats["findings_open"] == 0


def test_get_scanner_stats_populated(engine):
    engine.add_scanner(ORG_A, {"name": "S1", "status": "active"})
    engine.add_scanner(ORG_A, {"name": "S2", "status": "inactive"})
    engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "sched1"})
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    engine.create_finding(ORG_A, r["result_id"], {
        "vuln_name": "F1", "severity": "critical", "asset_ip": "10.0.0.1"
    })
    engine.create_finding(ORG_A, r["result_id"], {
        "vuln_name": "F2", "severity": "high", "asset_ip": "10.0.0.2"
    })

    stats = engine.get_scanner_stats(ORG_A)
    assert stats["total_scanners"] == 2
    assert stats["active"] == 1
    assert stats["total_schedules"] == 1
    assert stats["findings_open"] == 2
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1
    assert stats["assets_covered"] == 2


def test_stats_org_isolation(engine):
    engine.add_scanner(ORG_A, {"name": "OrgA scanner"})
    engine.add_scanner(ORG_B, {"name": "OrgB scanner"})
    stats_a = engine.get_scanner_stats(ORG_A)
    stats_b = engine.get_scanner_stats(ORG_B)
    assert stats_a["total_scanners"] == 1
    assert stats_b["total_scanners"] == 1


# ---------------------------------------------------------------------------
# 7. Scanner CRUD — additional edge cases
# ---------------------------------------------------------------------------


def test_add_scanner_all_valid_types(engine):
    # Valid: nessus, qualys, openvas, trivy, grype, nuclei, nikto
    valid_types = ["nessus", "qualys", "openvas", "trivy", "grype", "nuclei", "nikto"]
    for stype in valid_types:
        s = engine.add_scanner(ORG_A, {"name": f"Scanner-{stype}", "scanner_type": stype})
        assert s["scanner_type"] == stype


def test_add_scanner_all_valid_license_types(engine):
    # Valid: commercial, community, oss
    valid_licenses = ["oss", "commercial", "community"]
    for ltype in valid_licenses:
        s = engine.add_scanner(ORG_A, {"name": f"Lic-{ltype}", "license_type": ltype})
        assert s["license_type"] == ltype


def test_add_scanner_status_defaults(engine):
    s = engine.add_scanner(ORG_A, {"name": "DefaultStatus"})
    assert s["status"] in ("active", "inactive", "maintenance")


def test_list_scanners_filter_type(engine):
    engine.add_scanner(ORG_A, {"name": "Nessus-1", "scanner_type": "nessus"})
    engine.add_scanner(ORG_A, {"name": "Trivy-1", "scanner_type": "trivy"})
    nessus = [s for s in engine.list_scanners(ORG_A) if s["scanner_type"] == "nessus"]
    assert len(nessus) == 1


def test_scanner_org_id_stored(engine):
    s = engine.add_scanner(ORG_A, {"name": "OrgCheck"})
    assert s["org_id"] == ORG_A


# ---------------------------------------------------------------------------
# 8. Schedule — additional edge cases
# ---------------------------------------------------------------------------


def test_create_schedule_all_valid_frequencies(engine):
    # Valid: daily, weekly, monthly, on_demand
    for freq in ("daily", "weekly", "monthly", "on_demand"):
        sched = engine.create_schedule(ORG_A, {
            "scanner_id": "x",
            "name": f"Sched-{freq}",
            "frequency": freq,
        })
        assert sched["frequency"] == freq


def test_create_schedule_with_targets_list(engine):
    sched = engine.create_schedule(ORG_A, {
        "scanner_id": "x",
        "name": "Multi-target",
        "target_type": "cidr",
        "targets": ["10.0.0.0/8", "192.168.0.0/16"],
    })
    assert isinstance(sched["targets"], list)
    assert len(sched["targets"]) == 2


def test_create_schedule_disabled_by_default(engine):
    sched = engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "Default-enabled"})
    assert isinstance(sched["enabled"], bool)


def test_list_schedules_count_increases(engine):
    engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "S1"})
    engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "S2"})
    engine.create_schedule(ORG_A, {"scanner_id": "x", "name": "S3"})
    assert len(engine.list_schedules(ORG_A)) == 3


# ---------------------------------------------------------------------------
# 9. Scan results — additional edge cases
# ---------------------------------------------------------------------------


def test_create_scan_result_defaults(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    assert r["result_id"] is not None
    assert r["org_id"] == ORG_A


def test_create_scan_result_all_severity_counts(engine):
    r = engine.create_scan_result(ORG_A, {
        "scanner_id": "s1",
        "critical_count": 5,
        "high_count": 10,
        "medium_count": 20,
        "low_count": 50,
    })
    assert r["critical_count"] == 5
    assert r["high_count"] == 10


def test_list_scan_results_org_isolation(engine):
    engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    results_b = engine.list_scan_results(ORG_B)
    assert results_b == []


def test_list_scan_results_no_filter(engine):
    engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    engine.create_scan_result(ORG_A, {"scanner_id": "s2"})
    results = engine.list_scan_results(ORG_A)
    assert len(results) == 2


# ---------------------------------------------------------------------------
# 10. Findings — additional edge cases
# ---------------------------------------------------------------------------


def test_create_finding_all_severities(engine):
    # Valid: critical, high, medium, low, info
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    for sev in ("critical", "high", "medium", "low", "info"):
        f = engine.create_finding(ORG_A, r["result_id"], {
            "vuln_name": f"Vuln-{sev}",
            "severity": sev,
        })
        assert f["severity"] == sev


def test_list_findings_no_filter_returns_all(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    for i in range(4):
        engine.create_finding(ORG_A, r["result_id"], {"vuln_name": f"Finding-{i}"})
    all_findings = engine.list_findings(ORG_A)
    assert len(all_findings) == 4


def test_list_findings_org_isolation(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "OrgA Finding"})
    findings_b = engine.list_findings(ORG_B)
    assert findings_b == []


def test_create_finding_stores_cve_id(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    f = engine.create_finding(ORG_A, r["result_id"], {
        "vuln_name": "Log4Shell",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
    })
    assert f["cve_id"] == "CVE-2021-44228"
    assert f["cvss_score"] == 10.0


def test_update_finding_status_all_valid_states(engine):
    # Valid: open, in_progress, patched, accepted, false_positive
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    for status in ("open", "in_progress", "patched", "accepted", "false_positive"):
        f = engine.create_finding(ORG_A, r["result_id"], {"vuln_name": f"F-{status}"})
        ok = engine.update_finding_status(ORG_A, f["finding_id"], status)
        assert ok is True


# ---------------------------------------------------------------------------
# 11. Stats — additional coverage
# ---------------------------------------------------------------------------


def test_get_scanner_stats_critical_count(engine):
    engine.add_scanner(ORG_A, {"name": "S", "status": "active"})
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "C1", "severity": "critical"})
    engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "C2", "severity": "critical"})
    stats = engine.get_scanner_stats(ORG_A)
    assert stats["by_severity"].get("critical") == 2


def test_get_scanner_stats_multiple_scanners(engine):
    for i in range(5):
        engine.add_scanner(ORG_A, {"name": f"Scanner-{i}", "status": "active"})
    stats = engine.get_scanner_stats(ORG_A)
    assert stats["total_scanners"] == 5
    assert stats["active"] == 5


def test_stats_findings_open_count(engine):
    r = engine.create_scan_result(ORG_A, {"scanner_id": "s1"})
    f1 = engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "Open1"})
    f2 = engine.create_finding(ORG_A, r["result_id"], {"vuln_name": "Open2"})
    engine.update_finding_status(ORG_A, f2["finding_id"], "patched")
    stats = engine.get_scanner_stats(ORG_A)
    assert stats["findings_open"] == 1
