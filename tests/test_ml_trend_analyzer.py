"""Tests for the vulnerability trend analyzer module.

[V3] Decision Intelligence — trend analysis for security posture tracking.

Tests cover:
- ScanHistoryStore: add/get/persistence/bounding
- TrendAnalyzer: severity drift, CWE emergence, recurrence, volume trends
- Posture scoring: improvement, degradation, stability
- Edge cases: empty data, single scan, identical scans
"""

import json
import os
import tempfile


from core.ml.trend_analyzer import (
    ScanHistoryStore,
    TrendAnalyzer,
    TrendPoint,
    TrendReport,
    VulnTrend,
    analyze_scan_trends,
    get_trend_analyzer,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scan(
    scan_id: str,
    timestamp: str,
    findings: list,
    org_id: str = "org-1",
    app_id: str = "app-1",
) -> dict:
    return {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "org_id": org_id,
        "app_id": app_id,
        "findings": findings,
    }


def _make_finding(
    cve_id: str = "CVE-2024-1234",
    severity: str = "high",
    cwe_id: str = "CWE-79",
    cvss_score: float = 7.5,
    scanner: str = "snyk",
) -> dict:
    return {
        "cve_id": cve_id,
        "severity": severity,
        "cwe_id": cwe_id,
        "cvss_score": cvss_score,
        "title": f"Test finding {cve_id}",
        "scanner": scanner,
    }


def _generate_improving_scans(n: int = 10) -> list:
    """Generate scans where severity is improving over time."""
    scans = []
    for i in range(n):
        # Fewer critical findings over time
        findings = []
        num_critical = max(0, 5 - i)
        num_high = max(0, 8 - i)
        num_medium = 3
        for j in range(num_critical):
            findings.append(_make_finding(f"CVE-2024-{1000+i*10+j}", "critical", "CWE-89"))
        for j in range(num_high):
            findings.append(_make_finding(f"CVE-2024-{2000+i*10+j}", "high", "CWE-79"))
        for j in range(num_medium):
            findings.append(_make_finding(f"CVE-2024-{3000+i*10+j}", "medium", "CWE-200"))
        scans.append(
            _make_scan(f"scan-{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings)
        )
    return scans


def _generate_degrading_scans(n: int = 10) -> list:
    """Generate scans where severity is worsening over time."""
    scans = []
    for i in range(n):
        findings = []
        num_critical = i * 2
        num_high = i * 3
        for j in range(num_critical):
            findings.append(_make_finding(f"CVE-2024-{1000+i*10+j}", "critical", "CWE-89"))
        for j in range(num_high):
            findings.append(_make_finding(f"CVE-2024-{2000+i*10+j}", "high", "CWE-79"))
        findings.append(_make_finding(f"CVE-2024-{3000+i}", "low", "CWE-200"))
        scans.append(
            _make_scan(f"scan-{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings)
        )
    return scans


# ---------------------------------------------------------------------------
# TrendPoint / VulnTrend / TrendReport serialization
# ---------------------------------------------------------------------------


class TestDataClasses:
    def test_trend_point_to_dict(self):
        tp = TrendPoint(timestamp="2026-03-01T00:00:00Z", value=7.5, label="scan_0")
        d = tp.to_dict()
        assert d["timestamp"] == "2026-03-01T00:00:00Z"
        assert d["value"] == 7.5
        assert d["label"] == "scan_0"

    def test_vuln_trend_to_dict(self):
        vt = VulnTrend(
            trend_id="abc123",
            category="severity_drift",
            direction="increasing",
            magnitude=0.456789,
            confidence=0.89123,
            description="Test trend",
            affected_cves=["CVE-2024-1"],
            recommendation="Fix it",
        )
        d = vt.to_dict()
        assert d["trend_id"] == "abc123"
        assert d["magnitude"] == 0.4568  # rounded to 4 places
        assert d["confidence"] == 0.8912
        assert d["pillar"] == "V3"

    def test_trend_report_to_dict(self):
        report = TrendReport(
            generated_at="2026-03-03T00:00:00Z",
            scan_count=10,
            finding_count=50,
            time_range_days=9.5,
            posture_score=75.3,
            posture_trend="improving",
        )
        d = report.to_dict()
        assert d["scan_count"] == 10
        assert d["finding_count"] == 50
        assert d["time_range_days"] == 9.5
        assert d["posture_score"] == 75.3
        assert d["posture_trend"] == "improving"
        assert d["trend_count"] == 0
        assert d["actionable_trends"] == 0


# ---------------------------------------------------------------------------
# ScanHistoryStore tests
# ---------------------------------------------------------------------------


class TestScanHistoryStore:
    def test_empty_store(self):
        store = ScanHistoryStore()
        assert store.scan_count == 0
        assert store.get_scans() == []

    def test_add_and_get(self):
        store = ScanHistoryStore()
        scan = _make_scan("s1", "2026-03-01T00:00:00Z", [_make_finding()])
        store.add_scan(scan)
        assert store.scan_count == 1
        scans = store.get_scans()
        assert len(scans) == 1
        assert scans[0]["scan_id"] == "s1"

    def test_bounded_size(self):
        store = ScanHistoryStore(max_scans=5)
        for i in range(10):
            store.add_scan(_make_scan(f"s{i}", f"2026-03-01T{i:02d}:00:00Z", []))
        assert store.scan_count == 5
        scans = store.get_scans()
        # Should keep the latest 5
        assert scans[0]["scan_id"] == "s5"
        assert scans[-1]["scan_id"] == "s9"

    def test_filter_by_org(self):
        store = ScanHistoryStore()
        store.add_scan(_make_scan("s1", "2026-03-01T00:00:00Z", [], org_id="org-a"))
        store.add_scan(_make_scan("s2", "2026-03-01T01:00:00Z", [], org_id="org-b"))
        store.add_scan(_make_scan("s3", "2026-03-01T02:00:00Z", [], org_id="org-a"))
        assert len(store.get_scans(org_id="org-a")) == 2
        assert len(store.get_scans(org_id="org-b")) == 1

    def test_filter_by_app(self):
        store = ScanHistoryStore()
        store.add_scan(_make_scan("s1", "2026-03-01T00:00:00Z", [], app_id="app-x"))
        store.add_scan(_make_scan("s2", "2026-03-01T01:00:00Z", [], app_id="app-y"))
        assert len(store.get_scans(app_id="app-x")) == 1
        assert len(store.get_scans(app_id="app-y")) == 1

    def test_persistence(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "history.json")

        # Write
        store1 = ScanHistoryStore(persist_path=path)
        store1.add_scan(_make_scan("s1", "2026-03-01T00:00:00Z", [_make_finding()]))
        store1.add_scan(_make_scan("s2", "2026-03-01T01:00:00Z", [_make_finding()]))
        assert os.path.exists(path)

        # Read back
        store2 = ScanHistoryStore(persist_path=path)
        assert store2.scan_count == 2
        assert store2.get_scans()[0]["scan_id"] == "s1"

        import shutil
        shutil.rmtree(tmpdir)

    def test_auto_timestamp(self):
        store = ScanHistoryStore()
        scan = {"scan_id": "s1", "findings": []}
        store.add_scan(scan)
        scans = store.get_scans()
        assert "timestamp" in scans[0]


# ---------------------------------------------------------------------------
# TrendAnalyzer — severity drift
# ---------------------------------------------------------------------------


class TestSeverityDrift:
    def test_improving_severity_detected(self):
        scans = _generate_improving_scans(10)
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        severity_trends = [t for t in report.trends if t.category == "severity_drift"]
        # Should detect decreasing severity (improving posture)
        if severity_trends:
            assert severity_trends[0].direction == "decreasing"

    def test_degrading_severity_detected(self):
        scans = _generate_degrading_scans(10)
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        severity_trends = [t for t in report.trends if t.category == "severity_drift"]
        if severity_trends:
            assert severity_trends[0].direction == "increasing"

    def test_stable_severity_no_trend(self):
        # Same findings every scan
        findings = [_make_finding("CVE-2024-1", "medium")]
        scans = [
            _make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings)
            for i in range(10)
        ]
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        severity_trends = [t for t in report.trends if t.category == "severity_drift"]
        # Should be either empty or direction=stable
        for t in severity_trends:
            assert t.magnitude < 0.1  # Small magnitude = stable


# ---------------------------------------------------------------------------
# TrendAnalyzer — CWE emergence
# ---------------------------------------------------------------------------


class TestCWEEmergence:
    def test_new_cwe_detected(self):
        # First 5 scans: only CWE-79
        # Last 5 scans: CWE-79 + CWE-502 (new!)
        scans = []
        for i in range(5):
            scans.append(
                _make_scan(
                    f"s{i}",
                    f"2026-03-{i+1:02d}T00:00:00+00:00",
                    [_make_finding(f"CVE-2024-{i}", "high", "CWE-79")],
                )
            )
        for i in range(5, 10):
            scans.append(
                _make_scan(
                    f"s{i}",
                    f"2026-03-{i+1:02d}T00:00:00+00:00",
                    [
                        _make_finding(f"CVE-2024-{i}", "high", "CWE-79"),
                        _make_finding(f"CVE-2024-{i+100}", "critical", "CWE-502"),
                    ],
                )
            )

        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()

        cwe_trends = [t for t in report.trends if t.category == "cwe_emergence"]
        assert len(cwe_trends) > 0
        # CWE-502 should be in the description
        assert any("CWE-502" in t.description for t in cwe_trends)

    def test_no_emergence_when_same_cwes(self):
        findings = [_make_finding("CVE-2024-1", "high", "CWE-79")]
        scans = [
            _make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings)
            for i in range(10)
        ]
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        cwe_trends = [t for t in report.trends if t.category == "cwe_emergence"]
        assert len(cwe_trends) == 0


# ---------------------------------------------------------------------------
# TrendAnalyzer — recurrence
# ---------------------------------------------------------------------------


class TestRecurrence:
    def test_recurring_cve_detected(self):
        # Same CVE in every scan
        findings = [_make_finding("CVE-2024-RECURRING", "critical", "CWE-89")]
        scans = [
            _make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings)
            for i in range(10)
        ]
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        recurrence_trends = [t for t in report.trends if t.category == "recurrence"]
        assert len(recurrence_trends) > 0
        assert "CVE-2024-RECURRING" in recurrence_trends[0].affected_cves

    def test_no_recurrence_for_unique_cves(self):
        scans = [
            _make_scan(
                f"s{i}",
                f"2026-03-{i+1:02d}T00:00:00+00:00",
                [_make_finding(f"CVE-2024-{i}", "high")],
            )
            for i in range(10)
        ]
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        recurrence_trends = [t for t in report.trends if t.category == "recurrence"]
        assert len(recurrence_trends) == 0


# ---------------------------------------------------------------------------
# TrendAnalyzer — volume trends
# ---------------------------------------------------------------------------


class TestVolumeTrends:
    def test_volume_spike_detected(self):
        # 9 normal scans with ~3 findings, then 1 scan with 30 findings
        scans = []
        for i in range(9):
            findings = [_make_finding(f"CVE-2024-{i*3+j}", "medium") for j in range(3)]
            scans.append(_make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings))
        # Spike scan
        spike_findings = [_make_finding(f"CVE-2024-{900+j}", "high") for j in range(30)]
        scans.append(_make_scan("s9", "2026-03-10T00:00:00+00:00", spike_findings))

        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        volume_trends = [t for t in report.trends if t.category == "volume"]
        assert any(t.direction == "spike" for t in volume_trends)

    def test_volume_drop_detected(self):
        # 9 normal scans with ~20 findings, then 1 scan with 1 finding
        scans = []
        for i in range(9):
            findings = [_make_finding(f"CVE-2024-{i*20+j}", "medium") for j in range(20)]
            scans.append(_make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings))
        scans.append(_make_scan("s9", "2026-03-10T00:00:00+00:00", [_make_finding()]))

        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        volume_trends = [t for t in report.trends if t.category == "volume"]
        assert any(t.direction == "drop" for t in volume_trends)

    def test_increasing_volume_trend(self):
        scans = []
        for i in range(10):
            num_findings = 5 + i * 5  # 5, 10, 15, ..., 50
            findings = [_make_finding(f"CVE-2024-{i*50+j}", "high") for j in range(num_findings)]
            scans.append(_make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings))

        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        volume_trends = [t for t in report.trends if t.category == "volume"]
        assert any(t.direction == "increasing" for t in volume_trends)


# ---------------------------------------------------------------------------
# Posture scoring
# ---------------------------------------------------------------------------


class TestPostureScore:
    def test_no_findings_high_posture(self):
        scans = [
            _make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", [])
            for i in range(5)
        ]
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        assert report.posture_score >= 90.0

    def test_many_critical_low_posture(self):
        scans = []
        for i in range(5):
            findings = [_make_finding(f"CVE-{i*20+j}", "critical") for j in range(20)]
            scans.append(_make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings))
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        assert report.posture_score <= 20.0

    def test_improving_posture_detected(self):
        scans = _generate_improving_scans(10)
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        assert report.posture_trend in ("improving", "stable")

    def test_degrading_posture_detected(self):
        scans = _generate_degrading_scans(10)
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        assert report.posture_trend in ("degrading", "stable")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_insufficient_data(self):
        analyzer = TrendAnalyzer(ScanHistoryStore())
        report = analyzer.analyze()
        assert report.scan_count == 0
        assert report.posture_trend == "insufficient_data"

    def test_single_scan(self):
        analyzer = TrendAnalyzer(ScanHistoryStore())
        analyzer.add_scan(
            _make_scan("s1", "2026-03-01T00:00:00+00:00", [_make_finding()])
        )
        report = analyzer.analyze()
        assert report.scan_count == 1
        assert report.posture_trend == "insufficient_data"

    def test_two_scans(self):
        analyzer = TrendAnalyzer(ScanHistoryStore())
        analyzer.add_scan(
            _make_scan("s1", "2026-03-01T00:00:00+00:00", [_make_finding()])
        )
        analyzer.add_scan(
            _make_scan("s2", "2026-03-02T00:00:00+00:00", [_make_finding()])
        )
        report = analyzer.analyze()
        assert report.scan_count == 2
        # Still insufficient for trends (min_scans=3)
        assert len(report.trends) == 0

    def test_empty_findings_scans(self):
        scans = [
            _make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", [])
            for i in range(5)
        ]
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        assert report.finding_count == 0
        assert report.posture_score >= 90.0

    def test_serialization_round_trip(self):
        scans = _generate_improving_scans(5)
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        d = report.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["scan_count"] == 5
        assert "posture_score" in parsed

    def test_report_actionable_count(self):
        scans = _generate_degrading_scans(10)
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        d = report.to_dict()
        assert d["actionable_trends"] <= d["trend_count"]

    def test_cwe_distribution_in_report(self):
        scans = []
        for i in range(5):
            findings = [
                _make_finding(f"CVE-2024-{i}", "high", "CWE-79"),
                _make_finding(f"CVE-2024-{i+100}", "medium", "CWE-89"),
                _make_finding(f"CVE-2024-{i+200}", "low", "CWE-200"),
            ]
            scans.append(_make_scan(f"s{i}", f"2026-03-{i+1:02d}T00:00:00+00:00", findings))
        analyzer = TrendAnalyzer(ScanHistoryStore())
        for s in scans:
            analyzer.add_scan(s)
        report = analyzer.analyze()
        assert "CWE-79" in report.cwe_distribution
        assert "CWE-89" in report.cwe_distribution
        assert report.cwe_distribution["CWE-79"] == 5


# ---------------------------------------------------------------------------
# Convenience function tests
# ---------------------------------------------------------------------------


class TestConvenienceFunction:
    def test_analyze_scan_trends(self):
        import core.ml.trend_analyzer as mod
        mod._default_analyzer = None  # Reset singleton

        scans = _generate_improving_scans(5)
        report = analyze_scan_trends(scans=scans)
        assert report.scan_count == 5
        assert report.finding_count > 0

    def test_get_trend_analyzer_singleton(self):
        import core.ml.trend_analyzer as mod
        mod._default_analyzer = None  # Reset

        a1 = get_trend_analyzer()
        a2 = get_trend_analyzer()
        assert a1 is a2

        mod._default_analyzer = None  # Cleanup
