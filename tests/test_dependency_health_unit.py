"""Tests for risk.dependency_health module — DependencyHealthMonitor.

Covers: health monitoring, maintenance status, security posture,
health scoring, recommendations, bulk monitoring.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from risk.dependency_health import (
    DependencyHealth,
    DependencyHealthMonitor,
    DependencyHealthReport,
    MaintenanceStatus,
    SecurityPosture,
)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def monitor() -> DependencyHealthMonitor:
    return DependencyHealthMonitor()


def _recent_date(days_ago: int = 5) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


# ── Data classes ──────────────────────────────────────────────────────────


class TestDataClasses:
    def test_maintenance_status_values(self):
        assert MaintenanceStatus.ACTIVE.value == "active"
        assert MaintenanceStatus.ABANDONED.value == "abandoned"

    def test_security_posture_values(self):
        assert SecurityPosture.SECURE.value == "secure"
        assert SecurityPosture.CRITICAL.value == "critical"

    def test_dependency_health_defaults(self):
        h = DependencyHealth(
            name="x",
            version="1.0",
            package_manager="pip",
            age_days=10,
            maintenance_status=MaintenanceStatus.ACTIVE,
            security_posture=SecurityPosture.SECURE,
        )
        assert h.vulnerability_count == 0
        assert h.critical_vulnerability_count == 0
        assert h.health_score == 0.0
        assert h.recommendations == []

    def test_dependency_health_report(self):
        r = DependencyHealthReport(
            dependencies=[],
            total_dependencies=0,
            healthy_count=0,
            at_risk_count=0,
            critical_count=0,
            average_health_score=0.0,
        )
        assert r.timestamp is not None


# ── Maintenance status ────────────────────────────────────────────────────


class TestMaintenanceStatus:
    def test_active_under_30_days(self, monitor):
        result = monitor._determine_maintenance_status(10)
        assert result == MaintenanceStatus.ACTIVE

    def test_slow_30_to_90_days(self, monitor):
        result = monitor._determine_maintenance_status(60)
        assert result == MaintenanceStatus.SLOW

    def test_stale_90_to_365_days(self, monitor):
        result = monitor._determine_maintenance_status(200)
        assert result == MaintenanceStatus.STALE

    def test_abandoned_over_365_days(self, monitor):
        result = monitor._determine_maintenance_status(400)
        assert result == MaintenanceStatus.ABANDONED

    def test_boundary_30(self, monitor):
        assert monitor._determine_maintenance_status(30) == MaintenanceStatus.SLOW

    def test_boundary_90(self, monitor):
        assert monitor._determine_maintenance_status(90) == MaintenanceStatus.STALE

    def test_boundary_365(self, monitor):
        assert monitor._determine_maintenance_status(365) == MaintenanceStatus.ABANDONED


# ── Security posture ──────────────────────────────────────────────────────


class TestSecurityPosture:
    def test_secure_no_vulns(self, monitor):
        assert monitor._determine_security_posture(0, 0) == SecurityPosture.SECURE

    def test_vulnerable_with_vulns(self, monitor):
        assert (
            monitor._determine_security_posture(3, 0) == SecurityPosture.VULNERABLE
        )

    def test_critical_with_critical_vulns(self, monitor):
        assert (
            monitor._determine_security_posture(5, 2) == SecurityPosture.CRITICAL
        )


# ── Health score ──────────────────────────────────────────────────────────


class TestHealthScore:
    def test_perfect_score(self, monitor):
        score = monitor._calculate_health_score(
            age_days=5,
            maintenance_status=MaintenanceStatus.ACTIVE,
            security_posture=SecurityPosture.SECURE,
            vuln_count=0,
        )
        assert score == 100.0

    def test_old_abandoned_critical(self, monitor):
        score = monitor._calculate_health_score(
            age_days=500,
            maintenance_status=MaintenanceStatus.ABANDONED,
            security_posture=SecurityPosture.CRITICAL,
            vuln_count=15,
        )
        # 100 - 30 (age) - 30 (abandoned) - 40 (critical) - 20 (vulns capped) = -20 → 0
        assert score == 0.0

    def test_moderate_score(self, monitor):
        score = monitor._calculate_health_score(
            age_days=60,
            maintenance_status=MaintenanceStatus.SLOW,
            security_posture=SecurityPosture.VULNERABLE,
            vuln_count=2,
        )
        # 100 - 5 (age) - 5 (slow) - 20 (vulnerable) - 4 (vulns) = 66
        assert score == 66.0

    def test_score_never_above_100(self, monitor):
        score = monitor._calculate_health_score(
            age_days=1,
            maintenance_status=MaintenanceStatus.ACTIVE,
            security_posture=SecurityPosture.SECURE,
            vuln_count=0,
        )
        assert score <= 100.0

    def test_score_never_below_0(self, monitor):
        score = monitor._calculate_health_score(
            age_days=9999,
            maintenance_status=MaintenanceStatus.ABANDONED,
            security_posture=SecurityPosture.CRITICAL,
            vuln_count=100,
        )
        assert score >= 0.0


# ── Recommendations ───────────────────────────────────────────────────────


class TestRecommendations:
    def test_abandoned_recommendation(self, monitor):
        recs = monitor._generate_recommendations(
            MaintenanceStatus.ABANDONED, SecurityPosture.SECURE, 400, 0
        )
        assert any("replacing" in r.lower() or "alternative" in r.lower() for r in recs)

    def test_stale_recommendation(self, monitor):
        recs = monitor._generate_recommendations(
            MaintenanceStatus.STALE, SecurityPosture.SECURE, 200, 0
        )
        assert any("monitor" in r.lower() or "alternative" in r.lower() for r in recs)

    def test_critical_posture_recommendation(self, monitor):
        recs = monitor._generate_recommendations(
            MaintenanceStatus.ACTIVE, SecurityPosture.CRITICAL, 5, 1
        )
        assert any("urgent" in r.lower() for r in recs)

    def test_vulnerable_posture_recommendation(self, monitor):
        recs = monitor._generate_recommendations(
            MaintenanceStatus.ACTIVE, SecurityPosture.VULNERABLE, 5, 1
        )
        assert any("update" in r.lower() for r in recs)

    def test_many_vulns_recommendation(self, monitor):
        recs = monitor._generate_recommendations(
            MaintenanceStatus.ACTIVE, SecurityPosture.VULNERABLE, 5, 8
        )
        assert any("multiple" in r.lower() for r in recs)

    def test_old_package_recommendation(self, monitor):
        recs = monitor._generate_recommendations(
            MaintenanceStatus.ABANDONED, SecurityPosture.SECURE, 500, 0
        )
        assert any("year" in r.lower() for r in recs)

    def test_healthy_no_recommendations(self, monitor):
        recs = monitor._generate_recommendations(
            MaintenanceStatus.ACTIVE, SecurityPosture.SECURE, 5, 0
        )
        assert len(recs) == 0


# ── monitor_dependency ────────────────────────────────────────────────────


class TestMonitorDependency:
    def test_healthy_dependency(self, monitor):
        h = monitor.monitor_dependency(
            name="requests",
            version="2.31.0",
            package_manager="pip",
            last_update_date=_recent_date(5),
        )
        assert h.name == "requests"
        assert h.maintenance_status == MaintenanceStatus.ACTIVE
        assert h.security_posture == SecurityPosture.SECURE
        assert h.health_score >= 90.0

    def test_vulnerable_dependency(self, monitor):
        h = monitor.monitor_dependency(
            name="flask",
            version="2.0.0",
            package_manager="pip",
            last_update_date=_recent_date(100),
            vulnerabilities=[
                {"cve_id": "CVE-2024-0001", "severity": "critical"}
            ],
        )
        assert h.security_posture == SecurityPosture.CRITICAL
        assert h.critical_vulnerability_count == 1
        assert h.health_score < 70.0

    def test_unknown_update_date(self, monitor):
        h = monitor.monitor_dependency(
            name="mystery",
            version="1.0",
            package_manager="pip",
            last_update_date=None,
        )
        assert h.age_days == 999

    def test_no_vulnerabilities_default(self, monitor):
        h = monitor.monitor_dependency(
            name="safe",
            version="1.0",
            package_manager="npm",
            last_update_date=_recent_date(10),
        )
        assert h.vulnerability_count == 0
        assert h.critical_vulnerability_count == 0


# ── monitor_all_dependencies ─────────────────────────────────────────────


class TestMonitorAllDependencies:
    def test_report_structure(self, monitor):
        deps = [
            {
                "name": "a",
                "version": "1.0",
                "package_manager": "pip",
                "last_update_date": _recent_date(5),
            },
            {
                "name": "b",
                "version": "2.0",
                "package_manager": "npm",
                "last_update_date": _recent_date(500),
                "vulnerabilities": [
                    {"cve_id": "CVE-1", "severity": "critical"}
                ],
            },
        ]
        report = monitor.monitor_all_dependencies(deps)
        assert isinstance(report, DependencyHealthReport)
        assert report.total_dependencies == 2
        assert report.healthy_count + report.at_risk_count + report.critical_count == 2

    def test_empty_dependencies(self, monitor):
        report = monitor.monitor_all_dependencies([])
        assert report.total_dependencies == 0
        assert report.average_health_score == 0.0

    def test_all_healthy(self, monitor):
        deps = [
            {
                "name": f"pkg{i}",
                "version": "1.0",
                "package_manager": "pip",
                "last_update_date": _recent_date(5),
            }
            for i in range(5)
        ]
        report = monitor.monitor_all_dependencies(deps)
        assert report.healthy_count == 5
        assert report.average_health_score >= 90.0

    def test_mixed_health(self, monitor):
        deps = [
            {
                "name": "healthy",
                "version": "1.0",
                "package_manager": "pip",
                "last_update_date": _recent_date(5),
            },
            {
                "name": "critical",
                "version": "1.0",
                "package_manager": "pip",
                "last_update_date": _recent_date(500),
                "vulnerabilities": [
                    {"cve_id": "CVE-1", "severity": "critical"},
                    {"cve_id": "CVE-2", "severity": "critical"},
                    {"cve_id": "CVE-3", "severity": "high"},
                    {"cve_id": "CVE-4", "severity": "high"},
                    {"cve_id": "CVE-5", "severity": "medium"},
                    {"cve_id": "CVE-6", "severity": "medium"},
                ],
            },
        ]
        report = monitor.monitor_all_dependencies(deps)
        assert report.critical_count >= 1
        assert report.average_health_score < 90.0
