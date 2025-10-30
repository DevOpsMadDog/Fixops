"""Comprehensive tests for Portfolio Management functionality.

This test suite covers:
- Data ingestion from multiple sources
- Normalization across different formats
- Indexing and search functionality
- Reporting and aggregation
- Cross-application analytics
- Portfolio-wide risk assessment
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Set

import pytest


class PortfolioDataStore:
    """In-memory data store for portfolio management."""

    def __init__(self):
        self.applications: Dict[str, Dict[str, Any]] = {}
        self.findings: List[Dict[str, Any]] = []
        self.scans: List[Dict[str, Any]] = []
        self.index: Dict[str, Set[str]] = {
            "by_severity": {},
            "by_tool": {},
            "by_app": {},
            "by_cve": {},
        }

    def ingest_application(self, app_data: Dict[str, Any]):
        """Ingest application metadata."""
        app_id = app_data["id"]
        self.applications[app_id] = app_data
        self._update_index("by_app", app_id, app_id)

    def ingest_findings(self, findings: List[Dict[str, Any]]):
        """Ingest security findings."""
        for finding in findings:
            finding_id = finding.get("id", len(self.findings))
            finding["finding_id"] = finding_id
            self.findings.append(finding)

            self._update_index(
                "by_severity", finding.get("severity", "unknown"), finding_id
            )
            self._update_index("by_tool", finding.get("tool", "unknown"), finding_id)
            self._update_index("by_app", finding.get("app_id", "unknown"), finding_id)

            if "cve_id" in finding:
                self._update_index("by_cve", finding["cve_id"], finding_id)

    def ingest_scan(self, scan_data: Dict[str, Any]):
        """Ingest scan metadata."""
        self.scans.append(scan_data)

    def _update_index(self, index_type: str, key: str, value: Any):
        """Update an index."""
        if key not in self.index[index_type]:
            self.index[index_type][key] = set()
        self.index[index_type][key].add(value)

    def search_findings(
        self,
        severity: str = None,
        tool: str = None,
        app_id: str = None,
        cve_id: str = None,
    ) -> List[Dict[str, Any]]:
        """Search findings with filters."""
        result_ids = None

        if severity:
            result_ids = self.index["by_severity"].get(severity, set())

        if tool:
            tool_ids = self.index["by_tool"].get(tool, set())
            result_ids = result_ids & tool_ids if result_ids else tool_ids

        if app_id:
            app_ids = self.index["by_app"].get(app_id, set())
            result_ids = result_ids & app_ids if result_ids else app_ids

        if cve_id:
            cve_ids = self.index["by_cve"].get(cve_id, set())
            result_ids = result_ids & cve_ids if result_ids else cve_ids

        if result_ids is None:
            return self.findings

        return [f for f in self.findings if f["finding_id"] in result_ids]

    def get_portfolio_summary(self) -> Dict[str, Any]:
        """Get portfolio-wide summary."""
        return {
            "total_applications": len(self.applications),
            "total_findings": len(self.findings),
            "total_scans": len(self.scans),
            "findings_by_severity": {
                severity: len(ids)
                for severity, ids in self.index["by_severity"].items()
            },
            "findings_by_tool": {
                tool: len(ids) for tool, ids in self.index["by_tool"].items()
            },
        }


class PortfolioNormalizer:
    """Normalizes data from different sources into common format."""

    @staticmethod
    def normalize_sonarqube(sonarqube_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize SonarQube data."""
        findings = []

        for issue in sonarqube_data.get("issues", []):
            findings.append(
                {
                    "id": issue["key"],
                    "tool": "sonarqube",
                    "type": issue["type"],
                    "severity": PortfolioNormalizer._map_sonarqube_severity(
                        issue["severity"]
                    ),
                    "rule": issue["rule"],
                    "message": issue["message"],
                    "file": issue["component"],
                    "line": issue.get("line"),
                    "app_id": sonarqube_data.get("projectKey"),
                    "timestamp": issue.get("creationDate"),
                }
            )

        return findings

    @staticmethod
    def normalize_snyk(snyk_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize Snyk data."""
        findings = []

        for vuln in snyk_data.get("vulnerabilities", []):
            findings.append(
                {
                    "id": vuln["id"],
                    "tool": "snyk",
                    "type": "vulnerability",
                    "severity": vuln["severity"],
                    "cve_id": vuln["identifiers"]["CVE"][0]
                    if vuln["identifiers"].get("CVE")
                    else None,
                    "package": vuln["packageName"],
                    "version": vuln["version"],
                    "cvss_score": vuln.get("cvssScore"),
                    "app_id": snyk_data.get("projectName"),
                    "timestamp": vuln.get("publicationTime"),
                }
            )

        return findings

    @staticmethod
    def normalize_veracode(veracode_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize Veracode data."""
        findings = []

        for flaw in veracode_data.get("flaws", []):
            findings.append(
                {
                    "id": str(flaw["issueid"]),
                    "tool": "veracode",
                    "type": "flaw",
                    "severity": PortfolioNormalizer._map_veracode_severity(
                        flaw["severity"]
                    ),
                    "cwe_id": f"CWE-{flaw['cweid']}",
                    "category": flaw["categoryname"],
                    "file": flaw["sourcefile"],
                    "line": flaw.get("line"),
                    "app_id": veracode_data.get("app_name"),
                    "timestamp": flaw.get("date_first_occurrence"),
                }
            )

        return findings

    @staticmethod
    def normalize_wiz(wiz_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize Wiz CNAPP data."""
        findings = []

        for issue in wiz_data.get("issues", []):
            findings.append(
                {
                    "id": issue["id"],
                    "tool": "wiz",
                    "type": issue["type"],
                    "severity": issue["severity"].lower(),
                    "resource": issue["resource"]["name"],
                    "cloud": issue["resource"]["cloudPlatform"],
                    "description": issue["description"],
                    "app_id": issue["projects"][0] if issue.get("projects") else None,
                    "timestamp": issue.get("createdAt"),
                }
            )

        return findings

    @staticmethod
    def _map_sonarqube_severity(severity: str) -> str:
        """Map SonarQube severity to standard levels."""
        mapping = {
            "BLOCKER": "critical",
            "CRITICAL": "critical",
            "MAJOR": "high",
            "MINOR": "medium",
            "INFO": "low",
        }
        return mapping.get(severity, "medium")

    @staticmethod
    def _map_veracode_severity(severity: int) -> str:
        """Map Veracode severity to standard levels."""
        if severity == 5:
            return "critical"
        elif severity == 4:
            return "high"
        elif severity == 3:
            return "medium"
        elif severity == 2:
            return "low"
        else:
            return "info"


class PortfolioReporter:
    """Generates portfolio-wide reports."""

    @staticmethod
    def generate_executive_summary(store: PortfolioDataStore) -> Dict[str, Any]:
        """Generate executive summary report."""
        summary = store.get_portfolio_summary()

        critical_count = summary["findings_by_severity"].get("critical", 0)
        high_count = summary["findings_by_severity"].get("high", 0)
        total_findings = summary["total_findings"]

        risk_score = 0.0
        if total_findings > 0:
            risk_score = (critical_count * 1.0 + high_count * 0.75) / total_findings

        return {
            "summary": summary,
            "risk_metrics": {
                "overall_risk_score": risk_score,
                "critical_findings": critical_count,
                "high_findings": high_count,
                "risk_level": PortfolioReporter._get_risk_level(risk_score),
            },
            "trends": PortfolioReporter._calculate_trends(store),
            "top_applications_at_risk": PortfolioReporter._get_top_risky_apps(store),
        }

    @staticmethod
    def generate_compliance_report(store: PortfolioDataStore) -> Dict[str, Any]:
        """Generate compliance report."""
        findings_by_app = {}

        for finding in store.findings:
            app_id = finding.get("app_id", "unknown")
            if app_id not in findings_by_app:
                findings_by_app[app_id] = []
            findings_by_app[app_id].append(finding)

        compliance_status = {}
        for app_id, findings in findings_by_app.items():
            critical_count = len(
                [f for f in findings if f.get("severity") == "critical"]
            )
            high_count = len([f for f in findings if f.get("severity") == "high"])

            is_compliant = critical_count == 0 and high_count < 5

            compliance_status[app_id] = {
                "compliant": is_compliant,
                "critical_findings": critical_count,
                "high_findings": high_count,
                "total_findings": len(findings),
            }

        return {
            "total_applications": len(compliance_status),
            "compliant_applications": len(
                [s for s in compliance_status.values() if s["compliant"]]
            ),
            "non_compliant_applications": len(
                [s for s in compliance_status.values() if not s["compliant"]]
            ),
            "compliance_rate": len(
                [s for s in compliance_status.values() if s["compliant"]]
            )
            / max(len(compliance_status), 1),
            "details": compliance_status,
        }

    @staticmethod
    def generate_tool_coverage_report(store: PortfolioDataStore) -> Dict[str, Any]:
        """Generate tool coverage report."""
        apps_by_tool = {}

        for finding in store.findings:
            tool = finding.get("tool", "unknown")
            app_id = finding.get("app_id", "unknown")

            if tool not in apps_by_tool:
                apps_by_tool[tool] = set()
            apps_by_tool[tool].add(app_id)

        return {
            "tools_in_use": list(apps_by_tool.keys()),
            "tool_coverage": {
                tool: {
                    "applications_covered": len(apps),
                    "coverage_percentage": len(apps) / max(len(store.applications), 1),
                }
                for tool, apps in apps_by_tool.items()
            },
        }

    @staticmethod
    def _get_risk_level(risk_score: float) -> str:
        """Convert risk score to level."""
        if risk_score >= 0.7:
            return "critical"
        elif risk_score >= 0.5:
            return "high"
        elif risk_score >= 0.3:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _calculate_trends(store: PortfolioDataStore) -> Dict[str, Any]:
        """Calculate trends over time."""
        recent_findings = [
            f
            for f in store.findings
            if f.get("timestamp")
            and datetime.fromisoformat(f["timestamp"].replace("Z", ""))
            > datetime.utcnow() - timedelta(days=30)
        ]

        return {
            "findings_last_30_days": len(recent_findings),
            "trend": "increasing"
            if len(recent_findings) > len(store.findings) * 0.3
            else "stable",
        }

    @staticmethod
    def _get_top_risky_apps(
        store: PortfolioDataStore, top_n: int = 5
    ) -> List[Dict[str, Any]]:
        """Get top risky applications."""
        app_risk_scores = {}

        for finding in store.findings:
            app_id = finding.get("app_id", "unknown")
            severity = finding.get("severity", "low")

            if app_id not in app_risk_scores:
                app_risk_scores[app_id] = 0.0

            severity_weights = {
                "critical": 1.0,
                "high": 0.75,
                "medium": 0.5,
                "low": 0.25,
            }
            app_risk_scores[app_id] += severity_weights.get(severity, 0.0)

        sorted_apps = sorted(app_risk_scores.items(), key=lambda x: x[1], reverse=True)[
            :top_n
        ]

        return [
            {"app_id": app_id, "risk_score": score} for app_id, score in sorted_apps
        ]


class TestPortfolioDataIngestion:
    """Test portfolio data ingestion."""

    def test_ingest_application_metadata(self):
        """Test ingesting application metadata."""
        store = PortfolioDataStore()

        app_data = {
            "id": "app-001",
            "name": "E-Commerce Web App",
            "type": "web",
            "criticality": "high",
        }

        store.ingest_application(app_data)

        assert len(store.applications) == 1
        assert store.applications["app-001"]["name"] == "E-Commerce Web App"

    def test_ingest_multiple_applications(self):
        """Test ingesting multiple applications."""
        store = PortfolioDataStore()

        apps = [
            {"id": "app-001", "name": "App 1"},
            {"id": "app-002", "name": "App 2"},
            {"id": "app-003", "name": "App 3"},
        ]

        for app in apps:
            store.ingest_application(app)

        assert len(store.applications) == 3

    def test_ingest_findings(self):
        """Test ingesting security findings."""
        store = PortfolioDataStore()

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "high", "tool": "snyk", "app_id": "app-001"},
            {"id": "f3", "severity": "medium", "tool": "veracode", "app_id": "app-002"},
        ]

        store.ingest_findings(findings)

        assert len(store.findings) == 3

    def test_ingest_scan_metadata(self):
        """Test ingesting scan metadata."""
        store = PortfolioDataStore()

        scan_data = {
            "id": "scan-001",
            "app_id": "app-001",
            "tool": "sonarqube",
            "timestamp": datetime.utcnow().isoformat(),
        }

        store.ingest_scan(scan_data)

        assert len(store.scans) == 1


class TestPortfolioNormalization:
    """Test portfolio data normalization."""

    def test_normalize_sonarqube_data(self):
        """Test normalizing SonarQube data."""
        sonarqube_data = {
            "projectKey": "my-app",
            "issues": [
                {
                    "key": "issue-1",
                    "type": "BUG",
                    "severity": "CRITICAL",
                    "rule": "squid:S1234",
                    "message": "Test issue",
                    "component": "src/main.py",
                    "line": 42,
                    "creationDate": "2024-01-01T00:00:00Z",
                }
            ],
        }

        findings = PortfolioNormalizer.normalize_sonarqube(sonarqube_data)

        assert len(findings) == 1
        assert findings[0]["tool"] == "sonarqube"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["app_id"] == "my-app"

    def test_normalize_snyk_data(self):
        """Test normalizing Snyk data."""
        snyk_data = {
            "projectName": "my-app",
            "vulnerabilities": [
                {
                    "id": "SNYK-001",
                    "severity": "high",
                    "identifiers": {"CVE": ["CVE-2024-12345"]},
                    "packageName": "requests",
                    "version": "2.28.0",
                    "cvssScore": 7.5,
                    "publicationTime": "2024-01-01T00:00:00Z",
                }
            ],
        }

        findings = PortfolioNormalizer.normalize_snyk(snyk_data)

        assert len(findings) == 1
        assert findings[0]["tool"] == "snyk"
        assert findings[0]["cve_id"] == "CVE-2024-12345"
        assert findings[0]["package"] == "requests"

    def test_normalize_veracode_data(self):
        """Test normalizing Veracode data."""
        veracode_data = {
            "app_name": "my-app",
            "flaws": [
                {
                    "issueid": 123456,
                    "cweid": 89,
                    "categoryname": "SQL Injection",
                    "severity": 5,
                    "sourcefile": "src/db.py",
                    "line": 100,
                    "date_first_occurrence": "2024-01-01T00:00:00Z",
                }
            ],
        }

        findings = PortfolioNormalizer.normalize_veracode(veracode_data)

        assert len(findings) == 1
        assert findings[0]["tool"] == "veracode"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["cwe_id"] == "CWE-89"

    def test_normalize_wiz_data(self):
        """Test normalizing Wiz CNAPP data."""
        wiz_data = {
            "issues": [
                {
                    "id": "wiz-001",
                    "type": "Vulnerability",
                    "severity": "HIGH",
                    "resource": {
                        "name": "my-resource",
                        "cloudPlatform": "AWS",
                    },
                    "description": "Test issue",
                    "projects": ["my-app"],
                    "createdAt": "2024-01-01T00:00:00Z",
                }
            ],
        }

        findings = PortfolioNormalizer.normalize_wiz(wiz_data)

        assert len(findings) == 1
        assert findings[0]["tool"] == "wiz"
        assert findings[0]["severity"] == "high"
        assert findings[0]["cloud"] == "AWS"


class TestPortfolioIndexing:
    """Test portfolio indexing and search."""

    def test_index_by_severity(self):
        """Test indexing findings by severity."""
        store = PortfolioDataStore()

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "critical", "tool": "snyk", "app_id": "app-001"},
            {"id": "f3", "severity": "high", "tool": "veracode", "app_id": "app-002"},
        ]

        store.ingest_findings(findings)

        assert len(store.index["by_severity"]["critical"]) == 2
        assert len(store.index["by_severity"]["high"]) == 1

    def test_search_by_severity(self):
        """Test searching findings by severity."""
        store = PortfolioDataStore()

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "high", "tool": "snyk", "app_id": "app-001"},
            {"id": "f3", "severity": "medium", "tool": "veracode", "app_id": "app-002"},
        ]

        store.ingest_findings(findings)

        critical_findings = store.search_findings(severity="critical")
        assert len(critical_findings) == 1
        assert critical_findings[0]["id"] == "f1"

    def test_search_by_tool(self):
        """Test searching findings by tool."""
        store = PortfolioDataStore()

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "high", "tool": "sonarqube", "app_id": "app-001"},
            {"id": "f3", "severity": "medium", "tool": "snyk", "app_id": "app-002"},
        ]

        store.ingest_findings(findings)

        sonarqube_findings = store.search_findings(tool="sonarqube")
        assert len(sonarqube_findings) == 2

    def test_search_by_application(self):
        """Test searching findings by application."""
        store = PortfolioDataStore()

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "high", "tool": "snyk", "app_id": "app-001"},
            {"id": "f3", "severity": "medium", "tool": "veracode", "app_id": "app-002"},
        ]

        store.ingest_findings(findings)

        app1_findings = store.search_findings(app_id="app-001")
        assert len(app1_findings) == 2

    def test_search_with_multiple_filters(self):
        """Test searching with multiple filters."""
        store = PortfolioDataStore()

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "critical", "tool": "snyk", "app_id": "app-001"},
            {"id": "f3", "severity": "high", "tool": "sonarqube", "app_id": "app-002"},
        ]

        store.ingest_findings(findings)

        results = store.search_findings(severity="critical", tool="sonarqube")
        assert len(results) == 1
        assert results[0]["id"] == "f1"


class TestPortfolioReporting:
    """Test portfolio reporting."""

    def test_generate_executive_summary(self):
        """Test generating executive summary."""
        store = PortfolioDataStore()

        store.ingest_application({"id": "app-001", "name": "App 1"})
        store.ingest_application({"id": "app-002", "name": "App 2"})

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "high", "tool": "snyk", "app_id": "app-001"},
            {"id": "f3", "severity": "medium", "tool": "veracode", "app_id": "app-002"},
        ]
        store.ingest_findings(findings)

        summary = PortfolioReporter.generate_executive_summary(store)

        assert summary["summary"]["total_applications"] == 2
        assert summary["summary"]["total_findings"] == 3
        assert "risk_metrics" in summary
        assert "overall_risk_score" in summary["risk_metrics"]

    def test_generate_compliance_report(self):
        """Test generating compliance report."""
        store = PortfolioDataStore()

        store.ingest_application({"id": "app-001", "name": "App 1"})
        store.ingest_application({"id": "app-002", "name": "App 2"})

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "low", "tool": "snyk", "app_id": "app-002"},
        ]
        store.ingest_findings(findings)

        report = PortfolioReporter.generate_compliance_report(store)

        assert report["total_applications"] == 2
        assert report["non_compliant_applications"] >= 1

    def test_generate_tool_coverage_report(self):
        """Test generating tool coverage report."""
        store = PortfolioDataStore()

        store.ingest_application({"id": "app-001", "name": "App 1"})
        store.ingest_application({"id": "app-002", "name": "App 2"})

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "high", "tool": "sonarqube", "app_id": "app-002"},
            {"id": "f3", "severity": "medium", "tool": "snyk", "app_id": "app-001"},
        ]
        store.ingest_findings(findings)

        report = PortfolioReporter.generate_tool_coverage_report(store)

        assert "sonarqube" in report["tools_in_use"]
        assert "snyk" in report["tools_in_use"]
        assert report["tool_coverage"]["sonarqube"]["applications_covered"] == 2

    def test_top_risky_applications(self):
        """Test identifying top risky applications."""
        store = PortfolioDataStore()

        findings = [
            {
                "id": "f1",
                "severity": "critical",
                "tool": "sonarqube",
                "app_id": "app-001",
            },
            {"id": "f2", "severity": "critical", "tool": "snyk", "app_id": "app-001"},
            {"id": "f3", "severity": "high", "tool": "veracode", "app_id": "app-002"},
            {"id": "f4", "severity": "low", "tool": "wiz", "app_id": "app-003"},
        ]
        store.ingest_findings(findings)

        summary = PortfolioReporter.generate_executive_summary(store)
        top_apps = summary["top_applications_at_risk"]

        assert len(top_apps) > 0
        assert top_apps[0]["app_id"] == "app-001"  # Most critical findings


class TestPortfolioIntegration:
    """Test portfolio management integration."""

    def test_end_to_end_portfolio_workflow(self):
        """Test complete portfolio management workflow."""
        store = PortfolioDataStore()

        apps = [
            {"id": "app-001", "name": "E-Commerce Web App"},
            {"id": "app-002", "name": "Mobile Backend"},
            {"id": "app-003", "name": "Payment Service"},
        ]
        for app in apps:
            store.ingest_application(app)

        sonarqube_data = {
            "projectKey": "app-001",
            "issues": [
                {
                    "key": "sq-1",
                    "type": "BUG",
                    "severity": "CRITICAL",
                    "rule": "squid:S1234",
                    "message": "Critical bug",
                    "component": "src/main.py",
                    "creationDate": "2024-01-01T00:00:00Z",
                }
            ],
        }
        store.ingest_findings(PortfolioNormalizer.normalize_sonarqube(sonarqube_data))

        snyk_data = {
            "projectName": "app-002",
            "vulnerabilities": [
                {
                    "id": "SNYK-001",
                    "severity": "high",
                    "identifiers": {"CVE": ["CVE-2024-12345"]},
                    "packageName": "requests",
                    "version": "2.28.0",
                    "cvssScore": 7.5,
                    "publicationTime": "2024-01-01T00:00:00Z",
                }
            ],
        }
        store.ingest_findings(PortfolioNormalizer.normalize_snyk(snyk_data))

        executive_summary = PortfolioReporter.generate_executive_summary(store)
        compliance_report = PortfolioReporter.generate_compliance_report(store)
        coverage_report = PortfolioReporter.generate_tool_coverage_report(store)

        assert executive_summary["summary"]["total_applications"] == 3
        assert executive_summary["summary"]["total_findings"] == 2
        assert compliance_report["total_applications"] == 2
        assert len(coverage_report["tools_in_use"]) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
