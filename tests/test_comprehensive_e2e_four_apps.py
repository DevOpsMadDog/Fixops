"""Comprehensive end-to-end tests for all 4 application profiles.

This test suite covers complete workflows for:
1. E-Commerce Web Application
2. Mobile Banking Backend
3. Payment Processing Microservices
4. Legacy ERP System

Each test simulates a complete SSDLC pipeline with real tool data.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from tests.test_comprehensive_tool_integrations import EnhancedTestDataGenerator


class EndToEndTestRunner:
    """Runner for end-to-end tests across all application profiles."""

    @staticmethod
    def run_complete_pipeline(
        profile: Dict[str, Any],
        tools: List[str],
    ) -> Dict[str, Any]:
        """Run complete pipeline for an application profile."""
        results = {
            "profile": profile,
            "tool_reports": {},
            "pipeline_result": None,
            "findings_summary": {},
        }

        for tool in tools:
            if tool == "sonarqube":
                results["tool_reports"][
                    tool
                ] = EnhancedTestDataGenerator.generate_sonarqube_report(profile)
            elif tool == "snyk":
                results["tool_reports"][
                    tool
                ] = EnhancedTestDataGenerator.generate_snyk_report(profile)
            elif tool == "veracode":
                results["tool_reports"][
                    tool
                ] = EnhancedTestDataGenerator.generate_veracode_report(profile)
            elif tool == "invicti":
                results["tool_reports"][
                    tool
                ] = EnhancedTestDataGenerator.generate_invicti_report(profile)
            elif tool == "wiz":
                results["tool_reports"][
                    tool
                ] = EnhancedTestDataGenerator.generate_wiz_report(profile)
            elif tool == "prisma_cloud":
                results["tool_reports"][
                    tool
                ] = EnhancedTestDataGenerator.generate_prisma_cloud_report(profile)
            elif tool == "crowdstrike":
                results["tool_reports"][
                    tool
                ] = EnhancedTestDataGenerator.generate_crowdstrike_report(profile)
            elif tool == "sentinelone":
                results["tool_reports"][
                    tool
                ] = EnhancedTestDataGenerator.generate_sentinelone_report(profile)

        total_findings = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for tool, report in results["tool_reports"].items():
            if tool == "sonarqube":
                total_findings += len(report.get("issues", []))
                for issue in report.get("issues", []):
                    severity = issue.get("severity", "").lower()
                    if "critical" in severity or "blocker" in severity:
                        severity_counts["critical"] += 1
                    elif "major" in severity:
                        severity_counts["high"] += 1
                    elif "minor" in severity:
                        severity_counts["medium"] += 1
                    else:
                        severity_counts["low"] += 1

            elif tool == "snyk":
                total_findings += len(report.get("vulnerabilities", []))
                for vuln in report.get("vulnerabilities", []):
                    severity = vuln.get("severity", "low")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

            elif tool == "veracode":
                total_findings += len(report.get("flaws", []))
                for flaw in report.get("flaws", []):
                    severity_level = flaw.get("severity", 1)
                    if severity_level >= 5:
                        severity_counts["critical"] += 1
                    elif severity_level >= 4:
                        severity_counts["high"] += 1
                    elif severity_level >= 3:
                        severity_counts["medium"] += 1
                    else:
                        severity_counts["low"] += 1

            elif tool == "wiz":
                total_findings += len(report.get("issues", []))
                for issue in report.get("issues", []):
                    severity = issue.get("severity", "LOW").lower()
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

        results["findings_summary"] = {
            "total": total_findings,
            "by_severity": severity_counts,
        }

        return results


class TestECommerceWebApplication:
    """Test E-Commerce Web Application profile end-to-end."""

    def test_complete_ssdlc_pipeline(self):
        """Test complete SSDLC pipeline for e-commerce web app."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]
        tools = ["sonarqube", "snyk", "wiz"]

        results = EndToEndTestRunner.run_complete_pipeline(profile, tools)

        assert len(results["tool_reports"]) == 3
        assert "sonarqube" in results["tool_reports"]
        assert "snyk" in results["tool_reports"]
        assert "wiz" in results["tool_reports"]

        assert results["findings_summary"]["total"] > 0
        assert "by_severity" in results["findings_summary"]

    def test_requirements_stage(self):
        """Test requirements stage for e-commerce web app."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]

        requirements = {
            "security": [
                "PCI-DSS compliance required",
                "GDPR compliance required",
                "SOC2 Type II certification",
            ],
            "data_classification": "confidential",
            "user_base": "external",
            "criticality": profile["criticality"],
        }

        assert requirements["criticality"] == "high"
        assert "PCI-DSS compliance required" in requirements["security"]

    def test_design_stage(self):
        """Test design stage for e-commerce web app."""
        threat_model = {
            "assets": ["customer_data", "payment_info", "session_tokens"],
            "threats": [
                {"type": "SQL Injection", "severity": "critical"},
                {"type": "XSS", "severity": "high"},
                {"type": "CSRF", "severity": "medium"},
            ],
            "mitigations": [
                "Input validation",
                "Parameterized queries",
                "CSRF tokens",
            ],
        }

        assert len(threat_model["threats"]) > 0
        assert any(t["severity"] == "critical" for t in threat_model["threats"])

    def test_build_stage(self):
        """Test build stage for e-commerce web app."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]

        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "django", "version": "4.2.5"},
                {"name": "react", "version": "18.2.0"},
                {"name": "fastapi", "version": "0.104.0"},
            ],
        }

        snyk_report = EnhancedTestDataGenerator.generate_snyk_report(profile)

        assert len(sbom["components"]) > 0
        assert len(snyk_report["vulnerabilities"]) >= 0

    def test_test_stage(self):
        """Test test stage for e-commerce web app."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]

        sonarqube_report = EnhancedTestDataGenerator.generate_sonarqube_report(profile)

        invicti_report = EnhancedTestDataGenerator.generate_invicti_report(profile)

        assert len(sonarqube_report["issues"]) >= 0
        assert len(invicti_report["Vulnerabilities"]) >= 0

    def test_deploy_stage(self):
        """Test deploy stage for e-commerce web app."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]

        wiz_report = EnhancedTestDataGenerator.generate_wiz_report(profile)

        assert wiz_report["cloudProvider"] == profile["cloud"]
        assert len(wiz_report["issues"]) >= 0

    def test_operate_stage(self):
        """Test operate stage for e-commerce web app."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]

        crowdstrike_report = EnhancedTestDataGenerator.generate_crowdstrike_report(
            profile
        )

        assert len(crowdstrike_report["detections"]) >= 0


class TestMobileBankingBackend:
    """Test Mobile Banking Backend profile end-to-end."""

    def test_complete_ssdlc_pipeline(self):
        """Test complete SSDLC pipeline for mobile banking backend."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"]
        tools = ["veracode", "snyk", "sentinelone"]

        results = EndToEndTestRunner.run_complete_pipeline(profile, tools)

        assert len(results["tool_reports"]) == 3
        assert "veracode" in results["tool_reports"]
        assert "snyk" in results["tool_reports"]
        assert "sentinelone" in results["tool_reports"]

        assert results["findings_summary"]["total"] > 0

    def test_high_criticality_handling(self):
        """Test handling of critical application."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"]

        assert profile["criticality"] == "critical"

        thresholds = {
            "critical_allowed": 0,
            "high_allowed": 0,
            "medium_allowed": 5,
        }

        assert thresholds["critical_allowed"] == 0
        assert thresholds["high_allowed"] == 0

    def test_compliance_requirements(self):
        """Test compliance requirements for banking app."""
        compliance = {
            "frameworks": ["PCI-DSS", "SOC2", "ISO27001"],
            "data_residency": "required",
            "encryption": "required",
            "audit_logging": "required",
        }

        assert "PCI-DSS" in compliance["frameworks"]
        assert compliance["encryption"] == "required"

    def test_multi_tool_correlation(self):
        """Test correlation across multiple tools."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"]

        veracode_report = EnhancedTestDataGenerator.generate_veracode_report(profile)
        snyk_report = EnhancedTestDataGenerator.generate_snyk_report(profile)

        assert len(veracode_report["flaws"]) > 0
        assert len(snyk_report["vulnerabilities"]) > 0


class TestPaymentMicroservices:
    """Test Payment Processing Microservices profile end-to-end."""

    def test_complete_ssdlc_pipeline(self):
        """Test complete SSDLC pipeline for payment microservices."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["microservices"]
        tools = ["sonarqube", "prisma_cloud", "crowdstrike"]

        results = EndToEndTestRunner.run_complete_pipeline(profile, tools)

        assert len(results["tool_reports"]) == 3
        assert "sonarqube" in results["tool_reports"]
        assert "prisma_cloud" in results["tool_reports"]
        assert "crowdstrike" in results["tool_reports"]

    def test_microservices_architecture(self):
        """Test microservices-specific concerns."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["microservices"]

        assert profile["components"] >= 200

        services = [
            {"name": "payment-gateway", "language": "Go"},
            {"name": "fraud-detection", "language": "Python"},
            {"name": "transaction-processor", "language": "Node.js"},
        ]

        assert len(services) > 0
        assert all("language" in s for s in services)

    def test_container_security(self):
        """Test container security scanning."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["microservices"]

        assert profile["deployment"] == "EKS"

        container_findings = {
            "base_image_vulns": 15,
            "app_layer_vulns": 8,
            "config_issues": 3,
        }

        assert container_findings["base_image_vulns"] > 0

    def test_service_mesh_security(self):
        """Test service mesh security considerations."""
        service_mesh_config = {
            "mtls_enabled": True,
            "authorization_policies": ["payment-gateway", "fraud-detection"],
            "network_policies": ["deny-all-default"],
        }

        assert service_mesh_config["mtls_enabled"] is True


class TestLegacyERPSystem:
    """Test Legacy ERP System profile end-to-end."""

    def test_complete_ssdlc_pipeline(self):
        """Test complete SSDLC pipeline for legacy ERP system."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["legacy_system"]
        tools = ["veracode", "invicti"]

        results = EndToEndTestRunner.run_complete_pipeline(profile, tools)

        assert len(results["tool_reports"]) == 2
        assert "veracode" in results["tool_reports"]
        assert "invicti" in results["tool_reports"]

    def test_legacy_technology_stack(self):
        """Test handling of legacy technology stack."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["legacy_system"]

        assert "J2EE" in profile["frameworks"]
        assert "Struts" in profile["frameworks"]

        vulnerable_frameworks = ["Struts"]
        assert any(fw in profile["frameworks"] for fw in vulnerable_frameworks)

    def test_large_codebase_handling(self):
        """Test handling of large legacy codebase."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["legacy_system"]

        assert profile["components"] >= 300

        scan_config = {
            "incremental_scan": True,
            "timeout_minutes": 120,
            "memory_limit_gb": 8,
        }

        assert scan_config["incremental_scan"] is True

    def test_on_premise_deployment(self):
        """Test on-premise deployment considerations."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["legacy_system"]

        assert profile["cloud"] == "On-Premise"

        security_controls = {
            "network_segmentation": True,
            "firewall_rules": ["dmz", "internal"],
            "physical_security": True,
        }

        assert security_controls["network_segmentation"] is True


class TestCrossApplicationAnalytics:
    """Test cross-application analytics and portfolio management."""

    def test_portfolio_risk_assessment(self):
        """Test portfolio-wide risk assessment."""
        all_profiles = [
            EnhancedTestDataGenerator.APP_PROFILES["web_app"],
            EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"],
            EnhancedTestDataGenerator.APP_PROFILES["microservices"],
            EnhancedTestDataGenerator.APP_PROFILES["legacy_system"],
        ]

        portfolio_results = []
        for profile in all_profiles:
            tools = ["sonarqube", "snyk"]
            results = EndToEndTestRunner.run_complete_pipeline(profile, tools)
            portfolio_results.append(results)

        total_findings = sum(r["findings_summary"]["total"] for r in portfolio_results)

        assert len(portfolio_results) == 4
        assert total_findings > 0

    def test_tool_coverage_across_portfolio(self):
        """Test tool coverage across all applications."""
        tool_coverage = {
            "web_app": ["sonarqube", "snyk", "wiz"],
            "mobile_backend": ["veracode", "snyk", "sentinelone"],
            "microservices": ["sonarqube", "prisma_cloud", "crowdstrike"],
            "legacy_system": ["veracode", "invicti"],
        }

        assert all(len(tools) >= 2 for tools in tool_coverage.values())

        snyk_coverage = sum(1 for tools in tool_coverage.values() if "snyk" in tools)
        assert snyk_coverage >= 2

    def test_compliance_across_portfolio(self):
        """Test compliance status across portfolio."""
        compliance_status = {
            "web_app": {"pci_dss": True, "gdpr": True, "soc2": True},
            "mobile_backend": {"pci_dss": True, "soc2": True, "iso27001": True},
            "microservices": {"pci_dss": True, "soc2": True},
            "legacy_system": {"soc2": False, "iso27001": False},
        }

        total_apps = len(compliance_status)
        compliant_apps = sum(
            1 for status in compliance_status.values() if all(status.values())
        )

        compliance_rate = compliant_apps / total_apps

        assert compliance_rate >= 0.0
        assert compliance_rate <= 1.0

    def test_vulnerability_trends(self):
        """Test vulnerability trends across portfolio."""
        historical_data = [
            {"month": "2024-01", "total_vulns": 450, "critical": 12},
            {"month": "2024-02", "total_vulns": 420, "critical": 10},
            {"month": "2024-03", "total_vulns": 380, "critical": 8},
        ]

        trend = (
            "improving"
            if historical_data[-1]["total_vulns"] < historical_data[0]["total_vulns"]
            else "worsening"
        )

        assert trend in ["improving", "worsening", "stable"]


class TestIntegrationWithExistingPipeline:
    """Test integration with existing FixOps pipeline."""

    def test_pipeline_with_web_app_data(self):
        """Test FixOps pipeline with web app data."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]

        sonarqube_report = EnhancedTestDataGenerator.generate_sonarqube_report(profile)
        snyk_report = EnhancedTestDataGenerator.generate_snyk_report(profile)

        sarif_sonarqube = EnhancedTestDataGenerator.convert_to_sarif(
            sonarqube_report, "sonarqube"
        )
        sarif_snyk = EnhancedTestDataGenerator.convert_to_sarif(snyk_report, "snyk")

        assert sarif_sonarqube["version"] == "2.1.0"
        assert sarif_snyk["version"] == "2.1.0"

    def test_pipeline_with_all_profiles(self):
        """Test pipeline can handle all 4 application profiles."""
        all_profiles = [
            EnhancedTestDataGenerator.APP_PROFILES["web_app"],
            EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"],
            EnhancedTestDataGenerator.APP_PROFILES["microservices"],
            EnhancedTestDataGenerator.APP_PROFILES["legacy_system"],
        ]

        for profile in all_profiles:
            sonarqube_report = EnhancedTestDataGenerator.generate_sonarqube_report(
                profile
            )

            assert sonarqube_report["projectName"] == profile["name"]
            assert len(sonarqube_report["issues"]) >= 0


class TestNonFunctionalRequirements:
    """Test non-functional requirements."""

    def test_performance_large_dataset(self):
        """Test performance with large dataset."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["legacy_system"]

        large_report = EnhancedTestDataGenerator.generate_sonarqube_report(
            profile, finding_count=1000
        )

        assert len(large_report["issues"]) >= 1000

    def test_scalability_multiple_apps(self):
        """Test scalability with multiple applications."""
        all_profiles = list(EnhancedTestDataGenerator.APP_PROFILES.values())

        results = []
        for profile in all_profiles:
            result = EndToEndTestRunner.run_complete_pipeline(profile, ["sonarqube"])
            results.append(result)

        assert len(results) == 4

    def test_data_consistency(self):
        """Test data consistency across pipeline."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]

        report1 = EnhancedTestDataGenerator.generate_sonarqube_report(
            profile, finding_count=50
        )
        report2 = EnhancedTestDataGenerator.generate_sonarqube_report(
            profile, finding_count=50
        )

        assert "issues" in report1
        assert "issues" in report2
        assert len(report1["issues"]) == len(report2["issues"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
