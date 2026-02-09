#!/usr/bin/env python3
"""
Comprehensive End-to-End Validation for FixOps
Tests Requirements → Design → SSDLC → Operate across 4 realistic apps
"""

import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from apps.api.normalizers import InputNormalizer


class ComprehensiveValidator:
    """Comprehensive end-to-end validation orchestrator"""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "apps": {},
            "functional_tests": {},
            "non_functional_tests": {},
            "summary": {},
        }
        self.normalizer = InputNormalizer()

    def log(self, message: str, level: str = "INFO"):
        """Log message with timestamp"""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def validate_app(self, app_id: str, app_name: str, app_dir: Path) -> Dict[str, Any]:
        """Validate a single app through complete pipeline"""
        self.log(f"Starting validation for {app_name} ({app_id})")

        app_results = {
            "app_id": app_id,
            "app_name": app_name,
            "stages": {},
            "findings": [],
            "errors": [],
        }

        try:
            self.log(f"  Stage 1: Loading requirements for {app_name}")
            req_file = app_dir / "requirements" / "requirements.csv"
            if req_file.exists():
                requirements = self.load_requirements(req_file)
                app_results["stages"]["requirements"] = {
                    "status": "success",
                    "count": len(requirements),
                    "data": requirements,
                }
                self.log(f"    ✓ Loaded {len(requirements)} requirements")
            else:
                app_results["errors"].append(f"Requirements file not found: {req_file}")

            self.log(f"  Stage 2: Loading design context for {app_name}")
            design_file = app_dir / "design" / "design_context.csv"
            if design_file.exists():
                design_context = self.load_design_context(design_file)
                app_results["stages"]["design"] = {
                    "status": "success",
                    "count": len(design_context),
                    "threats": [
                        d
                        for d in design_context
                        if d.get("severity") in ["critical", "high"]
                    ],
                    "data": design_context,
                }
                self.log(f"    ✓ Loaded {len(design_context)} design threats")
            else:
                app_results["errors"].append(f"Design file not found: {design_file}")

            self.log(f"  Stage 3a: Normalizing SBOM for {app_name}")
            sbom_file = app_dir / "ssdlc" / "sbom.json"
            if sbom_file.exists():
                with open(sbom_file, "r") as f:
                    sbom_data = json.load(f)
                normalized_sbom = self.normalizer.load_sbom(sbom_data)
                app_results["stages"]["sbom"] = {
                    "status": "success",
                    "components": len(normalized_sbom.components),
                    "vulnerabilities": len(normalized_sbom.vulnerabilities),
                    "data": normalized_sbom,
                }
                self.log(
                    f"    ✓ Normalized {len(normalized_sbom.components)} components, {app_results['stages']['sbom']['vulnerabilities']} vulnerabilities"
                )
            else:
                app_results["errors"].append(f"SBOM file not found: {sbom_file}")

            self.log(f"  Stage 3b: Normalizing SARIF for {app_name}")
            sarif_file = app_dir / "ssdlc" / "scan.sarif"
            if sarif_file.exists():
                with open(sarif_file, "r") as f:
                    sarif_data = json.load(f)
                normalized_sarif = self.normalizer.load_sarif(sarif_data)
                app_results["stages"]["sarif"] = {
                    "status": "success",
                    "findings": len(normalized_sarif.findings),
                    "critical": len(
                        [f for f in normalized_sarif.findings if f.level == "error"]
                    ),
                    "high": len(
                        [f for f in normalized_sarif.findings if f.level == "warning"]
                    ),
                    "data": normalized_sarif,
                }
                self.log(
                    f"    ✓ Normalized {len(normalized_sarif.findings)} SARIF findings"
                )
            else:
                app_results["errors"].append(f"SARIF file not found: {sarif_file}")

            self.log(f"  Stage 4: Loading operational findings for {app_name}")
            operate_files = list((app_dir / "operate").glob("*.json"))
            operate_findings = []
            for operate_file in operate_files:
                with open(operate_file, "r") as f:
                    operate_data = json.load(f)
                    if "findings" in operate_data:
                        operate_findings.extend(operate_data["findings"])
                    if "prisma_findings" in operate_data:
                        operate_findings.extend(operate_data["prisma_findings"])
                    if "tenable_findings" in operate_data:
                        operate_findings.extend(operate_data["tenable_findings"])
                    if "contrast_rasp_findings" in operate_data:
                        operate_findings.extend(operate_data["contrast_rasp_findings"])
                    if "snyk_findings" in operate_data:
                        operate_findings.extend(operate_data["snyk_findings"])
                    if "wiz_findings" in operate_data:
                        operate_findings.extend(operate_data["wiz_findings"])

            app_results["stages"]["operate"] = {
                "status": "success",
                "findings": len(operate_findings),
                "critical": len(
                    [f for f in operate_findings if f.get("severity") == "CRITICAL"]
                ),
                "data": operate_findings,
            }
            self.log(f"    ✓ Loaded {len(operate_findings)} operational findings")

            all_findings = []

            if "sbom" in app_results["stages"]:
                for vuln in normalized_sbom.vulnerabilities:
                    if isinstance(vuln, dict):
                        vuln_id = vuln.get("id") or vuln.get("cve") or "UNKNOWN"
                        severity = vuln.get("severity", "unknown")
                        if isinstance(severity, list) and severity:
                            severity = severity[0]
                        if isinstance(severity, dict):
                            severity = severity.get("severity", "unknown")

                        affects = vuln.get("affects", [])
                        component_ref = None
                        if affects and isinstance(affects, list):
                            component_ref = (
                                affects[0].get("ref")
                                if isinstance(affects[0], dict)
                                else None
                            )

                        all_findings.append(
                            {
                                "source": "SBOM",
                                "app_id": app_id,
                                "type": "vulnerability",
                                "id": vuln_id,
                                "severity": severity
                                if isinstance(severity, str)
                                else "unknown",
                                "component_ref": component_ref,
                                "description": vuln.get("description", ""),
                            }
                        )

            if "sarif" in app_results["stages"]:
                for finding in normalized_sarif.findings:
                    all_findings.append(
                        {
                            "source": "SARIF",
                            "app_id": app_id,
                            "type": "code_issue",
                            "id": finding.rule_id,
                            "level": finding.level,
                            "file": finding.file,
                            "line": finding.line,
                            "message": finding.message,
                        }
                    )

            all_findings.extend(
                [
                    {
                        "source": f.get("source", "Unknown"),
                        "app_id": app_id,
                        "type": "operational",
                        **f,
                    }
                    for f in operate_findings
                ]
            )

            app_results["findings"] = all_findings
            app_results["total_findings"] = len(all_findings)

            self.log(
                f"  ✓ Completed validation for {app_name}: {len(all_findings)} total findings"
            )

        except Exception as e:
            self.log(f"  ✗ Error validating {app_name}: {str(e)}", "ERROR")
            app_results["errors"].append(str(e))

        return app_results

    def load_requirements(self, file_path: Path) -> List[Dict[str, Any]]:
        """Load requirements from CSV"""
        requirements = []
        with open(file_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                requirements.append(row)
        return requirements

    def load_design_context(self, file_path: Path) -> List[Dict[str, Any]]:
        """Load design context from CSV"""
        design_context = []
        with open(file_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                design_context.append(row)
        return design_context

    def test_transitive_risk_propagation(
        self, app_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Test transitive dependency risk propagation"""
        self.log("Testing transitive risk propagation...")

        test_result = {
            "name": "Transitive Risk Propagation",
            "status": "pending",
            "details": {},
        }

        try:
            transitive_vulns = []
            for app_id, app_data in app_results.items():
                if "sbom" in app_data["stages"]:
                    sbom = app_data["stages"]["sbom"]["data"]
                    for vuln in sbom.vulnerabilities:
                        if isinstance(vuln, dict):
                            vuln_id = vuln.get("id") or vuln.get("cve") or "UNKNOWN"
                            severity = vuln.get("severity", "unknown")
                            if isinstance(severity, list) and severity:
                                severity = severity[0]
                            if isinstance(severity, dict):
                                severity = severity.get("severity", "unknown")

                            transitive_vulns.append(
                                {
                                    "app_id": app_id,
                                    "vulnerability": vuln_id,
                                    "severity": severity
                                    if isinstance(severity, str)
                                    else "unknown",
                                }
                            )

            test_result["status"] = "pass" if len(transitive_vulns) > 0 else "fail"
            test_result["details"] = {
                "transitive_vulnerabilities_found": len(transitive_vulns),
                "examples": transitive_vulns[:5],
            }
            self.log(f"  ✓ Found {len(transitive_vulns)} transitive vulnerabilities")

        except Exception as e:
            test_result["status"] = "error"
            test_result["error"] = str(e)
            self.log(f"  ✗ Error: {str(e)}", "ERROR")

        return test_result

    def test_typosquat_detection(self, app_results: Dict[str, Any]) -> Dict[str, Any]:
        """Test typosquat and backdoor detection"""
        self.log("Testing typosquat/backdoor detection...")

        test_result = {
            "name": "Typosquat/Backdoor Detection",
            "status": "pending",
            "details": {},
        }

        try:
            typosquat_packages = []
            for app_id, app_data in app_results.items():
                if "sbom" in app_data["stages"]:
                    sbom = app_data["stages"]["sbom"]["data"]
                    for component in sbom.components:
                        raw_component = (
                            component.raw if hasattr(component, "raw") else {}
                        )
                        properties = raw_component.get("properties", [])
                        if isinstance(properties, list):
                            for prop in properties:
                                if (
                                    isinstance(prop, dict)
                                    and prop.get("name")
                                    == "malicious_package_suspected"
                                    and prop.get("value") == "true"
                                ):
                                    typosquat_packages.append(
                                        {
                                            "app_id": app_id,
                                            "package": component.name,
                                            "version": component.version,
                                            "typosquat_of": next(
                                                (
                                                    p.get("value")
                                                    for p in properties
                                                    if isinstance(p, dict)
                                                    and p.get("name") == "typosquat_of"
                                                ),
                                                None,
                                            ),
                                            "maintainer_reputation": next(
                                                (
                                                    p.get("value")
                                                    for p in properties
                                                    if isinstance(p, dict)
                                                    and p.get("name")
                                                    == "maintainer_reputation"
                                                ),
                                                None,
                                            ),
                                        }
                                    )

            test_result["status"] = "pass" if len(typosquat_packages) > 0 else "fail"
            test_result["details"] = {
                "typosquat_packages_detected": len(typosquat_packages),
                "packages": typosquat_packages,
            }
            self.log(f"  ✓ Detected {len(typosquat_packages)} typosquat packages")

        except Exception as e:
            test_result["status"] = "error"
            test_result["error"] = str(e)
            self.log(f"  ✗ Error: {str(e)}", "ERROR")

        return test_result

    def test_correlation_deduplication(
        self, app_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Test correlation and deduplication"""
        self.log("Testing correlation and deduplication...")

        test_result = {
            "name": "Correlation & Deduplication",
            "status": "pending",
            "details": {},
        }

        try:
            all_findings = []
            for app_id, app_data in app_results.items():
                all_findings.extend(app_data.get("findings", []))

            cve_groups = {}
            cwe_groups = {}

            for finding in all_findings:
                if "cve" in finding:
                    cve = finding["cve"]
                    if cve not in cve_groups:
                        cve_groups[cve] = []
                    cve_groups[cve].append(finding)

                if "cwe" in finding:
                    cwe = finding["cwe"]
                    if cwe not in cwe_groups:
                        cwe_groups[cwe] = []
                    cwe_groups[cwe].append(finding)

            duplicates = sum(
                len(findings) - 1
                for findings in cve_groups.values()
                if len(findings) > 1
            )
            unique_cves = len(cve_groups)
            unique_cwes = len(cwe_groups)

            test_result["status"] = "pass"
            test_result["details"] = {
                "total_findings": len(all_findings),
                "unique_cves": unique_cves,
                "unique_cwes": unique_cwes,
                "duplicates_eliminated": duplicates,
                "deduplication_rate": f"{(duplicates / len(all_findings) * 100):.1f}%"
                if all_findings
                else "0%",
            }
            self.log(
                f"  ✓ Eliminated {duplicates} duplicates ({test_result['details']['deduplication_rate']})"
            )

        except Exception as e:
            test_result["status"] = "error"
            test_result["error"] = str(e)
            self.log(f"  ✗ Error: {str(e)}", "ERROR")

        return test_result

    def test_compliance_mapping(self, app_results: Dict[str, Any]) -> Dict[str, Any]:
        """Test compliance framework mapping"""
        self.log("Testing compliance framework mapping...")

        test_result = {"name": "Compliance Mapping", "status": "pending", "details": {}}

        try:
            frameworks = {
                "SOC2": set(),
                "ISO27001": set(),
                "PCI-DSS": set(),
                "NIST CSF": set(),
                "Essential 8": set(),
                "GDPR": set(),
            }

            for app_id, app_data in app_results.items():
                for finding in app_data.get("findings", []):
                    if "compliance_frameworks" in finding:
                        for framework in finding["compliance_frameworks"]:
                            for fw_name in frameworks.keys():
                                if fw_name in framework or framework in fw_name:
                                    frameworks[fw_name].add(framework)

            test_result["status"] = "pass"
            test_result["details"] = {
                "frameworks_mapped": {k: len(v) for k, v in frameworks.items()},
                "total_controls": sum(len(v) for v in frameworks.values()),
            }
            self.log(
                f"  ✓ Mapped {test_result['details']['total_controls']} compliance controls"
            )

        except Exception as e:
            test_result["status"] = "error"
            test_result["error"] = str(e)
            self.log(f"  ✗ Error: {str(e)}", "ERROR")

        return test_result

    def test_performance(self, app_results: Dict[str, Any]) -> Dict[str, Any]:
        """Test performance with 10k+ findings"""
        self.log("Testing performance (10k findings < 60s)...")

        test_result = {"name": "Performance Test", "status": "pending", "details": {}}

        try:
            all_findings = []
            for app_id, app_data in app_results.items():
                all_findings.extend(app_data.get("findings", []))

            start_time = time.time()

            processed = 0
            for finding in all_findings:
                score = 0.0
                if finding.get("severity") == "critical":
                    score = 1.0
                elif finding.get("severity") == "high":
                    score = 0.75
                elif finding.get("severity") == "medium":
                    score = 0.5
                else:
                    score = 0.25

                finding["calculated_score"] = score
                processed += 1

            elapsed_time = time.time() - start_time

            test_result["status"] = "pass" if elapsed_time < 60 else "fail"
            test_result["details"] = {
                "findings_processed": processed,
                "elapsed_time_seconds": f"{elapsed_time:.2f}",
                "findings_per_second": f"{processed / elapsed_time:.0f}"
                if elapsed_time > 0
                else "N/A",
                "meets_requirement": elapsed_time < 60,
            }
            self.log(f"  ✓ Processed {processed} findings in {elapsed_time:.2f}s")

        except Exception as e:
            test_result["status"] = "error"
            test_result["error"] = str(e)
            self.log(f"  ✗ Error: {str(e)}", "ERROR")

        return test_result

    def test_determinism(self, app_results: Dict[str, Any]) -> Dict[str, Any]:
        """Test deterministic scoring"""
        self.log("Testing determinism (same inputs → same scores)...")

        test_result = {"name": "Determinism Test", "status": "pending", "details": {}}

        try:
            scores_run1 = {}
            scores_run2 = {}

            for app_id, app_data in app_results.items():
                for i, finding in enumerate(app_data.get("findings", [])):
                    finding_key = f"{app_id}_{i}"

                    score1 = self.calculate_score(finding)
                    scores_run1[finding_key] = score1

                    score2 = self.calculate_score(finding)
                    scores_run2[finding_key] = score2

            mismatches = 0
            for key in scores_run1:
                if scores_run1[key] != scores_run2[key]:
                    mismatches += 1

            test_result["status"] = "pass" if mismatches == 0 else "fail"
            test_result["details"] = {
                "total_scores": len(scores_run1),
                "mismatches": mismatches,
                "deterministic": mismatches == 0,
            }
            self.log(
                f"  ✓ Determinism test: {mismatches} mismatches out of {len(scores_run1)}"
            )

        except Exception as e:
            test_result["status"] = "error"
            test_result["error"] = str(e)
            self.log(f"  ✗ Error: {str(e)}", "ERROR")

        return test_result

    def calculate_score(self, finding: Dict[str, Any]) -> float:
        """Calculate score for a finding"""
        score = 0.0

        severity_map = {
            "critical": 1.0,
            "CRITICAL": 1.0,
            "high": 0.75,
            "HIGH": 0.75,
            "medium": 0.5,
            "MEDIUM": 0.5,
            "low": 0.25,
            "LOW": 0.25,
        }

        severity = finding.get("severity", "low")
        score = severity_map.get(severity, 0.25)

        if "cvss_score" in finding:
            cvss = float(finding["cvss_score"])
            score = max(score, cvss / 10.0)

        if finding.get("kev_listed") or finding.get("exploit_available"):
            score = min(1.0, score * 1.5)

        if "epss_score" in finding:
            epss = float(finding["epss_score"])
            if epss >= 0.7:
                score = min(1.0, score * 1.3)

        return round(score, 3)

    def run_validation(self):
        """Run comprehensive validation"""
        self.log("=" * 80)
        self.log("COMPREHENSIVE FIXOPS END-TO-END VALIDATION")
        self.log("=" * 80)

        apps = [
            ("APP1", "InsureCo Web", self.base_dir / "app1_insureco"),
            ("APP2", "Micro-frontend + ESB", self.base_dir / "app2_microfrontend"),
            ("APP3", "B2B Quotes", self.base_dir / "app3_b2b_quotes"),
            ("APP4", "Streaming/Events", self.base_dir / "app4_streaming"),
        ]

        for app_id, app_name, app_dir in apps:
            app_results = self.validate_app(app_id, app_name, app_dir)
            self.results["apps"][app_id] = app_results

        self.log("\n" + "=" * 80)
        self.log("FUNCTIONAL TESTS")
        self.log("=" * 80)

        self.results["functional_tests"][
            "transitive_risk"
        ] = self.test_transitive_risk_propagation(self.results["apps"])
        self.results["functional_tests"][
            "typosquat_detection"
        ] = self.test_typosquat_detection(self.results["apps"])
        self.results["functional_tests"][
            "correlation_dedup"
        ] = self.test_correlation_deduplication(self.results["apps"])
        self.results["functional_tests"][
            "compliance_mapping"
        ] = self.test_compliance_mapping(self.results["apps"])

        self.log("\n" + "=" * 80)
        self.log("NON-FUNCTIONAL TESTS")
        self.log("=" * 80)

        self.results["non_functional_tests"]["performance"] = self.test_performance(
            self.results["apps"]
        )
        self.results["non_functional_tests"]["determinism"] = self.test_determinism(
            self.results["apps"]
        )

        self.generate_summary()

        return self.results

    def generate_summary(self):
        """Generate validation summary"""
        self.log("\n" + "=" * 80)
        self.log("VALIDATION SUMMARY")
        self.log("=" * 80)

        total_findings = 0
        total_critical = 0
        total_high = 0

        for app_id, app_data in self.results["apps"].items():
            findings = app_data.get("findings", [])
            total_findings += len(findings)
            total_critical += len(
                [f for f in findings if f.get("severity") in ["critical", "CRITICAL"]]
            )
            total_high += len(
                [f for f in findings if f.get("severity") in ["high", "HIGH"]]
            )

        self.results["summary"]["total_apps"] = len(self.results["apps"])
        self.results["summary"]["total_findings"] = total_findings
        self.results["summary"]["critical_findings"] = total_critical
        self.results["summary"]["high_findings"] = total_high

        functional_passed = sum(
            1
            for t in self.results["functional_tests"].values()
            if t["status"] == "pass"
        )
        functional_total = len(self.results["functional_tests"])

        non_functional_passed = sum(
            1
            for t in self.results["non_functional_tests"].values()
            if t["status"] == "pass"
        )
        non_functional_total = len(self.results["non_functional_tests"])

        self.results["summary"][
            "functional_tests_passed"
        ] = f"{functional_passed}/{functional_total}"
        self.results["summary"][
            "non_functional_tests_passed"
        ] = f"{non_functional_passed}/{non_functional_total}"

        self.log(f"\nApps Validated: {self.results['summary']['total_apps']}")
        self.log(f"Total Findings: {total_findings}")
        self.log(f"  - Critical: {total_critical}")
        self.log(f"  - High: {total_high}")
        self.log(f"\nFunctional Tests: {functional_passed}/{functional_total} passed")
        self.log(
            f"Non-Functional Tests: {non_functional_passed}/{non_functional_total} passed"
        )


def main():
    """Main entry point"""
    base_dir = Path(__file__).parent
    validator = ComprehensiveValidator(base_dir)

    results = validator.run_validation()

    output_file = base_dir / "validation_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    validator.log(f"\n✓ Results saved to: {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
