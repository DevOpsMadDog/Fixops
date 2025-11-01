"""Comprehensive tests for tool integrations with simulated data for 4 real applications.

This test suite covers:
- 4 Real Application Profiles (Web App, Mobile Backend, Microservices, Legacy System)
- Tool Integrations: SonarQube, Snyk, Veracode, Invicti, Wiz, Prisma Cloud, CrowdStrike, etc.
- SSDLC Orchestrator (API/CLI)
- Decision/Correlation Engines
- LLM/Probabilistic Models
- Knowledge Graph/Compliance
- Vulnerability Management/Marketplace/Backtesting
- SBOM Generation (Syft/Trivy/CycloneDX)
- Portfolio Management
"""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict

import pytest


class EnhancedTestDataGenerator:
    """Generate realistic test data for various security tools."""

    APP_PROFILES = {
        "web_app": {
            "name": "E-Commerce Web Application",
            "type": "web",
            "criticality": "high",
            "languages": ["Python", "JavaScript", "TypeScript"],
            "frameworks": ["Django", "React", "FastAPI"],
            "components": 150,
            "dependencies": 1200,
            "cloud": "AWS",
            "deployment": "Kubernetes",
        },
        "mobile_backend": {
            "name": "Mobile Banking Backend",
            "type": "api",
            "criticality": "critical",
            "languages": ["Java", "Kotlin"],
            "frameworks": ["Spring Boot", "Micronaut"],
            "components": 80,
            "dependencies": 800,
            "cloud": "Azure",
            "deployment": "Azure App Service",
        },
        "microservices": {
            "name": "Payment Processing Microservices",
            "type": "microservices",
            "criticality": "critical",
            "languages": ["Go", "Python", "Node.js"],
            "frameworks": ["Gin", "Express", "gRPC"],
            "components": 200,
            "dependencies": 1500,
            "cloud": "AWS",
            "deployment": "EKS",
        },
        "legacy_system": {
            "name": "Legacy ERP System",
            "type": "monolith",
            "criticality": "high",
            "languages": ["Java", "C++"],
            "frameworks": ["J2EE", "Struts"],
            "components": 300,
            "dependencies": 600,
            "cloud": "On-Premise",
            "deployment": "Terraform",
        },
    }

    @staticmethod
    def generate_sonarqube_report(
        profile: Dict[str, Any], finding_count: int = 150
    ) -> Dict[str, Any]:
        """Generate SonarQube SAST report."""
        issues = []

        rule_types = {
            "BUG": ["NullPointerException", "ResourceLeak", "DeadStore"],
            "VULNERABILITY": [
                "SQLInjection",
                "XSS",
                "HardcodedCredentials",
                "WeakCryptography",
            ],
            "CODE_SMELL": ["ComplexMethod", "DuplicateCode", "LongMethod"],
            "SECURITY_HOTSPOT": ["InsecureRandom", "WeakHash", "CookieWithoutSecure"],
        }

        severities = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]

        for i in range(finding_count):
            issue_type = random.choice(list(rule_types.keys()))
            rule = random.choice(rule_types[issue_type])

            issues.append(
                {
                    "key": f"sonar-{uuid.uuid4().hex[:12]}",
                    "rule": f"squid:{rule}",
                    "severity": random.choice(severities),
                    "component": f"src/{random.choice(profile['languages']).lower()}/module_{i % 20}/file.ext",
                    "line": random.randint(1, 500),
                    "message": f"{rule} detected in code",
                    "type": issue_type,
                    "status": "OPEN",
                    "effort": f"{random.randint(5, 120)}min",
                    "debt": f"{random.randint(1, 8)}h",
                    "creationDate": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 90))
                    ).isoformat(),
                }
            )

        return {
            "projectKey": profile["name"].lower().replace(" ", "-"),
            "projectName": profile["name"],
            "version": "1.0.0",
            "analysisDate": datetime.utcnow().isoformat(),
            "issues": issues,
            "metrics": {
                "bugs": len([i for i in issues if i["type"] == "BUG"]),
                "vulnerabilities": len(
                    [i for i in issues if i["type"] == "VULNERABILITY"]
                ),
                "code_smells": len([i for i in issues if i["type"] == "CODE_SMELL"]),
                "security_hotspots": len(
                    [i for i in issues if i["type"] == "SECURITY_HOTSPOT"]
                ),
            },
        }

    @staticmethod
    def generate_snyk_report(
        profile: Dict[str, Any], vuln_count: int = 100
    ) -> Dict[str, Any]:
        """Generate Snyk SCA report."""
        vulnerabilities = []

        for i in range(vuln_count):
            package_name = f"package-{i:04d}"
            cve_id = "CVE-2024-" + str(10000 + i)

            vulnerabilities.append(
                {
                    "id": f"SNYK-{random.choice(['PYTHON', 'JS', 'JAVA'])}-{uuid.uuid4().hex[:12].upper()}",
                    "title": f"Vulnerability in {package_name}",
                    "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cvssScore": round(random.uniform(4.0, 9.9), 1),
                    "severity": random.choice(["low", "medium", "high", "critical"]),
                    "identifiers": {
                        "CVE": [cve_id],
                        "CWE": [f"CWE-{random.randint(1, 999)}"],
                    },
                    "packageName": package_name,
                    "version": f"{random.randint(0, 5)}.{random.randint(0, 20)}.{random.randint(0, 50)}",
                    "exploitMaturity": random.choice(
                        ["no-known-exploit", "proof-of-concept", "functional", "high"]
                    ),
                    "publicationTime": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 365))
                    ).isoformat(),
                    "disclosureTime": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 400))
                    ).isoformat(),
                    "isUpgradable": random.choice([True, False]),
                    "isPatchable": random.choice([True, False]),
                    "upgradePath": [
                        package_name,
                        f"{random.randint(0, 5)}.{random.randint(0, 20)}.{random.randint(0, 50)}",
                    ]
                    if random.random() < 0.6
                    else [],
                }
            )

        return {
            "ok": False,
            "vulnerabilities": vulnerabilities,
            "dependencyCount": profile["dependencies"],
            "org": "test-org",
            "projectName": profile["name"],
            "summary": {
                "critical": len(
                    [v for v in vulnerabilities if v["severity"] == "critical"]
                ),
                "high": len([v for v in vulnerabilities if v["severity"] == "high"]),
                "medium": len(
                    [v for v in vulnerabilities if v["severity"] == "medium"]
                ),
                "low": len([v for v in vulnerabilities if v["severity"] == "low"]),
            },
        }

    @staticmethod
    def generate_veracode_report(
        profile: Dict[str, Any], flaw_count: int = 120
    ) -> Dict[str, Any]:
        """Generate Veracode SAST/SCA/DAST report."""
        flaws = []

        categories = [
            "SQL Injection",
            "Cross-Site Scripting",
            "Command Injection",
            "Path Traversal",
            "Insecure Cryptography",
            "Hardcoded Credentials",
            "XML External Entity",
            "Server-Side Request Forgery",
            "CSRF",
        ]

        for i in range(flaw_count):
            flaws.append(
                {
                    "issueid": random.randint(1000000, 9999999),
                    "cweid": random.randint(1, 999),
                    "categoryname": random.choice(categories),
                    "severity": random.randint(1, 5),
                    "exploitLevel": random.randint(0, 3),
                    "module": f"module-{i % 20}.jar",
                    "sourcefile": f"src/{random.choice(profile['languages']).lower()}/File{i}.ext",
                    "line": random.randint(1, 500),
                    "remediationeffort": random.randint(1, 5),
                    "affects_policy_compliance": random.choice([True, False]),
                    "date_first_occurrence": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 180))
                    ).isoformat(),
                    "remediation_status": random.choice(
                        ["New", "Open", "Fixed", "Mitigated"]
                    ),
                }
            )

        return {
            "app_name": profile["name"],
            "app_id": random.randint(100000, 999999),
            "sandbox_name": "Production",
            "scan_type": "Static",
            "analysis_date": datetime.utcnow().isoformat(),
            "flaws": flaws,
            "policy_compliance_status": "Did Not Pass",
            "total_flaws": len(flaws),
            "flaws_by_severity": {
                "5": len([f for f in flaws if f["severity"] == 5]),
                "4": len([f for f in flaws if f["severity"] == 4]),
                "3": len([f for f in flaws if f["severity"] == 3]),
                "2": len([f for f in flaws if f["severity"] == 2]),
                "1": len([f for f in flaws if f["severity"] == 1]),
            },
        }

    @staticmethod
    def generate_invicti_report(
        profile: Dict[str, Any], vuln_count: int = 80
    ) -> Dict[str, Any]:
        """Generate Invicti (formerly Netsparker) DAST report."""
        vulnerabilities = []

        vuln_types = [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "Local File Inclusion",
            "Remote File Inclusion",
            "XML External Entity",
            "Server-Side Request Forgery",
            "Open Redirect",
            "Clickjacking",
        ]

        for i in range(vuln_count):
            vulnerabilities.append(
                {
                    "Id": str(uuid.uuid4()),
                    "Type": random.choice(vuln_types),
                    "Severity": random.choice(
                        ["Critical", "High", "Medium", "Low", "Information"]
                    ),
                    "Url": f"https://{profile['name'].lower().replace(' ', '-')}.example.com/endpoint/{i}",
                    "HttpMethod": random.choice(["GET", "POST", "PUT", "DELETE"]),
                    "FirstSeenDate": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 90))
                    ).isoformat(),
                    "LastSeenDate": datetime.utcnow().isoformat(),
                    "State": random.choice(
                        ["Present", "Accepted Risk", "False Positive", "Fixed"]
                    ),
                    "Certainty": random.randint(80, 100),
                    "Impact": random.choice(["High", "Medium", "Low"]),
                    "CVSS": round(random.uniform(4.0, 9.9), 1),
                    "CWE": [random.randint(1, 999)],
                }
            )

        return {
            "ScanId": str(uuid.uuid4()),
            "TargetUrl": f"https://{profile['name'].lower().replace(' ', '-')}.example.com",
            "ScanDate": datetime.utcnow().isoformat(),
            "ScanDuration": f"{random.randint(30, 180)} minutes",
            "Vulnerabilities": vulnerabilities,
            "Summary": {
                "Critical": len(
                    [v for v in vulnerabilities if v["Severity"] == "Critical"]
                ),
                "High": len([v for v in vulnerabilities if v["Severity"] == "High"]),
                "Medium": len(
                    [v for v in vulnerabilities if v["Severity"] == "Medium"]
                ),
                "Low": len([v for v in vulnerabilities if v["Severity"] == "Low"]),
            },
        }

    @staticmethod
    def generate_wiz_report(
        profile: Dict[str, Any], issue_count: int = 100
    ) -> Dict[str, Any]:
        """Generate Wiz CNAPP report."""
        issues = []

        issue_types = [
            "Vulnerability",
            "Misconfiguration",
            "Exposure",
            "Identity Risk",
            "Data Risk",
            "Malware",
            "Lateral Movement",
            "Secrets",
        ]

        for i in range(issue_count):
            issues.append(
                {
                    "id": str(uuid.uuid4()),
                    "type": random.choice(issue_types),
                    "severity": random.choice(
                        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
                    ),
                    "status": random.choice(
                        ["OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED"]
                    ),
                    "resource": {
                        "id": f"resource-{i % 30}",
                        "name": f"{profile['name']}-resource-{i % 30}",
                        "type": random.choice(
                            ["VM", "Container", "Function", "Storage", "Database"]
                        ),
                        "cloudPlatform": profile["cloud"],
                        "region": random.choice(
                            ["us-east-1", "us-west-2", "eu-west-1"]
                        ),
                        "subscriptionId": str(uuid.uuid4()),
                    },
                    "createdAt": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 60))
                    ).isoformat(),
                    "updatedAt": datetime.utcnow().isoformat(),
                    "description": f"Security issue detected in {profile['name']}",
                    "remediation": "Apply recommended security controls",
                    "projects": [profile["name"]],
                }
            )

        return {
            "scanId": str(uuid.uuid4()),
            "scanTime": datetime.utcnow().isoformat(),
            "cloudProvider": profile["cloud"],
            "issues": issues,
            "summary": {
                "totalIssues": len(issues),
                "critical": len([i for i in issues if i["severity"] == "CRITICAL"]),
                "high": len([i for i in issues if i["severity"] == "HIGH"]),
                "medium": len([i for i in issues if i["severity"] == "MEDIUM"]),
                "low": len([i for i in issues if i["severity"] == "LOW"]),
            },
        }

    @staticmethod
    def generate_prisma_cloud_report(
        profile: Dict[str, Any], alert_count: int = 90
    ) -> Dict[str, Any]:
        """Generate Palo Alto Prisma Cloud report."""
        alerts = []

        policy_types = [
            "Config",
            "Network",
            "Audit Event",
            "Anomaly",
            "Data",
        ]

        for i in range(alert_count):
            alerts.append(
                {
                    "id": str(uuid.uuid4()),
                    "status": random.choice(
                        ["open", "resolved", "dismissed", "snoozed"]
                    ),
                    "reason": random.choice(
                        ["NEW_ALERT", "RESOURCE_UPDATED", "POLICY_UPDATED"]
                    ),
                    "policy": {
                        "policyId": str(uuid.uuid4()),
                        "name": f"Security Policy {i % 20}",
                        "policyType": random.choice(policy_types),
                        "severity": random.choice(
                            ["critical", "high", "medium", "low", "informational"]
                        ),
                        "complianceMetadata": [
                            {
                                "standardName": "CIS",
                                "requirementId": f"CIS-{random.randint(1, 10)}.{random.randint(1, 20)}",
                            },
                            {
                                "standardName": "PCI-DSS",
                                "requirementId": f"PCI-{random.randint(1, 12)}.{random.randint(1, 5)}",
                            },
                        ],
                    },
                    "resource": {
                        "id": f"resource-{i % 30}",
                        "name": f"{profile['name']}-resource-{i % 30}",
                        "resourceType": random.choice(
                            [
                                "AWS::EC2::Instance",
                                "AWS::S3::Bucket",
                                "Azure::VM",
                                "GCP::ComputeInstance",
                            ]
                        ),
                        "cloudType": profile["cloud"],
                        "region": random.choice(
                            ["us-east-1", "us-west-2", "eu-west-1"]
                        ),
                    },
                    "alertTime": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 45))
                    ).isoformat(),
                    "firstSeen": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 90))
                    ).isoformat(),
                    "lastSeen": datetime.utcnow().isoformat(),
                }
            )

        return {
            "scanId": str(uuid.uuid4()),
            "scanTime": datetime.utcnow().isoformat(),
            "cloudAccount": profile["cloud"],
            "alerts": alerts,
            "summary": {
                "total": len(alerts),
                "open": len([a for a in alerts if a["status"] == "open"]),
                "critical": len(
                    [a for a in alerts if a["policy"]["severity"] == "critical"]
                ),
                "high": len([a for a in alerts if a["policy"]["severity"] == "high"]),
            },
        }

    @staticmethod
    def generate_crowdstrike_report(
        profile: Dict[str, Any], detection_count: int = 50
    ) -> Dict[str, Any]:
        """Generate CrowdStrike EDR report."""
        detections = []

        tactics = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
        ]
        techniques = ["T1190", "T1059", "T1053", "T1068", "T1055"]

        for i in range(detection_count):
            detections.append(
                {
                    "detection_id": str(uuid.uuid4()),
                    "created_timestamp": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 30))
                    ).isoformat(),
                    "severity": random.randint(1, 5),
                    "status": random.choice(
                        [
                            "new",
                            "in_progress",
                            "true_positive",
                            "false_positive",
                            "ignored",
                        ]
                    ),
                    "tactic": random.choice(tactics),
                    "technique": random.choice(techniques),
                    "device": {
                        "device_id": f"device-{i % 20}",
                        "hostname": f"{profile['name'].lower().replace(' ', '-')}-host-{i % 20}",
                        "platform": random.choice(["Windows", "Linux", "Mac"]),
                    },
                    "behaviors": [
                        {
                            "behavior_id": str(uuid.uuid4()),
                            "filename": f"suspicious_file_{i}.exe",
                            "filepath": f"/path/to/file_{i}",
                            "cmdline": f"command_{i} --args",
                            "user_name": f"user{i % 10}",
                        }
                    ],
                }
            )

        return {
            "scanId": str(uuid.uuid4()),
            "scanTime": datetime.utcnow().isoformat(),
            "detections": detections,
            "summary": {
                "total": len(detections),
                "critical": len([d for d in detections if d["severity"] == 5]),
                "high": len([d for d in detections if d["severity"] == 4]),
                "medium": len([d for d in detections if d["severity"] == 3]),
            },
        }

    @staticmethod
    def generate_sentinelone_report(
        profile: Dict[str, Any], threat_count: int = 40
    ) -> Dict[str, Any]:
        """Generate SentinelOne EDR report."""
        threats = []

        threat_types = ["Malware", "Ransomware", "Trojan", "Exploit", "PUA"]

        for i in range(threat_count):
            threats.append(
                {
                    "id": str(uuid.uuid4()),
                    "createdAt": (
                        datetime.utcnow() - timedelta(days=random.randint(1, 30))
                    ).isoformat(),
                    "updatedAt": datetime.utcnow().isoformat(),
                    "classification": random.choice(threat_types),
                    "confidenceLevel": random.choice(
                        ["malicious", "suspicious", "n/a"]
                    ),
                    "mitigationStatus": random.choice(
                        ["not_mitigated", "mitigated", "marked_as_benign"]
                    ),
                    "threatName": f"Threat.{random.choice(threat_types)}.{i}",
                    "agentComputerName": f"{profile['name'].lower().replace(' ', '-')}-agent-{i % 20}",
                    "agentOsType": random.choice(["windows", "linux", "macos"]),
                    "filePath": f"/path/to/threat/file_{i}",
                    "fileContentHash": hashlib.sha256(
                        f"threat{i}".encode()
                    ).hexdigest(),
                }
            )

        return {
            "scanId": str(uuid.uuid4()),
            "scanTime": datetime.utcnow().isoformat(),
            "threats": threats,
            "summary": {
                "total": len(threats),
                "malicious": len(
                    [t for t in threats if t["confidenceLevel"] == "malicious"]
                ),
                "suspicious": len(
                    [t for t in threats if t["confidenceLevel"] == "suspicious"]
                ),
            },
        }

    @staticmethod
    def convert_to_sarif(tool_report: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
        """Convert various tool reports to SARIF format."""
        results = []

        if tool_name == "sonarqube":
            for issue in tool_report.get("issues", []):
                results.append(
                    {
                        "ruleId": issue["rule"],
                        "level": "error"
                        if issue["severity"] in ["BLOCKER", "CRITICAL"]
                        else "warning",
                        "message": {"text": issue["message"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": issue["component"]},
                                    "region": {"startLine": issue.get("line", 1)},
                                }
                            }
                        ],
                    }
                )
        elif tool_name == "snyk":
            for vuln in tool_report.get("vulnerabilities", []):
                results.append(
                    {
                        "ruleId": vuln["id"],
                        "level": "error"
                        if vuln["severity"] in ["critical", "high"]
                        else "warning",
                        "message": {"text": vuln["title"]},
                        "properties": {
                            "cvssScore": vuln["cvssScore"],
                            "packageName": vuln["packageName"],
                        },
                    }
                )
        elif tool_name == "veracode":
            for flaw in tool_report.get("flaws", []):
                results.append(
                    {
                        "ruleId": f"CWE-{flaw['cweid']}",
                        "level": "error" if flaw["severity"] >= 4 else "warning",
                        "message": {"text": flaw["categoryname"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": flaw["sourcefile"]},
                                    "region": {"startLine": flaw.get("line", 1)},
                                }
                            }
                        ],
                    }
                )

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": "1.0.0",
                        }
                    },
                    "results": results,
                }
            ],
        }


class TestToolIntegrations:
    """Test integration with various security tools."""

    def test_sonarqube_integration_web_app(self):
        """Test SonarQube integration with web application profile."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]
        sonarqube_report = EnhancedTestDataGenerator.generate_sonarqube_report(profile)

        assert sonarqube_report["projectName"] == profile["name"]
        assert len(sonarqube_report["issues"]) > 0
        assert "metrics" in sonarqube_report

    def test_snyk_integration_mobile_backend(self):
        """Test Snyk integration with mobile backend profile."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"]
        snyk_report = EnhancedTestDataGenerator.generate_snyk_report(profile)

        assert snyk_report["projectName"] == profile["name"]
        assert len(snyk_report["vulnerabilities"]) > 0
        assert "summary" in snyk_report

    def test_veracode_integration_microservices(self):
        """Test Veracode integration with microservices profile."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["microservices"]
        veracode_report = EnhancedTestDataGenerator.generate_veracode_report(profile)

        assert veracode_report["app_name"] == profile["name"]
        assert len(veracode_report["flaws"]) > 0
        assert "flaws_by_severity" in veracode_report

    def test_invicti_integration_legacy_system(self):
        """Test Invicti DAST integration with legacy system profile."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["legacy_system"]
        invicti_report = EnhancedTestDataGenerator.generate_invicti_report(profile)

        assert len(invicti_report["Vulnerabilities"]) > 0
        assert "Summary" in invicti_report

    def test_wiz_cnapp_integration(self):
        """Test Wiz CNAPP integration."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]
        wiz_report = EnhancedTestDataGenerator.generate_wiz_report(profile)

        assert len(wiz_report["issues"]) > 0
        assert wiz_report["cloudProvider"] == profile["cloud"]
        assert "summary" in wiz_report

    def test_prisma_cloud_integration(self):
        """Test Prisma Cloud integration."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["microservices"]
        prisma_report = EnhancedTestDataGenerator.generate_prisma_cloud_report(profile)

        assert len(prisma_report["alerts"]) > 0
        assert prisma_report["cloudAccount"] == profile["cloud"]
        assert "summary" in prisma_report

    def test_crowdstrike_edr_integration(self):
        """Test CrowdStrike EDR integration."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]
        crowdstrike_report = EnhancedTestDataGenerator.generate_crowdstrike_report(
            profile
        )

        assert len(crowdstrike_report["detections"]) > 0
        assert "summary" in crowdstrike_report

    def test_sentinelone_edr_integration(self):
        """Test SentinelOne EDR integration."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"]
        sentinelone_report = EnhancedTestDataGenerator.generate_sentinelone_report(
            profile
        )

        assert len(sentinelone_report["threats"]) > 0
        assert "summary" in sentinelone_report

    def test_sarif_conversion_sonarqube(self):
        """Test SARIF conversion for SonarQube reports."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]
        sonarqube_report = EnhancedTestDataGenerator.generate_sonarqube_report(profile)
        sarif = EnhancedTestDataGenerator.convert_to_sarif(
            sonarqube_report, "sonarqube"
        )

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) > 0
        assert len(sarif["runs"][0]["results"]) > 0

    def test_sarif_conversion_snyk(self):
        """Test SARIF conversion for Snyk reports."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"]
        snyk_report = EnhancedTestDataGenerator.generate_snyk_report(profile)
        sarif = EnhancedTestDataGenerator.convert_to_sarif(snyk_report, "snyk")

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) > 0

    def test_sarif_conversion_veracode(self):
        """Test SARIF conversion for Veracode reports."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["microservices"]
        veracode_report = EnhancedTestDataGenerator.generate_veracode_report(profile)
        sarif = EnhancedTestDataGenerator.convert_to_sarif(veracode_report, "veracode")

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) > 0


class TestFourApplicationProfiles:
    """Test all 4 application profiles end-to-end."""

    def test_web_app_complete_pipeline(self):
        """Test complete pipeline for web application."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["web_app"]

        sonarqube = EnhancedTestDataGenerator.generate_sonarqube_report(profile)
        snyk = EnhancedTestDataGenerator.generate_snyk_report(profile)
        wiz = EnhancedTestDataGenerator.generate_wiz_report(profile)

        assert sonarqube["projectName"] == profile["name"]
        assert snyk["projectName"] == profile["name"]
        assert len(wiz["issues"]) > 0

    def test_mobile_backend_complete_pipeline(self):
        """Test complete pipeline for mobile backend."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["mobile_backend"]

        veracode = EnhancedTestDataGenerator.generate_veracode_report(profile)
        snyk = EnhancedTestDataGenerator.generate_snyk_report(profile)
        sentinelone = EnhancedTestDataGenerator.generate_sentinelone_report(profile)

        assert veracode["app_name"] == profile["name"]
        assert snyk["projectName"] == profile["name"]
        assert len(sentinelone["threats"]) > 0

    def test_microservices_complete_pipeline(self):
        """Test complete pipeline for microservices."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["microservices"]

        sonarqube = EnhancedTestDataGenerator.generate_sonarqube_report(profile)
        prisma = EnhancedTestDataGenerator.generate_prisma_cloud_report(profile)
        crowdstrike = EnhancedTestDataGenerator.generate_crowdstrike_report(profile)

        assert sonarqube["projectName"] == profile["name"]
        assert len(prisma["alerts"]) > 0
        assert len(crowdstrike["detections"]) > 0

    def test_legacy_system_complete_pipeline(self):
        """Test complete pipeline for legacy system."""
        profile = EnhancedTestDataGenerator.APP_PROFILES["legacy_system"]

        veracode = EnhancedTestDataGenerator.generate_veracode_report(profile)
        invicti = EnhancedTestDataGenerator.generate_invicti_report(profile)

        assert veracode["app_name"] == profile["name"]
        assert len(invicti["Vulnerabilities"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
