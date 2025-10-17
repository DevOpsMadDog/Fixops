"""Comprehensive test data generators for FixOps testing."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict

random.seed(42)


class TestDataGenerator:
    """Generate realistic test data for FixOps testing."""

    @staticmethod
    def generate_design_csv(component_count: int = 50) -> str:
        """Generate a design context CSV with specified number of components."""
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "Component",
                "Exposure",
                "Language",
                "Criticality",
                "Owner",
                "DataClass",
            ],
        )
        writer.writeheader()

        languages = ["Python", "JavaScript", "Java", "Go", "Rust", "C++"]
        exposures = ["internet", "internal", "partner", "dmz"]
        criticalities = ["low", "medium", "high", "critical"]
        data_classes = ["public", "internal", "confidential", "restricted"]

        for i in range(component_count):
            writer.writerow(
                {
                    "Component": f"component-{i:03d}",
                    "Exposure": random.choice(exposures),
                    "Language": random.choice(languages),
                    "Criticality": random.choice(criticalities),
                    "Owner": f"team-{i % 5}",
                    "DataClass": random.choice(data_classes),
                }
            )

        return output.getvalue()

    @staticmethod
    def generate_sbom(
        component_count: int = 800,
        format_type: str = "CycloneDX",
    ) -> Dict[str, Any]:
        """Generate an SBOM with specified number of components."""
        if format_type == "CycloneDX":
            return TestDataGenerator._generate_cyclonedx_sbom(component_count)
        else:
            return TestDataGenerator._generate_spdx_sbom(component_count)

    @staticmethod
    def _generate_cyclonedx_sbom(component_count: int) -> Dict[str, Any]:
        """Generate CycloneDX format SBOM."""
        components = []

        popular_packages = [
            ("requests", "2.31.0", "2.32.0"),
            ("flask", "2.3.0", "3.0.0"),
            ("django", "4.2.0", "5.0.0"),
            ("numpy", "1.24.0", "1.26.0"),
            ("pandas", "2.0.0", "2.1.0"),
            ("fastapi", "0.100.0", "0.110.0"),
            ("sqlalchemy", "2.0.0", "2.0.20"),
            ("pydantic", "2.0.0", "2.5.0"),
            ("click", "8.1.0", "8.1.7"),
            ("pytest", "7.4.0", "8.0.0"),
        ]

        for i in range(component_count):
            if i < len(popular_packages):
                name, old_ver, new_ver = popular_packages[i]
                version = old_ver if random.random() < 0.7 else new_ver
            else:
                name = f"package-{i:04d}"
                version = f"{random.randint(0, 5)}.{random.randint(0, 20)}.{random.randint(0, 50)}"

            component = {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": hashlib.sha256(
                            f"{name}{version}".encode()
                        ).hexdigest(),
                    }
                ],
                "licenses": [
                    {
                        "license": {
                            "id": random.choice(
                                ["MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0"]
                            )
                        }
                    }
                ],
            }

            if random.random() < 0.15:  # 15% have vulnerabilities
                component["vulnerabilities"] = [
                    {
                        "id": f"CVE-2024-{random.randint(10000, 99999)}",
                        "source": {"name": "NVD"},
                        "ratings": [
                            {
                                "severity": random.choice(
                                    ["low", "medium", "high", "critical"]
                                ),
                                "score": random.uniform(3.0, 9.5),
                                "method": "CVSSv3",
                            }
                        ],
                    }
                ]

            components.append(component)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "component": {
                    "type": "application",
                    "name": "test-application",
                    "version": "1.0.0",
                },
            },
            "components": components,
        }

    @staticmethod
    def _generate_spdx_sbom(component_count: int) -> Dict[str, Any]:
        """Generate SPDX format SBOM."""
        packages = []

        for i in range(component_count):
            name = f"package-{i:04d}"
            version = f"{random.randint(0, 5)}.{random.randint(0, 20)}.{random.randint(0, 50)}"

            packages.append(
                {
                    "SPDXID": f"SPDXRef-Package-{i}",
                    "name": name,
                    "versionInfo": version,
                    "downloadLocation": f"https://example.com/{name}/{version}",
                    "filesAnalyzed": False,
                    "licenseConcluded": random.choice(
                        ["MIT", "Apache-2.0", "BSD-3-Clause"]
                    ),
                }
            )

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-application",
            "documentNamespace": f"https://example.com/spdx/{uuid.uuid4()}",
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: test-generator"],
            },
            "packages": packages,
        }

    @staticmethod
    def generate_cve_feed(cve_count: int = 300) -> Dict[str, Any]:
        """Generate CVE feed with specified number of entries."""
        vulnerabilities = []

        for i in range(cve_count):
            cve_id = f"CVE-2024-{10000 + i}"
            severity = random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])

            vuln = {
                "id": cve_id,
                "sourceIdentifier": "nvd@nist.gov",
                "published": (
                    datetime.utcnow() - timedelta(days=random.randint(1, 365))
                ).isoformat()
                + "Z",
                "lastModified": datetime.utcnow().isoformat() + "Z",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": f"Test vulnerability {cve_id} - {severity} severity issue in test package",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": random.uniform(3.0, 9.9),
                                "baseSeverity": severity,
                            },
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {"lang": "en", "value": f"CWE-{random.randint(1, 999)}"}
                        ],
                    }
                ],
                "references": [
                    {
                        "url": f"https://example.com/advisory/{cve_id}",
                        "source": "example.com",
                    }
                ],
            }

            vulnerabilities.append(vuln)

        return {
            "resultsPerPage": cve_count,
            "startIndex": 0,
            "totalResults": cve_count,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "vulnerabilities": vulnerabilities,
        }

    @staticmethod
    def generate_sarif(finding_count: int = 200) -> Dict[str, Any]:
        """Generate SARIF scan results with specified number of findings."""
        results = []

        rule_ids = [
            "sql-injection",
            "xss",
            "hardcoded-credentials",
            "insecure-random",
            "path-traversal",
            "command-injection",
            "xxe",
            "csrf",
            "open-redirect",
            "ssrf",
        ]

        for i in range(finding_count):
            rule_id = random.choice(rule_ids)
            level = random.choice(["note", "warning", "error"])

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Test finding {i}: {rule_id} detected in file",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"src/module_{i % 20}/{random.choice(['main', 'utils', 'models'])}.py",
                            },
                            "region": {
                                "startLine": random.randint(1, 500),
                                "startColumn": random.randint(1, 80),
                            },
                        }
                    }
                ],
            }

            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestScanner",
                            "version": "1.0.0",
                            "informationUri": "https://example.com/scanner",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "name": rule_id.replace("-", " ").title(),
                                    "shortDescription": {
                                        "text": f"{rule_id} vulnerability"
                                    },
                                    "help": {
                                        "text": f"Avoid {rule_id} vulnerabilities"
                                    },
                                }
                                for rule_id in rule_ids
                            ],
                        }
                    },
                    "results": results,
                }
            ],
        }

    @staticmethod
    def generate_vex() -> Dict[str, Any]:
        """Generate VEX document for noise reduction."""
        statements = []

        for i in range(50):
            statements.append(
                {
                    "vulnerability": {
                        "id": f"CVE-2024-{10000 + i}",
                    },
                    "products": [
                        {
                            "id": f"pkg:pypi/package-{i:04d}",
                        }
                    ],
                    "status": random.choice(
                        ["not_affected", "affected", "fixed", "under_investigation"]
                    ),
                    "justification": (
                        random.choice(
                            [
                                "component_not_present",
                                "vulnerable_code_not_present",
                                "vulnerable_code_not_in_execute_path",
                                "vulnerable_code_cannot_be_controlled_by_adversary",
                            ]
                        )
                        if random.random() < 0.5
                        else None
                    ),
                }
            )

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
            "vulnerabilities": statements,
        }

    @staticmethod
    def generate_cnapp() -> Dict[str, Any]:
        """Generate CNAPP findings for cloud security posture."""
        findings = []
        assets = []

        for i in range(30):
            assets.append(
                {
                    "id": f"asset-{i}",
                    "type": random.choice(
                        ["vm", "container", "function", "storage", "database"]
                    ),
                    "name": f"resource-{i}",
                    "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
                    "tags": {
                        "environment": random.choice(["dev", "staging", "prod"]),
                        "owner": f"team-{i % 5}",
                    },
                }
            )

        for i in range(100):
            findings.append(
                {
                    "id": f"finding-{i}",
                    "asset_id": f"asset-{i % 30}",
                    "severity": random.choice(["low", "medium", "high", "critical"]),
                    "category": random.choice(
                        [
                            "misconfiguration",
                            "exposure",
                            "compliance",
                            "vulnerability",
                        ]
                    ),
                    "title": f"Test CNAPP finding {i}",
                    "description": "Test cloud security finding",
                    "recommendation": "Apply security best practices",
                }
            )

        return {
            "metadata": {
                "scan_time": datetime.utcnow().isoformat() + "Z",
                "provider": "test-cnapp",
            },
            "assets": assets,
            "findings": findings,
        }

    @staticmethod
    def write_test_data(output_dir: Path) -> Dict[str, Path]:
        """Generate and write all test data files."""
        output_dir.mkdir(parents=True, exist_ok=True)

        files = {}

        design_path = output_dir / "design.csv"
        design_path.write_text(TestDataGenerator.generate_design_csv(50))
        files["design"] = design_path

        sbom_cyclonedx_path = output_dir / "sbom_cyclonedx.json"
        sbom_cyclonedx_path.write_text(
            json.dumps(TestDataGenerator.generate_sbom(800, "CycloneDX"), indent=2)
        )
        files["sbom_cyclonedx"] = sbom_cyclonedx_path

        sbom_spdx_path = output_dir / "sbom_spdx.json"
        sbom_spdx_path.write_text(
            json.dumps(TestDataGenerator.generate_sbom(800, "SPDX"), indent=2)
        )
        files["sbom_spdx"] = sbom_spdx_path

        cve_path = output_dir / "cve.json"
        cve_path.write_text(
            json.dumps(TestDataGenerator.generate_cve_feed(300), indent=2)
        )
        files["cve"] = cve_path

        sarif_path = output_dir / "scan.sarif"
        sarif_path.write_text(
            json.dumps(TestDataGenerator.generate_sarif(200), indent=2)
        )
        files["sarif"] = sarif_path

        vex_path = output_dir / "vex.json"
        vex_path.write_text(json.dumps(TestDataGenerator.generate_vex(), indent=2))
        files["vex"] = vex_path

        cnapp_path = output_dir / "cnapp.json"
        cnapp_path.write_text(json.dumps(TestDataGenerator.generate_cnapp(), indent=2))
        files["cnapp"] = cnapp_path

        return files


if __name__ == "__main__":
    output_dir = Path(__file__).parent / "generated_test_data"
    files = TestDataGenerator.write_test_data(output_dir)

    print("Generated test data files:")
    for name, path in files.items():
        size_kb = path.stat().st_size / 1024
        print(f"  {name}: {path} ({size_kb:.1f} KB)")
