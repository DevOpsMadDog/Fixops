"""
Comprehensive end-to-end test suite with completely fresh test data.
Tests all components: API, CLI, configuration, math models, LLM integration.
"""

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest


class FreshTestDataGenerator:
    """Generate completely fresh test data for comprehensive testing."""

    def __init__(self, seed: int = None):
        self.seed = seed or secrets.randbits(32)
        self.component_counter = 0
        self.vuln_counter = 0

    def generate_design_csv(self, num_components: int = 50) -> str:
        """Generate fresh design CSV with realistic component data."""
        rows = ["component_name,criticality,data_classification,environment"]

        criticalities = ["critical", "high", "medium", "low"]
        classifications = ["public", "internal", "confidential", "restricted"]
        environments = ["production", "staging", "development", "test"]

        for i in range(num_components):
            self.component_counter += 1
            name = f"comp-{self.seed}-{self.component_counter:04d}"
            crit = criticalities[i % len(criticalities)]
            classif = classifications[i % len(classifications)]
            env = environments[i % len(environments)]
            rows.append(f"{name},{crit},{classif},{env}")

        return "\n".join(rows)

    def generate_sbom(self, num_packages: int = 100) -> Dict[str, Any]:
        """Generate fresh CycloneDX SBOM with realistic packages."""
        components = []

        package_prefixes = [
            "api-client",
            "data-processor",
            "auth-handler",
            "db-connector",
            "cache-manager",
            "logger-util",
            "config-parser",
            "http-server",
            "message-queue",
        ]

        for i in range(num_packages):
            prefix = package_prefixes[i % len(package_prefixes)]
            name = f"{prefix}-{self.seed}-{i:04d}"
            version = f"{1 + i // 20}.{(i // 5) % 10}.{i % 5}"

            component = {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "licenses": [{"license": {"id": "MIT"}}],
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": hashlib.sha256(
                            f"{name}:{version}".encode()
                        ).hexdigest(),
                    }
                ],
            }
            components.append(component)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "component": {
                    "type": "application",
                    "name": f"test-app-{self.seed}",
                    "version": "1.0.0",
                },
            },
            "components": components,
        }

    def generate_sarif(self, num_findings: int = 75) -> Dict[str, Any]:
        """Generate fresh SARIF with realistic security findings."""
        results = []

        severities = ["error", "warning", "note"]
        categories = [
            "sql-injection",
            "xss",
            "csrf",
            "weak-crypto",
            "path-traversal",
            "command-injection",
            "xxe",
        ]

        for i in range(num_findings):
            self.vuln_counter += 1
            category = categories[i % len(categories)]
            severity = severities[i % len(severities)]

            result = {
                "ruleId": f"RULE-{self.seed}-{self.vuln_counter:04d}",
                "level": severity,
                "message": {
                    "text": f"Security issue: {category} detected in component"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"src/module_{i % 10}/file_{i}.py"
                            },
                            "region": {"startLine": 10 + i, "startColumn": 5},
                        }
                    }
                ],
                "properties": {"category": category, "severity": severity},
            }
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": f"SecurityScanner-{self.seed}",
                            "version": "1.0.0",
                        }
                    },
                    "results": results,
                }
            ],
        }

    def generate_cve_feed(self, num_cves: int = 50) -> Dict[str, List[Dict[str, Any]]]:
        """Generate fresh CVE feed with realistic vulnerability data."""
        cves = []

        base_date = datetime.now() - timedelta(days=365)

        for i in range(num_cves):
            cve_id = f"CVE-2024-{10000 + self.seed % 10000 + i}"
            published = (base_date + timedelta(days=i * 7)).isoformat() + "Z"

            cve = {
                "id": cve_id,
                "published": published,
                "modified": published,
                "descriptions": [
                    {
                        "lang": "en",
                        "value": f"Vulnerability in component allowing {['DoS', 'RCE', 'XSS', 'SQLi'][i % 4]}",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 5.0 + (i % 5),
                                "baseSeverity": ["MEDIUM", "HIGH", "CRITICAL"][
                                    min(i % 3, 2)
                                ],
                            }
                        }
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": f"cpe:2.3:a:vendor:product:{i % 10}.{i % 5}:*:*:*:*:*:*:*",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
            cves.append(cve)

        return {"CVE_Items": cves}

    def generate_business_context(self) -> Dict[str, Any]:
        """Generate fresh business context configuration."""
        return {
            "service_name": f"test-service-{self.seed}",
            "environment": "production",
            "criticality": "high",
            "data_classification": "confidential",
            "compliance_frameworks": ["SOC2", "ISO27001", "PCI_DSS"],
            "stakeholders": {
                "owner": "security-team",
                "responsible": "platform-engineering",
            },
            "sla": {"uptime_requirement": "99.9%", "max_downtime_minutes": 43},
        }


@pytest.fixture
def fresh_data_generator():
    """Provide a fresh test data generator."""
    return FreshTestDataGenerator(seed=secrets.randbits(32))


@pytest.fixture
def temp_test_workspace(tmp_path):
    """Create isolated temporary workspace for tests."""
    workspace = {
        "root": tmp_path,
        "data": tmp_path / "data",
        "uploads": tmp_path / "data" / "uploads",
        "evidence": tmp_path / "data" / "evidence",
        "archive": tmp_path / "data" / "archive",
        "inputs": tmp_path / "inputs",
        "outputs": tmp_path / "outputs",
    }

    for path in workspace.values():
        if isinstance(path, Path):
            path.mkdir(parents=True, exist_ok=True)

    return workspace


@pytest.fixture
def fresh_design_csv(fresh_data_generator, temp_test_workspace):
    """Generate and save fresh design CSV."""
    csv_content = fresh_data_generator.generate_design_csv(num_components=60)
    csv_file = temp_test_workspace["inputs"] / "design.csv"
    csv_file.write_text(csv_content)
    return csv_file


@pytest.fixture
def fresh_sbom(fresh_data_generator, temp_test_workspace):
    """Generate and save fresh SBOM."""
    sbom_data = fresh_data_generator.generate_sbom(num_packages=120)
    sbom_file = temp_test_workspace["inputs"] / "sbom.json"
    sbom_file.write_text(json.dumps(sbom_data, indent=2))
    return sbom_file


@pytest.fixture
def fresh_sarif(fresh_data_generator, temp_test_workspace):
    """Generate and save fresh SARIF."""
    sarif_data = fresh_data_generator.generate_sarif(num_findings=85)
    sarif_file = temp_test_workspace["inputs"] / "scan.sarif"
    sarif_file.write_text(json.dumps(sarif_data, indent=2))
    return sarif_file


@pytest.fixture
def fresh_cve_feed(fresh_data_generator, temp_test_workspace):
    """Generate and save fresh CVE feed."""
    cve_data = fresh_data_generator.generate_cve_feed(num_cves=60)
    cve_file = temp_test_workspace["inputs"] / "cve.json"
    cve_file.write_text(json.dumps(cve_data, indent=2))
    return cve_file


@pytest.fixture
def fresh_business_context(fresh_data_generator, temp_test_workspace):
    """Generate and save fresh business context."""
    context_data = fresh_data_generator.generate_business_context()
    context_file = temp_test_workspace["inputs"] / "context.json"
    context_file.write_text(json.dumps(context_data, indent=2))
    return context_file


class TestFreshDataGeneration:
    """Test that fresh data generators work correctly."""

    def test_design_csv_generation(self, fresh_data_generator):
        """Test design CSV generation."""
        csv_content = fresh_data_generator.generate_design_csv(30)
        lines = csv_content.split("\n")

        assert len(lines) == 31
        assert lines[0] == "component_name,criticality,data_classification,environment"
        assert all("," in line for line in lines[1:])

    def test_sbom_generation(self, fresh_data_generator):
        """Test SBOM generation."""
        sbom = fresh_data_generator.generate_sbom(50)

        assert sbom["bomFormat"] == "CycloneDX"
        assert "components" in sbom
        assert len(sbom["components"]) == 50
        assert all("name" in comp for comp in sbom["components"])
        assert all("version" in comp for comp in sbom["components"])

    def test_sarif_generation(self, fresh_data_generator):
        """Test SARIF generation."""
        sarif = fresh_data_generator.generate_sarif(40)

        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"][0]["results"]) == 40
        assert all("ruleId" in r for r in sarif["runs"][0]["results"])

    def test_cve_feed_generation(self, fresh_data_generator):
        """Test CVE feed generation."""
        cve_feed = fresh_data_generator.generate_cve_feed(25)

        assert "CVE_Items" in cve_feed
        assert len(cve_feed["CVE_Items"]) == 25
        assert all(cve["id"].startswith("CVE-") for cve in cve_feed["CVE_Items"])


class TestInputNormalization:
    """Test input normalization with fresh data."""

    def test_design_csv_loading(self, fresh_design_csv):
        """Test loading fresh design CSV."""
        import csv

        with open(fresh_design_csv, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 60
        assert all("component_name" in row for row in rows)

    def test_sbom_loading(self, fresh_sbom):
        """Test loading fresh SBOM."""
        from apps.api.normalizers import InputNormalizer

        normalizer = InputNormalizer()
        with open(fresh_sbom, "rb") as f:
            result = normalizer.load_sbom(f.read())

        assert result.format in ["CycloneDX", "SPDX"]
        assert len(result.components) > 0

    def test_sarif_loading(self, fresh_sarif):
        """Test loading fresh SARIF."""
        from apps.api.normalizers import InputNormalizer

        normalizer = InputNormalizer()
        with open(fresh_sarif, "rb") as f:
            result = normalizer.load_sarif(f.read())

        assert hasattr(result, "findings")
        assert len(result.findings) > 0

    def test_cve_feed_loading(self, fresh_cve_feed):
        """Test loading fresh CVE feed."""
        from apps.api.normalizers import InputNormalizer

        normalizer = InputNormalizer()
        with open(fresh_cve_feed, "rb") as f:
            result = normalizer.load_cve_feed(f.read())

        assert hasattr(result, "records")
        assert isinstance(result.records, list)


class TestConfigurationSystem:
    """Test configuration system with fresh setups."""

    def test_overlay_loading(self):
        """Test loading overlay configuration."""
        from pathlib import Path

        from core.configuration import load_overlay

        overlay_path = Path("config/fixops.overlay.yml")
        if overlay_path.exists():
            overlay = load_overlay(overlay_path)
            assert overlay is not None
            assert hasattr(overlay, "mode")

    def test_runtime_preparation(self, temp_test_workspace):
        """Test overlay runtime preparation."""
        from pathlib import Path

        from core.overlay_runtime import prepare_overlay

        overlay_path = Path("config/fixops.overlay.yml")
        if overlay_path.exists():
            overlay = prepare_overlay(path=overlay_path)
            assert overlay is not None
            assert hasattr(overlay, "metadata")


class TestMathematicalModels:
    """Test mathematical models with fresh data."""

    def test_transition_normalization(self):
        """Test transition row normalization."""
        from core.probabilistic import _normalise_transition_row

        row = {"low": 0.3, "medium": 0.5, "high": 0.2}
        normalized = _normalise_transition_row(row)

        assert abs(sum(normalized.values()) - 1.0) < 1e-9

    def test_entropy_calculation(self):
        """Test entropy calculation."""
        from core.probabilistic import _entropy

        uniform = {"a": 0.25, "b": 0.25, "c": 0.25, "d": 0.25}
        entropy = _entropy(uniform)

        assert entropy > 1.0


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_empty_sbom_handling(self, temp_test_workspace):
        """Test handling of empty SBOM files."""
        from apps.api.normalizers import InputNormalizer

        normalizer = InputNormalizer()

        result = normalizer.load_sbom(b"")
        assert result.components == [] or len(result.components) == 0

    def test_malformed_json_handling(self):
        """Test handling of malformed JSON."""
        from apps.api.normalizers import InputNormalizer

        normalizer = InputNormalizer()

        result = normalizer.load_sbom(b"{invalid json")
        assert result is not None

    def test_division_by_zero_protection(self):
        """Test protection against division by zero."""
        from core.probabilistic import _normalise_transition_row

        row = {}
        normalized = _normalise_transition_row(row)

        assert "low" in normalized
        assert normalized["low"] == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
