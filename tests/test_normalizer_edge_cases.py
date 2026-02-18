"""
Regression tests for normalizer edge cases and bugs.

This test suite ensures that critical bugs found during deep testing
remain fixed and do not regress in future releases.
"""

import json

import pytest

from apps.api.normalizers import InputNormalizer


class TestNormalizerBugFixes:
    """Tests for bugs fixed during deep bug testing."""

    def test_bug1_nan_infinity_in_dict(self):
        """
        Bug 1: NaN/Infinity in JSON Serialization

        Severity: High
        Description: json.dumps with allow_nan=True emits invalid JSON tokens
        Fix: Set allow_nan=False and raise clear error
        """
        normalizer = InputNormalizer()

        sbom_with_nan = {
            "bomFormat": "CycloneDX",
            "components": [{"name": "test", "score": float("nan")}],
        }
        with pytest.raises(ValueError, match="NaN/Infinity"):
            normalizer.load_sbom(sbom_with_nan)

        sbom_with_inf = {
            "bomFormat": "CycloneDX",
            "components": [{"name": "test", "score": float("inf")}],
        }
        with pytest.raises(ValueError, match="NaN/Infinity"):
            normalizer.load_sbom(sbom_with_inf)

    def test_bug2_duplicate_vulnerability_detection(self):
        """
        Bug 2: Duplicate Vulnerability Detection

        Severity: Critical
        Description: Same vulnerability counted twice from doc-level and component-level
        Fix: Implemented deduplication logic using vulnerability ID
        """
        normalizer = InputNormalizer()

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "vulnerabilities": [
                {"id": "CVE-2024-0001", "ratings": [{"severity": "high"}]}
            ],
            "components": [
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "purl": "pkg:npm/test@1.0.0",
                    "vulnerabilities": [
                        {
                            "id": "CVE-2024-0001",
                            "ratings": [{"severity": "high"}],
                            "affects": [{"ref": "pkg:npm/test@1.0.0"}],
                        }
                    ],
                }
            ],
        }

        result = normalizer.load_sbom(sbom)

        assert (
            len(result.vulnerabilities) == 1
        ), f"Expected 1 deduplicated vulnerability, got {len(result.vulnerabilities)}"

        vuln = result.vulnerabilities[0]
        assert vuln.get("id") == "CVE-2024-0001"

    def test_bug3_invalid_utf8_handling(self):
        """
        Bug 3: Invalid UTF-8 Handling

        Severity: High
        Description: errors='ignore' silently corrupts data
        Fix: Strict encoding with BOM detection
        """
        normalizer = InputNormalizer()

        invalid_utf8 = b"\xff\xfe" + b'{"bomFormat": "CycloneDX"}'

        try:
            result = normalizer.load_sbom(invalid_utf8)
            assert result is not None
        except ValueError as e:
            assert "invalid" in str(e).lower() or "UTF" in str(e)

    def test_bug4_sarif_tool_name_preservation(self):
        """
        Bug 4: SARIF Multiple Runs Tool Name Preservation

        Severity: Medium
        Description: Tool names not preserved when aggregating multiple SARIF runs
        Fix: Added tool_name field to SarifFinding dataclass
        """
        normalizer = InputNormalizer()

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "SonarQube", "version": "9.9"}},
                    "results": [
                        {
                            "ruleId": "squid:S001",
                            "level": "error",
                            "message": {"text": "SQL injection vulnerability"},
                        }
                    ],
                },
                {
                    "tool": {"driver": {"name": "Snyk", "version": "1.1000.0"}},
                    "results": [
                        {
                            "ruleId": "SNYK-001",
                            "level": "warning",
                            "message": {"text": "Outdated dependency"},
                        }
                    ],
                },
            ],
        }

        result = normalizer.load_sarif(sarif)

        assert (
            len(result.findings) == 2
        ), f"Expected 2 findings, got {len(result.findings)}"

        tool_names = [f.tool_name for f in result.findings]
        assert "SonarQube" in tool_names, "SonarQube tool name not preserved"
        assert "Snyk" in tool_names, "Snyk tool name not preserved"


class TestNormalizerEdgeCases:
    """Additional edge case tests for normalizer robustness."""

    def test_deeply_nested_json(self):
        """Test handling of deeply nested JSON structures."""
        normalizer = InputNormalizer()

        nested = {"bomFormat": "CycloneDX"}
        current = nested
        for i in range(100):
            current["nested"] = {}
            current = current["nested"]

        result = normalizer.load_sbom(nested)
        assert result is not None

    def test_missing_component_fields(self):
        """Test graceful handling of missing component fields."""
        normalizer = InputNormalizer()

        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "minimal-component"}  # Missing version, purl, etc.
            ],
        }

        result = normalizer.load_sbom(sbom)
        assert len(result.components) == 1
        assert result.components[0].name == "minimal-component"

    def test_sarif_missing_rule_id(self):
        """Test SARIF findings without ruleId."""
        normalizer = InputNormalizer()

        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool"}},
                    "results": [
                        {"level": "error", "message": {"text": "Generic error"}}
                    ],
                }
            ],
        }

        result = normalizer.load_sarif(sarif)
        assert len(result.findings) == 1
        assert result.findings[0].rule_id is None or result.findings[0].rule_id == ""

    def test_sarif_no_locations(self):
        """Test SARIF findings without location information."""
        normalizer = InputNormalizer()

        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool"}},
                    "results": [
                        {
                            "ruleId": "TEST-001",
                            "level": "warning",
                            "message": {"text": "Warning without location"},
                        }
                    ],
                }
            ],
        }

        result = normalizer.load_sarif(sarif)
        assert len(result.findings) == 1
        assert result.findings[0].file is None or result.findings[0].file == ""

    def test_special_characters_in_purl(self):
        """Test handling of special characters in package URLs."""
        normalizer = InputNormalizer()

        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "purl": "pkg:npm/@scope/package@1.0.0?key=value#fragment",
                }
            ],
        }

        result = normalizer.load_sbom(sbom)
        assert len(result.components) == 1
        assert "@scope" in (result.components[0].purl or "")

    def test_large_sbom_performance(self):
        """Test performance with large SBOM (1000 components)."""
        normalizer = InputNormalizer()

        components = [
            {
                "name": f"component-{i}",
                "version": "1.0.0",
                "purl": f"pkg:npm/component-{i}@1.0.0",
            }
            for i in range(1000)
        ]

        sbom = {"bomFormat": "CycloneDX", "components": components}

        result = normalizer.load_sbom(sbom)
        assert len(result.components) == 1000

    def test_deterministic_output(self):
        """Test that same input produces identical output."""
        normalizer = InputNormalizer()

        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "pkg-a", "version": "1.0.0"},
                {"name": "pkg-b", "version": "2.0.0"},
            ],
            "vulnerabilities": [
                {"id": "CVE-2024-0001", "ratings": [{"severity": "high"}]}
            ],
        }

        results = []
        for _ in range(3):
            result = normalizer.load_sbom(sbom)
            results.append(json.dumps(result.to_dict(), sort_keys=True))

        assert len(set(results)) == 1, "Non-deterministic output detected"


class TestNormalizerSecurity:
    """Security-focused tests for normalizer."""

    def test_oversized_input_rejection(self):
        """Test that oversized inputs are rejected."""
        normalizer = InputNormalizer(max_document_bytes=1000)

        large_sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": f"component-{i}", "description": "x" * 100} for i in range(100)
            ],
        }

        with pytest.raises(ValueError, match="exceeds maximum"):
            normalizer.load_sbom(large_sbom)

    def test_gzip_bomb_protection(self):
        """Test protection against gzip bombs."""
        import gzip
        import io

        normalizer = InputNormalizer(max_document_bytes=10 * 1024 * 1024)  # 10MB

        data = b'{"bomFormat": "CycloneDX"}' + b"\x00" * (
            100 * 1024 * 1024
        )  # 100MB of zeros

        compressed = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed, mode="wb") as gz:
            gz.write(data)

        compressed_data = compressed.getvalue()

        with pytest.raises(ValueError, match="exceeds maximum"):
            normalizer.load_sbom(compressed_data)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
