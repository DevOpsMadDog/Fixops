"""Tests for enterprise SBOM parser — CycloneDX extraction and parsing."""
import asyncio
import json

from core.services.enterprise.sbom_parser import (
    parse_sbom,
    _extract_findings_from_cyclonedx,
)


class TestExtractFindingsFromCycloneDX:
    def test_empty_sbom(self):
        result = _extract_findings_from_cyclonedx({})
        assert result == {"findings": []}

    def test_no_components(self):
        result = _extract_findings_from_cyclonedx({"components": []})
        assert result == {"findings": []}

    def test_components_no_vulns(self):
        sbom = {
            "components": [
                {"name": "lodash", "version": "4.17.21"},
                {"name": "express", "version": "4.18.2"},
            ]
        }
        result = _extract_findings_from_cyclonedx(sbom)
        assert result["findings"] == []

    def test_component_with_vulnerabilities(self):
        sbom = {
            "components": [
                {
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    "vulnerabilities": [
                        {
                            "id": "CVE-2021-44228",
                            "description": "Log4Shell RCE",
                            "ratings": [{"severity": "CRITICAL"}],
                        }
                    ],
                }
            ]
        }
        result = _extract_findings_from_cyclonedx(sbom)
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["rule_id"] == "CVE-2021-44228"
        assert f["severity"] == "critical"
        assert f["component_name"] == "log4j-core"
        assert f["component_version"] == "2.14.1"
        assert f["category"] == "dependency"
        assert f["scanner_type"] == "sca"

    def test_multiple_vulns_per_component(self):
        sbom = {
            "components": [
                {
                    "name": "spring-boot",
                    "version": "2.7.0",
                    "vulnerabilities": [
                        {"id": "CVE-2024-001", "ratings": [{"severity": "HIGH"}]},
                        {"id": "CVE-2024-002", "ratings": [{"severity": "MEDIUM"}]},
                    ],
                }
            ]
        }
        result = _extract_findings_from_cyclonedx(sbom)
        assert len(result["findings"]) == 2

    def test_missing_ratings(self):
        sbom = {
            "components": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "vulnerabilities": [{"id": "CVE-2024-003"}],
                }
            ]
        }
        result = _extract_findings_from_cyclonedx(sbom)
        f = result["findings"][0]
        assert f["severity"] == "low"  # default

    def test_missing_vuln_id(self):
        sbom = {
            "components": [
                {
                    "name": "pkg",
                    "version": "1.0",
                    "vulnerabilities": [{"description": "some issue"}],
                }
            ]
        }
        result = _extract_findings_from_cyclonedx(sbom)
        assert result["findings"][0]["rule_id"] == "unknown"


class TestParseSbom:
    def test_parse_valid_sbom(self):
        sbom = json.dumps({
            "components": [
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "vulnerabilities": [
                        {"id": "CVE-2024-999", "ratings": [{"severity": "HIGH"}]},
                    ],
                }
            ]
        })
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(parse_sbom(sbom))
        finally:
            loop.close()
        assert len(result["findings"]) == 1

    def test_parse_invalid_json(self):
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(parse_sbom("not json"))
        finally:
            loop.close()
        assert result == {"findings": []}

    def test_parse_empty_json(self):
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(parse_sbom("{}"))
        finally:
            loop.close()
        assert result == {"findings": []}
