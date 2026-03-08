"""Tests for LocalOPAEngine and ProductionOPAEngine — policy evaluation."""
import pytest

from core.services.enterprise.real_opa_engine import (
    LocalOPAEngine,
    ProductionOPAEngine,
)


class TestLocalOPAEngine:
    @pytest.fixture
    def engine(self):
        return LocalOPAEngine()

    def test_init_loads_policies(self, engine):
        assert "vulnerability" in engine.policies
        assert "sbom" in engine.policies

    def test_vulnerability_policy_has_rules(self, engine):
        rules = engine.policies["vulnerability"]["rules"]
        assert len(rules) >= 2
        names = [r["name"] for r in rules]
        assert "block_critical_vulns" in names
        assert "allow_patched_vulns" in names

    def test_sbom_policy_has_rules(self, engine):
        rules = engine.policies["sbom"]["rules"]
        assert len(rules) >= 2
        names = [r["name"] for r in rules]
        assert "require_sbom" in names
        assert "validate_components" in names

    @pytest.mark.asyncio
    async def test_health_check(self, engine):
        assert await engine.health_check() is True

    @pytest.mark.asyncio
    async def test_evaluate_vuln_no_vulns(self, engine):
        result = await engine.evaluate_policy("vulnerability", {"vulnerabilities": []})
        assert result["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_evaluate_vuln_critical_unfixed(self, engine):
        result = await engine.evaluate_policy("vulnerability", {
            "vulnerabilities": [
                {"severity": "CRITICAL", "cve_id": "CVE-2024-001", "fix_available": False}
            ]
        })
        assert result["decision"] == "block"
        assert result["unfixed_critical_count"] == 1

    @pytest.mark.asyncio
    async def test_evaluate_vuln_critical_fixed(self, engine):
        result = await engine.evaluate_policy("vulnerability", {
            "vulnerabilities": [
                {"severity": "CRITICAL", "cve_id": "CVE-2024-001", "fix_available": True}
            ]
        })
        assert result["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_evaluate_vuln_non_critical(self, engine):
        result = await engine.evaluate_policy("vulnerability", {
            "vulnerabilities": [
                {"severity": "HIGH", "cve_id": "CVE-2024-002"},
                {"severity": "MEDIUM", "cve_id": "CVE-2024-003"},
            ]
        })
        assert result["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_evaluate_sbom_missing(self, engine):
        result = await engine.evaluate_policy("sbom", {"sbom_present": False})
        assert result["decision"] == "block"

    @pytest.mark.asyncio
    async def test_evaluate_sbom_invalid(self, engine):
        result = await engine.evaluate_policy("sbom", {
            "sbom_present": True,
            "sbom_valid": False,
        })
        assert result["decision"] == "block"

    @pytest.mark.asyncio
    async def test_evaluate_sbom_valid_no_components(self, engine):
        result = await engine.evaluate_policy("sbom", {
            "sbom_present": True,
            "sbom_valid": True,
            "sbom": {"components": []},
        })
        assert result["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_evaluate_sbom_valid_with_components(self, engine):
        result = await engine.evaluate_policy("sbom", {
            "sbom_present": True,
            "sbom_valid": True,
            "sbom": {
                "components": [
                    {"name": "lib-a", "version": "1.0.0"},
                    {"name": "lib-b", "version": "2.0.0"},
                ]
            },
        })
        assert result["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_evaluate_sbom_invalid_components(self, engine):
        result = await engine.evaluate_policy("sbom", {
            "sbom_present": True,
            "sbom_valid": True,
            "sbom": {
                "components": [
                    {"name": "lib-a"},  # missing version
                ]
            },
        })
        assert result["decision"] == "defer"

    @pytest.mark.asyncio
    async def test_evaluate_unknown_policy(self, engine):
        result = await engine.evaluate_policy("unknown_policy", {})
        assert result["decision"] == "allow"
        assert "Unknown policy" in result["rationale"]

    @pytest.mark.asyncio
    async def test_execution_time_in_result(self, engine):
        result = await engine.evaluate_policy("vulnerability", {"vulnerabilities": []})
        assert "execution_time_ms" in result
        assert result["execution_time_ms"] >= 0


class TestProductionOPAEngine:
    def test_init_defaults(self):
        engine = ProductionOPAEngine()
        assert engine.opa_url == "http://localhost:8181"
        assert engine.policy_package == "fixops"
        assert engine.health_path == "/health"
        assert engine.request_timeout == 5

    def test_init_custom(self):
        engine = ProductionOPAEngine(
            opa_url="http://opa:9191/",
            policy_package="custom.pkg",
            auth_token="token123",
            request_timeout=10,
        )
        assert engine.opa_url == "http://opa:9191"
        assert engine.policy_package == "custom/pkg"
        assert engine.auth_token == "token123"
        assert engine.request_timeout == 10

    def test_request_timeout_minimum(self):
        engine = ProductionOPAEngine(request_timeout=0)
        assert engine.request_timeout >= 1
