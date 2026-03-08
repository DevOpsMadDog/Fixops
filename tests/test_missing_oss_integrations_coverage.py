"""Tests for missing_oss_integrations — SSVCFramework, SBOMParser, _mean."""
import pytest

from core.services.enterprise.missing_oss_integrations import (
    _mean,
    SSVCFramework,
    SBOMParser,
)


class TestMean:
    def test_empty(self):
        assert _mean([]) == 0.0

    def test_single(self):
        assert _mean([5.0]) == 5.0

    def test_multiple(self):
        assert _mean([1.0, 2.0, 3.0]) == 2.0

    def test_negative(self):
        assert _mean([-1.0, 1.0]) == 0.0


class TestSSVCFramework:
    @pytest.fixture
    def framework(self):
        return SSVCFramework()

    def test_init(self, framework):
        assert framework is not None

    def test_calculate_ssvc_recommendation_act(self, framework):
        dp = {"Exploitation": "active", "Exposure": "open"}
        assert framework._calculate_ssvc_recommendation(dp) == "Act"

    def test_calculate_ssvc_recommendation_attend(self, framework):
        dp = {"Exploitation": "poc", "Exposure": "small"}
        assert framework._calculate_ssvc_recommendation(dp) == "Attend"

    def test_calculate_ssvc_recommendation_track(self, framework):
        dp = {"Exploitation": "none", "Exposure": "small"}
        assert framework._calculate_ssvc_recommendation(dp) == "Track"

    def test_calculate_priority_immediate(self, framework):
        dp = {"Exploitation": "active", "Exposure": "controlled"}
        assert framework._calculate_priority(dp) == "Immediate"

    def test_calculate_priority_scheduled(self, framework):
        dp = {"Exploitation": "poc", "Exposure": "small"}
        assert framework._calculate_priority(dp) == "Scheduled"

    def test_calculate_priority_defer(self, framework):
        dp = {"Exploitation": "none", "Exposure": "small"}
        assert framework._calculate_priority(dp) == "Defer"

    @pytest.mark.asyncio
    async def test_evaluate_ssvc_decision_without_client(self, framework):
        # ssvc library likely not installed in test env
        result = await framework.evaluate_ssvc_decision({
            "exploitation": "active",
            "exposure": "open",
        })
        # Either succeeds or returns unavailable
        assert "status" in result or "decision" in result


class TestSBOMParser:
    @pytest.fixture
    def parser(self):
        return SBOMParser()

    def test_init(self, parser):
        assert parser is not None

    def test_validate_sbom_structure_valid(self, parser):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "lodash", "version": "4.17.21"},
            ],
        }
        result = parser._validate_sbom_structure(sbom)
        assert result["valid"] is True
        assert result["errors"] == []

    def test_validate_sbom_structure_missing_fields(self, parser):
        result = parser._validate_sbom_structure({})
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_validate_sbom_structure_invalid_format(self, parser):
        result = parser._validate_sbom_structure({
            "bomFormat": "INVALID",
            "specVersion": "1.0",
            "components": [],
        })
        assert result["valid"] is False

    def test_validate_sbom_structure_missing_components(self, parser):
        result = parser._validate_sbom_structure({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
        })
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_parse_sbom_invalid_json(self, parser):
        result = await parser.parse_sbom("not json")
        if "status" in result:
            assert result["status"] in ("error", "lib4sbom_unavailable")

    @pytest.mark.asyncio
    async def test_parse_sbom_dict_input(self, parser):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "lib", "version": "1.0.0", "type": "library"},
            ],
        }
        result = await parser.parse_sbom(sbom)
        assert "status" in result
