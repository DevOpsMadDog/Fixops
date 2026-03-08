"""Tests for BusinessContextProcessor — SSVC, OTM, and YAML parsing."""
import pytest
import json

from core.services.enterprise.business_context_processor import (
    SSVCBusinessContext,
    OTMContext,
    FixOpsContextProcessor,
)


class TestSSVCBusinessContext:
    def test_create(self):
        ctx = SSVCBusinessContext(
            service_name="api-gw",
            environment="production",
            exploitation="none",
            exposure="controlled",
            utility="laborious",
            safety_impact="negligible",
            mission_impact="degraded",
            business_criticality="high",
            data_classification=["internal", "pii"],
            internet_facing=True,
            compliance_requirements=["pci_dss"],
            owner_team="platform",
            owner_email="team@example.com",
            escalation_contacts=["oncall@example.com"],
            sla_requirements={"p1": 4},
        )
        assert ctx.service_name == "api-gw"
        assert ctx.internet_facing is True
        assert "pii" in ctx.data_classification

    def test_optional_fields(self):
        ctx = SSVCBusinessContext(
            service_name="svc",
            environment="dev",
            exploitation="none",
            exposure="small",
            utility="laborious",
            safety_impact="negligible",
            mission_impact="degraded",
            business_criticality="low",
            data_classification=[],
            internet_facing=False,
            compliance_requirements=[],
            owner_team="t",
            owner_email="e@e.com",
            escalation_contacts=[],
            sla_requirements={},
        )
        assert ctx.threat_model_url is None
        assert ctx.attack_surface is None
        assert ctx.trust_boundaries is None


class TestOTMContext:
    def test_create(self):
        otm = OTMContext(
            otm_version="0.1.0",
            project={"name": "test"},
            representations=[],
            trust_zones=[],
            components=[],
            data_flows=[],
            threats=[],
            mitigations=[],
        )
        assert otm.otm_version == "0.1.0"
        assert otm.project["name"] == "test"


class TestFixOpsContextProcessor:
    @pytest.fixture
    def processor(self):
        return FixOpsContextProcessor()

    def test_supported_formats(self, processor):
        assert "core.yaml" in processor.supported_formats
        assert "otm.json" in processor.supported_formats
        assert "ssvc.yaml" in processor.supported_formats

    def test_process_fixops_yaml(self, processor):
        yaml_content = """
service_name: payment-api
environment: production
exploitation: none
exposure: open
utility: efficient
safety_impact: marginal
mission_impact: crippled
business_criticality: critical
data_classification:
  - pci
  - pii
internet_facing: true
compliance_requirements:
  - pci_dss
  - sox
owner_team: payments
owner_email: payments@example.com
escalation_contacts:
  - oncall@example.com
sla_requirements:
  p1: 4
"""
        ctx = processor.process_fixops_yaml(yaml_content)
        assert isinstance(ctx, SSVCBusinessContext)
        assert ctx.service_name == "payment-api"
        assert ctx.exploitation == "none"
        assert ctx.exposure == "open"
        assert ctx.internet_facing is True
        assert "pci" in ctx.data_classification

    def test_process_fixops_yaml_missing_field(self, processor):
        yaml_content = """
service_name: svc
# missing exploitation, exposure, etc.
"""
        with pytest.raises(Exception):
            processor.process_fixops_yaml(yaml_content)

    def test_process_fixops_yaml_defaults(self, processor):
        yaml_content = """
exploitation: active
exposure: open
utility: super_effective
safety_impact: hazardous
mission_impact: mev
"""
        ctx = processor.process_fixops_yaml(yaml_content)
        assert ctx.service_name == "unknown"
        assert ctx.environment == "production"
        assert ctx.business_criticality == "medium"

    def test_process_otm_json(self, processor):
        otm = {
            "otmVersion": "0.2.0",
            "project": {"name": "my-app", "owner": "dev-team"},
            "representations": [],
            "trustZones": [{"name": "internet-zone"}],
            "components": [{"name": "web-server"}],
            "dataFlows": [],
            "threats": [{"severity": "HIGH", "description": "XSS vuln"}],
            "mitigations": [{"name": "input validation"}],
        }
        ctx = processor.process_otm_json(json.dumps(otm))
        assert isinstance(ctx, SSVCBusinessContext)
        assert ctx.service_name == "my-app"

    def test_process_otm_json_empty(self, processor):
        ctx = processor.process_otm_json("{}")
        assert isinstance(ctx, SSVCBusinessContext)

    def test_analyze_exploitation_active(self, processor):
        threats = [{"status": "active", "description": "live exploit"}]
        assert processor._analyze_exploitation(threats) == "active"

    def test_analyze_exploitation_poc(self, processor):
        threats = [{"status": "reported", "description": "PoC available"}]
        assert processor._analyze_exploitation(threats) == "poc"

    def test_analyze_exploitation_none(self, processor):
        assert processor._analyze_exploitation([]) == "none"
        assert processor._analyze_exploitation([{"status": "mitigated"}]) == "none"

    def test_analyze_exposure_open(self, processor):
        zones = [{"name": "internet-dmz"}]
        assert processor._analyze_exposure([], zones) == "open"

    def test_analyze_exposure_controlled(self, processor):
        zones = [{"name": "external-api"}]
        assert processor._analyze_exposure([], zones) == "controlled"

    def test_analyze_exposure_small(self, processor):
        zones = [{"name": "internal-network"}]
        assert processor._analyze_exposure([], zones) == "small"

    def test_analyze_utility_no_threats(self, processor):
        assert processor._analyze_utility([], []) == "laborious"

    def test_analyze_utility_with_mitigations(self, processor):
        threats = [{"description": "manual exploit"}]
        mitigations = [{"name": "waf"}]
        assert processor._analyze_utility(threats, mitigations) == "efficient"

    def test_analyze_safety_impact_critical_project(self, processor):
        project = {"type": "medical-device"}
        assert processor._analyze_safety_impact([], project) == "hazardous"
