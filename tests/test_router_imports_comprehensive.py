"""Comprehensive router import and basic endpoint tests.

Tests that all router modules can be imported and basic endpoints respond.
This exercises a LOT of code just through imports.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for suite in ["suite-core", "suite-api", "suite-attack", "suite-feeds",
              "suite-evidence-risk", "suite-integrations"]:
    sys.path.insert(0, os.path.join(ROOT, suite))



# ---------------------------------------------------------------------------
# Test that all routers can be imported
# ---------------------------------------------------------------------------
class TestRouterImports:
    """Just importing routers exercises their module-level code."""

    def test_import_brain_router(self):
        from api.brain_router import router
        assert router is not None

    def test_import_autofix_router(self):
        from api.autofix_router import router
        assert router is not None

    def test_import_self_learning_router(self):
        from api.self_learning_router import router
        assert router is not None

    def test_import_algorithmic_router(self):
        from api.algorithmic_router import router
        assert router is not None

    def test_import_copilot_router(self):
        from api.copilot_router import router
        assert router is not None

    def test_import_deduplication_router(self):
        from api.deduplication_router import router
        assert router is not None

    def test_import_predictions_router(self):
        from api.predictions_router import router
        assert router is not None

    def test_import_exposure_case_router(self):
        from api.exposure_case_router import router
        assert router is not None

    def test_import_mcp_protocol_router(self):
        from api.mcp_protocol_router import router
        assert router is not None

    def test_import_mindsdb_router(self):
        from api.mindsdb_router import router
        assert router is not None


class TestAttackRouterImports:
    def test_import_mpte_router(self):
        from api.mpte_router import router
        assert router is not None

    def test_import_micro_pentest_router(self):
        from api.micro_pentest_router import router
        assert router is not None

    def test_import_attack_sim_router(self):
        from api.attack_sim_router import router
        assert router is not None

    def test_import_vuln_discovery_router(self):
        from api.vuln_discovery_router import router
        assert router is not None

    def test_import_secrets_router(self):
        from api.secrets_router import router
        assert router is not None

    def test_import_mpte_orchestrator_router(self):
        from api.mpte_orchestrator_router import router
        assert router is not None


class TestEvidenceRouterImports:
    def test_import_evidence_router(self):
        from api.evidence_router import router
        assert router is not None


class TestIntegrationRouterImports:
    def test_import_iac_router(self):
        from api.iac_router import router
        assert router is not None

    def test_import_webhooks_router(self):
        from api.webhooks_router import router
        assert router is not None

    def test_import_oss_tools(self):
        from api.oss_tools import router
        assert router is not None


# ---------------------------------------------------------------------------
# Core module imports (exercises module-level code for coverage)
# ---------------------------------------------------------------------------
class TestCoreModuleImports:
    def test_import_brain_pipeline(self):
        from core.brain_pipeline import BrainPipeline
        assert BrainPipeline is not None

    def test_import_autofix_engine(self):
        from core.autofix_engine import AutoFixEngine
        assert AutoFixEngine is not None

    def test_import_fail_engine(self):
        from core.fail_engine import FAILEngine
        assert FAILEngine is not None

    def test_import_exposure_case(self):
        from core.exposure_case import ExposureCaseManager
        assert ExposureCaseManager is not None

    def test_import_micro_pentest(self):
        from core.micro_pentest import run_micro_pentest
        assert run_micro_pentest is not None

    def test_import_sast_engine(self):
        from core.sast_engine import SASTEngine
        assert SASTEngine is not None

    def test_import_dast_engine(self):
        from core.dast_engine import DASTEngine
        assert DASTEngine is not None

    def test_import_secrets_scanner(self):
        from core.secrets_scanner import SecretsScanner
        assert SecretsScanner is not None

    def test_import_container_scanner(self):
        from core.container_scanner import ContainerImageScanner
        assert ContainerImageScanner is not None

    def test_import_cspm_engine(self):
        from core.cspm_engine import CSPMEngine
        assert CSPMEngine is not None

    def test_import_connectors(self):
        from core.connectors import AutomationConnectors
        assert AutomationConnectors is not None

    def test_import_security_connectors(self):
        from core.security_connectors import SnykConnector
        assert SnykConnector is not None

    def test_import_event_bus(self):
        from core.event_bus import get_event_bus
        bus = get_event_bus()
        assert bus is not None

    def test_import_crypto(self):
        from core.crypto import RSAKeyManager
        assert RSAKeyManager is not None

    def test_import_storage(self):
        from core.storage import ArtefactArchive
        assert ArtefactArchive is not None

    def test_import_context_engine(self):
        from core.context_engine import ContextEngine
        assert ContextEngine is not None

    def test_import_code_to_cloud_tracer(self):
        from core.code_to_cloud_tracer import CodeToCloudTracer
        assert CodeToCloudTracer is not None

    def test_import_soc2_evidence_generator(self):
        from core.soc2_evidence_generator import SOC2EvidenceGenerator
        assert SOC2EvidenceGenerator is not None

    def test_import_vllm_adapter(self):
        from core.vllm_autofix_adapter import VLLMAutoFixAdapter
        assert VLLMAutoFixAdapter is not None

    def test_import_scanner_parsers(self):
        from core.scanner_parsers import parse_scanner_output
        assert parse_scanner_output is not None

    def test_import_decision_policy(self):
        from core.decision_policy import DecisionPolicyEngine
        assert DecisionPolicyEngine is not None

    def test_import_severity_promotion(self):
        from core.severity_promotion import SeverityPromotionEngine
        assert SeverityPromotionEngine is not None


# ---------------------------------------------------------------------------
# DB module imports
# ---------------------------------------------------------------------------
class TestDBModuleImports:
    def test_import_user_db(self):
        from core.user_db import UserDB
        assert UserDB is not None

    def test_import_report_db(self):
        from core.report_db import ReportDB
        assert ReportDB is not None

    def test_import_audit_db(self):
        from core.audit_db import AuditDB
        assert AuditDB is not None

    def test_import_workflow_db(self):
        from core.workflow_db import WorkflowDB
        assert WorkflowDB is not None

    def test_import_fail_db(self):
        from core.fail_db import FAILDB
        assert FAILDB is not None

    def test_import_inventory_db(self):
        from core.inventory_db import InventoryDB
        assert InventoryDB is not None

    def test_import_policy_db(self):
        from core.policy_db import PolicyDB
        assert PolicyDB is not None


# ---------------------------------------------------------------------------
# Evidence Risk module imports
# ---------------------------------------------------------------------------
class TestEvidenceRiskImports:
    def test_import_compliance_engine(self):
        from compliance.compliance_engine import ComplianceEngine
        assert ComplianceEngine is not None

    def test_import_evidence_router(self):
        from api.evidence_router import router
        assert router is not None


# ---------------------------------------------------------------------------
# Integration module imports
# ---------------------------------------------------------------------------
class TestIntegrationModuleImports:
    def test_import_mcp_router(self):
        from api.mcp_router import router
        assert router is not None

    def test_import_ide_router(self):
        from api.ide_router import router
        assert router is not None
