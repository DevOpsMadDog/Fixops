"""Tests for PentAGI integration."""

import asyncio
import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from core.continuous_validation import (
    ContinuousValidationEngine,
    ValidationJob,
    ValidationStatus,
    ValidationTrigger,
)
from core.exploit_generator import (
    ExploitType,
    IntelligentExploitGenerator,
    PayloadComplexity,
)
from core.llm_providers import LLMProviderManager
from core.pentagi_advanced import (
    AdvancedPentagiClient,
    MultiAIOrchestrator,
    AIRole,
    AIDecision,
)
from core.pentagi_models import (
    ExploitabilityLevel,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestStatus,
)
from core.automated_remediation import (
    AutomatedRemediationEngine,
    RemediationPriority,
    RemediationStatus,
    RemediationType,
)


@pytest.fixture
def pentagi_config():
    """Create a test PentAGI configuration."""
    return PenTestConfig(
        id="test-config",
        name="Test PentAGI",
        pentagi_url="http://localhost:8443",
        api_key="test-key",
        enabled=True,
        max_concurrent_tests=5,
        timeout_seconds=300,
    )


@pytest.fixture
def llm_manager():
    """Create a mock LLM provider manager."""
    manager = MagicMock(spec=LLMProviderManager)
    return manager


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability for testing."""
    return {
        "id": "VULN-001",
        "type": "SQL Injection",
        "severity": "high",
        "cwe_id": "CWE-89",
        "description": "SQL injection in user search functionality",
        "file": "app/users.py",
        "line": 42,
    }


@pytest.fixture
def sample_context():
    """Create a sample context for testing."""
    return {
        "target_url": "https://test.example.com",
        "application": "Test Application",
        "framework": "Django 4.2",
        "database": "PostgreSQL",
        "environment": "staging",
    }


class TestMultiAIOrchestrator:
    """Test Multi-AI orchestration."""

    @pytest.mark.asyncio
    async def test_get_architect_decision(
        self, llm_manager, sample_vulnerability, sample_context
    ):
        """Test architect decision generation."""
        orchestrator = MultiAIOrchestrator(llm_manager)

        decision = await orchestrator.get_architect_decision(
            sample_context, sample_vulnerability
        )

        assert decision.role == AIRole.ARCHITECT
        assert decision.confidence > 0
        assert decision.recommendation
        assert "attack_vectors" in decision.metadata

    @pytest.mark.asyncio
    async def test_get_developer_decision(
        self, llm_manager, sample_vulnerability, sample_context
    ):
        """Test developer decision generation."""
        orchestrator = MultiAIOrchestrator(llm_manager)

        decision = await orchestrator.get_developer_decision(
            sample_context, sample_vulnerability
        )

        assert decision.role == AIRole.DEVELOPER
        assert decision.confidence > 0
        assert decision.recommendation
        assert "tools" in decision.metadata

    @pytest.mark.asyncio
    async def test_get_lead_decision(
        self, llm_manager, sample_vulnerability, sample_context
    ):
        """Test lead decision generation."""
        orchestrator = MultiAIOrchestrator(llm_manager)

        decision = await orchestrator.get_lead_decision(
            sample_context, sample_vulnerability
        )

        assert decision.role == AIRole.LEAD
        assert decision.confidence > 0
        assert decision.recommendation
        assert "strategy" in decision.metadata

    @pytest.mark.asyncio
    async def test_compose_consensus(self, llm_manager, sample_context):
        """Test consensus composition."""
        orchestrator = MultiAIOrchestrator(llm_manager)

        architect = AIDecision(
            role=AIRole.ARCHITECT,
            recommendation="High priority test",
            confidence=0.85,
            reasoning="Critical vulnerability",
            priority=8,
        )

        developer = AIDecision(
            role=AIRole.DEVELOPER,
            recommendation="Use SQLMap",
            confidence=0.90,
            reasoning="Standard SQL injection",
            priority=9,
        )

        lead = AIDecision(
            role=AIRole.LEAD,
            recommendation="Follow OWASP guidelines",
            confidence=0.80,
            reasoning="Best practice approach",
            priority=8,
        )

        consensus = await orchestrator.compose_consensus(
            architect, developer, lead, sample_context
        )

        assert consensus.action
        assert 0 <= consensus.confidence <= 1
        assert len(consensus.contributing_decisions) == 3
        assert len(consensus.execution_plan) > 0


class TestAdvancedPentagiClient:
    """Test Advanced PentAGI client."""

    @pytest.mark.asyncio
    async def test_execute_pentest(
        self, pentagi_config, llm_manager, sample_context
    ):
        """Test basic pentest execution."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)

            request = PenTestRequest(
                id="test-request",
                finding_id="VULN-001",
                target_url="https://test.example.com",
                vulnerability_type="SQL Injection",
                test_case="Test SQL injection",
                priority=PenTestPriority.HIGH,
            )

            # Mock the API call
            client._call_pentagi_api = AsyncMock(
                return_value={
                    "job_id": "test-job",
                    "status": "completed",
                    "exploit_successful": True,
                }
            )

            result = await client.execute_pentest(request)

            assert result["job_id"] == "test-job"
            assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_execute_pentest_with_consensus(
        self, pentagi_config, llm_manager, sample_vulnerability, sample_context
    ):
        """Test consensus-based pentest execution."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)

            result = await client.execute_pentest_with_consensus(
                sample_vulnerability, sample_context
            )

            assert "status" in result
            assert "consensus" in result
            assert result["status"] in ["completed", "manual_review_required"]


class TestExploitGenerator:
    """Test intelligent exploit generator."""

    @pytest.mark.asyncio
    async def test_generate_exploit(
        self, llm_manager, sample_vulnerability, sample_context
    ):
        """Test exploit generation."""
        generator = IntelligentExploitGenerator(llm_manager)

        exploit = await generator.generate_exploit(
            sample_vulnerability, sample_context, PayloadComplexity.MODERATE
        )

        assert exploit.exploit_type == ExploitType.SQL_INJECTION
        assert exploit.payload
        assert exploit.complexity == PayloadComplexity.MODERATE
        assert 0 <= exploit.success_probability <= 1
        assert len(exploit.prerequisites) >= 0

    @pytest.mark.asyncio
    async def test_generate_exploit_chain(
        self, llm_manager, sample_vulnerability, sample_context
    ):
        """Test exploit chain generation."""
        generator = IntelligentExploitGenerator(llm_manager)

        vulnerabilities = [
            sample_vulnerability,
            {**sample_vulnerability, "id": "VULN-002", "type": "XSS"},
            {**sample_vulnerability, "id": "VULN-003", "type": "Authentication Bypass"},
        ]

        chain = await generator.generate_exploit_chain(vulnerabilities, sample_context)

        assert chain.name
        assert len(chain.stages) > 0
        assert 0 <= chain.overall_success_probability <= 1
        assert len(chain.kill_chain_phases) > 0

    @pytest.mark.asyncio
    async def test_optimize_payload(
        self, llm_manager, sample_vulnerability, sample_context
    ):
        """Test payload optimization."""
        generator = IntelligentExploitGenerator(llm_manager)

        # Generate base exploit
        exploit = await generator.generate_exploit(
            sample_vulnerability, sample_context, PayloadComplexity.SIMPLE
        )

        # Optimize for WAF bypass
        constraints = {"waf": "ModSecurity", "encoding": "UTF-8"}

        optimized = await generator.optimize_payload(exploit, constraints)

        assert optimized.payload
        assert "optimized_from" in optimized.metadata


class TestContinuousValidation:
    """Test continuous validation engine."""

    @pytest.mark.asyncio
    async def test_trigger_validation(
        self, pentagi_config, llm_manager, sample_vulnerability
    ):
        """Test validation triggering."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)
            orchestrator = MultiAIOrchestrator(llm_manager)
            engine = ContinuousValidationEngine(client, orchestrator)

            job = await engine.trigger_validation(
                ValidationTrigger.CODE_COMMIT,
                "https://test.example.com",
                [sample_vulnerability],
            )

            assert job.id
            assert job.trigger == ValidationTrigger.CODE_COMMIT
            assert job.status == ValidationStatus.SCHEDULED
            assert len(job.vulnerabilities) == 1

    @pytest.mark.asyncio
    async def test_security_posture_assessment(self, pentagi_config, llm_manager):
        """Test security posture assessment."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)
            orchestrator = MultiAIOrchestrator(llm_manager)
            engine = ContinuousValidationEngine(client, orchestrator)

            posture = await engine._assess_security_posture()

            assert posture.timestamp
            assert 0 <= posture.risk_score <= 100
            assert posture.trend in ["improving", "degrading", "stable"]
            assert isinstance(posture.critical_findings, list)
            assert isinstance(posture.recommendations, list)


class TestAutomatedRemediation:
    """Test automated remediation engine."""

    @pytest.mark.asyncio
    async def test_generate_remediation_suggestions(
        self, pentagi_config, llm_manager, sample_vulnerability, sample_context
    ):
        """Test remediation suggestion generation."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)
            engine = AutomatedRemediationEngine(llm_manager, client)

            suggestions = await engine.generate_remediation_suggestions(
                sample_vulnerability, sample_context
            )

            assert len(suggestions) > 0
            for suggestion in suggestions:
                assert suggestion.finding_id == sample_vulnerability["id"]
                assert suggestion.title
                assert suggestion.description
                assert suggestion.remediation_type in RemediationType
                assert suggestion.priority in RemediationPriority

    @pytest.mark.asyncio
    async def test_generate_remediation_plan(
        self, pentagi_config, llm_manager, sample_vulnerability, sample_context
    ):
        """Test remediation plan generation."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)
            engine = AutomatedRemediationEngine(llm_manager, client)

            findings = [
                sample_vulnerability,
                {**sample_vulnerability, "id": "VULN-002", "severity": "critical"},
                {**sample_vulnerability, "id": "VULN-003", "severity": "medium"},
            ]

            plan = await engine.generate_remediation_plan(findings, sample_context)

            assert plan["total_findings"] == 3
            assert plan["total_suggestions"] > 0
            assert "by_priority" in plan
            assert "timeline" in plan
            assert "estimated_total_effort" in plan

    @pytest.mark.asyncio
    async def test_verify_remediation(
        self, pentagi_config, llm_manager, sample_context
    ):
        """Test remediation verification."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)
            client.validate_remediation = AsyncMock(
                return_value=(True, "Vulnerability fixed")
            )

            engine = AutomatedRemediationEngine(llm_manager, client)

            # Generate a suggestion
            suggestions = await engine.generate_remediation_suggestions(
                {"id": "VULN-001", "type": "SQL Injection"}, sample_context
            )

            suggestion = suggestions[0]

            # Verify it
            verification = await engine.verify_remediation(suggestion, sample_context)

            assert verification.suggestion_id == suggestion.id
            assert isinstance(verification.verified, bool)
            assert verification.verification_evidence


class TestIntegrationWorkflow:
    """Test complete integration workflows."""

    @pytest.mark.asyncio
    async def test_complete_pentest_workflow(
        self, pentagi_config, llm_manager, sample_vulnerability, sample_context
    ):
        """Test complete pentesting workflow."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            # Initialize components
            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)
            generator = IntelligentExploitGenerator(llm_manager)

            # 1. Generate custom exploit
            exploit = await generator.generate_exploit(
                sample_vulnerability, sample_context, PayloadComplexity.ADVANCED
            )

            assert exploit.payload

            # 2. Execute pentest with consensus
            result = await client.execute_pentest_with_consensus(
                sample_vulnerability, sample_context
            )

            assert "consensus" in result

    @pytest.mark.asyncio
    async def test_complete_remediation_workflow(
        self, pentagi_config, llm_manager, sample_vulnerability, sample_context
    ):
        """Test complete remediation workflow."""
        with patch("core.pentagi_db.PentagiDB") as mock_db:
            mock_db_instance = MagicMock()
            mock_db.return_value = mock_db_instance

            # Initialize components
            client = AdvancedPentagiClient(pentagi_config, llm_manager, mock_db_instance)
            engine = AutomatedRemediationEngine(llm_manager, client)

            # 1. Generate remediation suggestions
            suggestions = await engine.generate_remediation_suggestions(
                sample_vulnerability, sample_context
            )

            assert len(suggestions) > 0
            suggestion = suggestions[0]

            # 2. Simulate applying the fix
            suggestion.status = RemediationStatus.APPLIED

            # 3. Verify the remediation
            client.validate_remediation = AsyncMock(
                return_value=(True, "Fix verified")
            )

            verification = await engine.verify_remediation(suggestion, sample_context)

            assert verification.verified
            assert not verification.still_exploitable


def test_data_models():
    """Test data model serialization."""
    request = PenTestRequest(
        id="test-1",
        finding_id="VULN-001",
        target_url="https://test.com",
        vulnerability_type="SQL Injection",
        test_case="Test case",
        priority=PenTestPriority.HIGH,
    )

    data = request.to_dict()
    assert data["id"] == "test-1"
    assert data["priority"] == "high"


def test_exploit_type_mapping():
    """Test exploit type identification."""
    generator = IntelligentExploitGenerator(MagicMock())

    # Test CWE mapping
    vuln1 = {"cwe_id": "CWE-89", "type": "unknown"}
    assert generator._identify_exploit_type(vuln1) == ExploitType.SQL_INJECTION

    vuln2 = {"cwe_id": "CWE-79", "type": "unknown"}
    assert generator._identify_exploit_type(vuln2) == ExploitType.XSS

    # Test keyword matching
    vuln3 = {"cwe_id": "", "type": "SQL injection vulnerability"}
    assert generator._identify_exploit_type(vuln3) == ExploitType.SQL_INJECTION


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
