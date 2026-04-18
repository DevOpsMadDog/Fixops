"""Tests for GraphRAG security-ops insight path in copilot_router.

Covers:
1. _classify_security_intent detects top_risks, compliance, threat_landscape,
   attack_surface intents; returns None for CWE developer questions.
2. _build_insight_answer returns Markdown with Key Findings section when enriched.
3. _build_insight_answer returns helpful fallback text when not enriched.
4. _generate_security_insight returns structured dict when bridge is available.
5. ask_security_question routes ops questions through GraphRAG and returns
   intent + recommended_actions in AskResponse.
"""
from __future__ import annotations

import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from apps.api.copilot_router import (
    _INTENT_ATTACK_SURFACE,
    _INTENT_COMPLIANCE,
    _INTENT_THREAT_LANDSCAPE,
    _INTENT_TOP_RISKS,
    _build_insight_answer,
    _classify_security_intent,
    _generate_security_insight,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _mock_bridge(entities: List[Dict[str, Any]], enriched: bool = True) -> MagicMock:
    """Return a mock CopilotGraphRAGBridge whose enrich_query returns controlled data."""
    bridge = MagicMock()
    context_summary = f"Found {len(entities)} entities." if enriched else ""
    bridge.enrich_query.return_value = {
        "query": "test",
        "graph_context": context_summary,
        "entities": entities,
        "relationships": [],
        "enriched": enriched,
    }
    return bridge


# ===========================================================================
# Test 1: _classify_security_intent intent detection
# ===========================================================================


class TestClassifySecurityIntent:
    """_classify_security_intent routes questions to the correct intent."""

    def test_top_risks_detected(self):
        assert _classify_security_intent("What are our top risks?") == _INTENT_TOP_RISKS

    def test_biggest_risk_detected(self):
        assert _classify_security_intent("What is our biggest risk right now?") == _INTENT_TOP_RISKS

    def test_compliance_soc2_detected(self):
        assert _classify_security_intent("Are we compliant with SOC2?") == _INTENT_COMPLIANCE

    def test_compliance_pci_detected(self):
        assert _classify_security_intent("What is our PCI-DSS compliance status?") == _INTENT_COMPLIANCE

    def test_compliance_gdpr_detected(self):
        assert _classify_security_intent("Are there any GDPR compliance gaps?") == _INTENT_COMPLIANCE

    def test_threat_landscape_who_attacking(self):
        assert _classify_security_intent("Who is attacking us?") == _INTENT_THREAT_LANDSCAPE

    def test_threat_landscape_apt(self):
        assert _classify_security_intent("Any APT groups targeting our sector?") == _INTENT_THREAT_LANDSCAPE

    def test_attack_surface_detected(self):
        assert _classify_security_intent("What assets are exposed?") == _INTENT_ATTACK_SURFACE

    def test_attack_surface_internet_facing(self):
        assert _classify_security_intent("Show me internet-facing services") == _INTENT_ATTACK_SURFACE

    def test_cwe_question_returns_none(self):
        """CWE developer questions should NOT be classified as a security-ops intent."""
        assert _classify_security_intent("What is SQL injection?") is None

    def test_xss_question_returns_none(self):
        assert _classify_security_intent("How do I prevent XSS in Python?") is None

    def test_empty_question_returns_none(self):
        assert _classify_security_intent("") is None

    def test_generic_question_returns_none(self):
        assert _classify_security_intent("Hello, how are you?") is None


# ===========================================================================
# Test 2: _build_insight_answer with enriched entities
# ===========================================================================


class TestBuildInsightAnswerEnriched:
    """_build_insight_answer produces correct Markdown when GraphRAG found entities."""

    _ENTITIES = [
        {"id": "cve_log4j", "type": "CVE", "name": "Log4Shell CVE-2021-44228", "score": 1.0},
        {"id": "svc_api", "type": "Service", "name": "Production API", "score": 0.85},
    ]
    _GRAPH_CONTEXT = "TrustGraph context: 2 critical findings linked to production services."

    def test_returns_string(self):
        result = _build_insight_answer(
            _INTENT_TOP_RISKS, "top risks?", self._GRAPH_CONTEXT, self._ENTITIES, True
        )
        assert isinstance(result, str)

    def test_contains_intent_heading(self):
        result = _build_insight_answer(
            _INTENT_TOP_RISKS, "top risks?", self._GRAPH_CONTEXT, self._ENTITIES, True
        )
        assert "Top Security Risks" in result

    def test_contains_key_findings_section(self):
        result = _build_insight_answer(
            _INTENT_TOP_RISKS, "top risks?", self._GRAPH_CONTEXT, self._ENTITIES, True
        )
        assert "Key Findings" in result

    def test_contains_entity_names(self):
        result = _build_insight_answer(
            _INTENT_TOP_RISKS, "top risks?", self._GRAPH_CONTEXT, self._ENTITIES, True
        )
        assert "Log4Shell CVE-2021-44228" in result
        assert "Production API" in result

    def test_contains_graph_context(self):
        result = _build_insight_answer(
            _INTENT_TOP_RISKS, "top risks?", self._GRAPH_CONTEXT, self._ENTITIES, True
        )
        assert self._GRAPH_CONTEXT in result

    def test_contains_recommended_actions(self):
        result = _build_insight_answer(
            _INTENT_TOP_RISKS, "top risks?", self._GRAPH_CONTEXT, self._ENTITIES, True
        )
        assert "Recommended Actions" in result

    def test_compliance_heading_for_compliance_intent(self):
        result = _build_insight_answer(
            _INTENT_COMPLIANCE, "SOC2?", "compliance context", self._ENTITIES, True
        )
        assert "Compliance Posture" in result

    def test_threat_heading_for_threat_intent(self):
        result = _build_insight_answer(
            _INTENT_THREAT_LANDSCAPE, "who attacks?", "threat context", self._ENTITIES, True
        )
        assert "Threat Landscape" in result

    def test_attack_surface_heading(self):
        result = _build_insight_answer(
            _INTENT_ATTACK_SURFACE, "exposed?", "surface context", self._ENTITIES, True
        )
        assert "Attack Surface" in result

    def test_capped_at_eight_entities(self):
        """Only up to 8 entities appear in Key Findings."""
        many = [
            {"id": f"e{i}", "type": "CVE", "name": f"CVE-2024-{i:04d}", "score": 0.8}
            for i in range(15)
        ]
        result = _build_insight_answer(
            _INTENT_TOP_RISKS, "top risks?", "ctx", many, True
        )
        # Count bullet entries: each entity line starts with "- **"
        bullets = [line for line in result.splitlines() if line.startswith("- **")]
        assert len(bullets) <= 8


# ===========================================================================
# Test 3: _build_insight_answer with no enrichment (empty graph)
# ===========================================================================


class TestBuildInsightAnswerNotEnriched:
    """_build_insight_answer returns helpful fallback text when graph has no data."""

    def test_no_key_findings_section_when_empty(self):
        result = _build_insight_answer(_INTENT_TOP_RISKS, "top risks?", "", [], False)
        assert "Key Findings" not in result

    def test_fallback_message_present(self):
        result = _build_insight_answer(_INTENT_TOP_RISKS, "top risks?", "", [], False)
        assert "No specific findings" in result or "no data" in result.lower() or "Tip:" in result

    def test_recommended_actions_still_present(self):
        """Even with no data, actions should be shown so users know what to do next."""
        result = _build_insight_answer(_INTENT_TOP_RISKS, "top risks?", "", [], False)
        assert "Recommended Actions" in result

    def test_tip_about_ingestion(self):
        result = _build_insight_answer(_INTENT_TOP_RISKS, "top risks?", "", [], False)
        assert "Ingest" in result or "ingest" in result or "connector" in result.lower()

    def test_returns_string(self):
        result = _build_insight_answer(_INTENT_COMPLIANCE, "SOC2?", "", [], False)
        assert isinstance(result, str)
        assert len(result) > 0


# ===========================================================================
# Test 4: _generate_security_insight structured output
# ===========================================================================


class TestGenerateSecurityInsight:
    """_generate_security_insight returns a complete structured insight dict."""

    _ENTITIES = [
        {"id": "risk_001", "type": "Finding", "name": "Unauthenticated API endpoint", "score": 0.9},
        {"id": "risk_002", "type": "CVE", "name": "CVE-2023-1234", "score": 0.75},
    ]

    def _patch_bridge(self, entities, enriched=True):
        """Context manager that replaces the bridge singleton with a mock."""
        mock_bridge = _mock_bridge(entities, enriched=enriched)
        return patch(
            "apps.api.copilot_router._get_graphrag_bridge",
            return_value=mock_bridge,
        )

    def test_returns_dict(self):
        with self._patch_bridge(self._ENTITIES):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("What are our top risks?", _INTENT_TOP_RISKS)
        assert isinstance(result, dict)

    def test_contains_required_keys(self):
        required = {"answer", "findings", "recommended_actions", "confidence", "source", "intent", "enriched"}
        with self._patch_bridge(self._ENTITIES):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("What are our top risks?", _INTENT_TOP_RISKS)
        assert required.issubset(result.keys())

    def test_source_is_graphrag_security_insight(self):
        with self._patch_bridge(self._ENTITIES):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert result["source"] == "graphrag_security_insight"

    def test_intent_propagated(self):
        with self._patch_bridge(self._ENTITIES):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("who attacks?", _INTENT_THREAT_LANDSCAPE)
        assert result["intent"] == _INTENT_THREAT_LANDSCAPE

    def test_confidence_nonzero_when_enriched(self):
        with self._patch_bridge(self._ENTITIES):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert result["confidence"] > 0.0

    def test_confidence_capped_at_095(self):
        many = [{"id": f"e{i}", "type": "F", "name": f"f{i}", "score": 1.0} for i in range(20)]
        with self._patch_bridge(many):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert result["confidence"] <= 0.95

    def test_recommended_actions_list(self):
        with self._patch_bridge(self._ENTITIES):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert isinstance(result["recommended_actions"], list)
        assert len(result["recommended_actions"]) > 0

    def test_recommended_actions_have_action_and_endpoint_keys(self):
        with self._patch_bridge(self._ENTITIES):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        for act in result["recommended_actions"]:
            assert "action" in act
            assert "endpoint" in act

    def test_findings_capped_at_ten(self):
        many = [{"id": f"e{i}", "type": "F", "name": f"f{i}", "score": 1.0} for i in range(20)]
        with self._patch_bridge(many):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert len(result["findings"]) <= 10

    def test_returns_none_when_bridge_unavailable(self):
        with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", False):
            result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert result is None

    def test_low_confidence_when_not_enriched(self):
        with self._patch_bridge([], enriched=False):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert result["confidence"] < 0.5

    def test_enriched_false_propagated(self):
        with self._patch_bridge([], enriched=False):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert result["enriched"] is False

    def test_answer_is_non_empty_string(self):
        with self._patch_bridge(self._ENTITIES):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                result = _generate_security_insight("top risks", _INTENT_TOP_RISKS)
        assert isinstance(result["answer"], str)
        assert len(result["answer"]) > 0


# ===========================================================================
# Test 5: ask_security_question endpoint routes through GraphRAG for ops questions
# ===========================================================================


class TestAskEndpointGraphRAGRouting:
    """ask_security_question uses GraphRAG path for security-ops questions."""

    _ENTITIES = [
        {"id": "e1", "type": "Finding", "name": "Critical open port 8443", "score": 0.9},
    ]

    def _mock_bridge_fixture(self, entities=None, enriched=True):
        if entities is None:
            entities = self._ENTITIES
        mock_bridge = _mock_bridge(entities, enriched=enriched)
        return mock_bridge

    @pytest.mark.asyncio
    async def test_top_risks_question_returns_graphrag_source(self):
        """'What are our top risks?' routes to GraphRAG, returns graphrag_security_insight source."""
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What are our top risks?")
                response = await ask_security_question(req)
        assert response.source == "graphrag_security_insight"

    @pytest.mark.asyncio
    async def test_top_risks_returns_intent(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What are our top risks?")
                response = await ask_security_question(req)
        assert response.intent == _INTENT_TOP_RISKS

    @pytest.mark.asyncio
    async def test_compliance_question_returns_compliance_intent(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="Are we compliant with SOC2?")
                response = await ask_security_question(req)
        assert response.intent == _INTENT_COMPLIANCE

    @pytest.mark.asyncio
    async def test_threat_landscape_question_returns_threat_intent(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="Who is attacking us?")
                response = await ask_security_question(req)
        assert response.intent == _INTENT_THREAT_LANDSCAPE

    @pytest.mark.asyncio
    async def test_attack_surface_question_returns_attack_surface_intent(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What assets are exposed?")
                response = await ask_security_question(req)
        assert response.intent == _INTENT_ATTACK_SURFACE

    @pytest.mark.asyncio
    async def test_recommended_actions_populated_for_ops_question(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What are our top risks?")
                response = await ask_security_question(req)
        assert isinstance(response.recommended_actions, list)
        assert len(response.recommended_actions) > 0

    @pytest.mark.asyncio
    async def test_recommended_actions_have_endpoint(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What are our top risks?")
                response = await ask_security_question(req)
        for act in response.recommended_actions:
            assert "endpoint" in act

    @pytest.mark.asyncio
    async def test_answer_contains_key_findings_when_enriched(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What are our top risks?")
                response = await ask_security_question(req)
        assert "Key Findings" in response.answer

    @pytest.mark.asyncio
    async def test_cwe_question_falls_through_to_knowledge_base(self):
        """SQL injection question should NOT use GraphRAG — must use builtin KB."""
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What is SQL injection?")
                response = await ask_security_question(req)
        # Must NOT have been handled by GraphRAG
        assert response.source != "graphrag_security_insight"
        assert response.matched_cwe == "CWE-89"

    @pytest.mark.asyncio
    async def test_xss_question_falls_through_to_knowledge_base(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="Explain cross-site scripting XSS")
                response = await ask_security_question(req)
        assert response.matched_cwe == "CWE-79"

    @pytest.mark.asyncio
    async def test_confidence_returned_in_response(self):
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What are our top risks?")
                response = await ask_security_question(req)
        assert isinstance(response.confidence, float)
        assert 0.0 <= response.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_related_findings_from_graphrag_entities(self):
        """related_findings in AskResponse is populated from GraphRAG entity list."""
        mock_bridge = self._mock_bridge_fixture()
        with patch("apps.api.copilot_router._get_graphrag_bridge", return_value=mock_bridge):
            with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", True):
                from apps.api.copilot_router import AskRequest, ask_security_question
                req = AskRequest(question="What are our top risks?")
                response = await ask_security_question(req)
        assert isinstance(response.related_findings, list)
        # At least one entity was in the fixture
        assert len(response.related_findings) >= 1
        assert response.related_findings[0]["name"] == "Critical open port 8443"

    @pytest.mark.asyncio
    async def test_bridge_unavailable_falls_through_to_cwe_for_ops_question(self):
        """When GraphRAG bridge is unavailable, ops questions still get a response."""
        with patch("apps.api.copilot_router._HAS_GRAPHRAG_BRIDGE", False):
            from apps.api.copilot_router import AskRequest, ask_security_question
            req = AskRequest(question="What are our top risks?")
            response = await ask_security_question(req)
        # Falls through to CWE path — should still respond (generic match)
        assert isinstance(response.answer, str)
        assert len(response.answer) > 0
