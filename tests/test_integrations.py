import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, ANY

import networkx as nx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "fixops-blended-enterprise"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from src.integrations.ctinexus_adapter import CTINexusGraphResult
from src.services.knowledge_graph import KnowledgeGraphBuilder, SecurityEntity
from src.services.llm_explanation_engine import LLMExplanationEngine, ExplanationRequest
from src.services.sarif_risk_synthesizer import SarifRiskSynthesizer


@pytest.mark.asyncio
async def test_knowledge_graph_builder_uses_ctinexus_adapter():
    adapter = AsyncMock()
    graph = nx.DiGraph()
    graph.add_node("v1", type="vulnerability", name="CVE-1", severity="HIGH")
    graph.add_node("c1", type="component", name="service/api", path="service/api")
    graph.add_edge("v1", "c1", relation_type="affects", confidence=0.9)
    relations = [
        {"source": "v1", "target": "c1", "type": "affects", "confidence": 0.9, "properties": {"severity": "HIGH"}}
    ]
    adapter.build_graph.return_value = CTINexusGraphResult(
        graph=graph,
        relations=relations,
        serialized={"nodes": ["v1", "c1"], "edges": relations},
    )

    builder = KnowledgeGraphBuilder(graph_adapter=adapter)
    entities = [
        SecurityEntity("v1", "vulnerability", "CVE-1", {"severity": "HIGH", "file_location": "service/api"}, 0.9),
        SecurityEntity("c1", "component", "service/api", {"path": "service/api"}, 0.8),
    ]

    result = await builder.build_graph({"sarif": {}}, None)

    adapter.build_graph.assert_awaited()
    assert result["relations_count"] == 1
    assert result["serialized_graph"]["edges"] == relations
    assert builder.graph.has_edge("v1", "c1")
    assert builder.graph.edges[("v1", "c1")]["relation_type"] == "affects"


@pytest.mark.asyncio
async def test_llm_explanation_engine_invokes_awesome_model():
    engine = LLMExplanationEngine()
    engine.cybersec_engine.llm_client = AsyncMock()
    engine.cybersec_engine.llm_client.generate.return_value = "Summary: ok\nAnalysis: details"

    request = ExplanationRequest(
        context_type="vulnerability_analysis",
        technical_data={"sample": "data"},
        audience="security_analyst",
        detail_level="detailed",
    )

    explanation = await engine.generate_explanation(request)

    engine.cybersec_engine.llm_client.generate.assert_awaited()
    engine.cybersec_engine.llm_client.generate.assert_awaited_with(ANY, system_prompt=ANY)
    assert "Summary" in explanation.detailed_analysis


@pytest.mark.asyncio
async def test_llm_explanation_engine_handles_generation_error():
    engine = LLMExplanationEngine()
    engine.cybersec_engine.llm_client = AsyncMock()
    engine.cybersec_engine.llm_client.generate.side_effect = RuntimeError("boom")

    request = ExplanationRequest(
        context_type="decision_rationale",
        technical_data={"decision": "allow"},
        audience="executive",
        detail_level="summary",
    )

    explanation = await engine.generate_explanation(request)

    assert "Unable" in explanation.summary
    assert explanation.confidence < 0.5


@pytest.mark.asyncio
async def test_sarif_risk_synthesizer_scores_non_cve_findings():
    class StubTooling:
        def cluster_results(self, results):
            return [{"cluster_id": "default", "findings": results}]

        def score_cluster(self, cluster):
            return 0.5

        def score_finding(self, finding):
            return 0.7 if not finding.get("cve") else 0.9

    synthesizer = SarifRiskSynthesizer(tooling=StubTooling())

    sarif_data = {
        "runs": [
            {
                "results": [
                    {"ruleId": "R1", "level": "warning", "properties": {"securitySeverity": "HIGH", "confidence": 0.8}},
                    {"ruleId": "R2", "level": "error", "properties": {"securitySeverity": "CRITICAL", "cve": "CVE-1"}},
                ]
            }
        ]
    }

    summary = await synthesizer.synthesize(sarif_data)

    assert pytest.approx(summary.overall_risk, 0.01) == 0.5
    assert summary.non_cve_findings and summary.non_cve_findings[0]["risk_score"] > 0
