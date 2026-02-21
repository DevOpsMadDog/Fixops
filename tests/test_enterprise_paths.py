import csv
from pathlib import Path
from typing import Mapping

import pytest
from apps.api.normalizers import InputNormalizer
from apps.api.pipeline import PipelineOrchestrator
from core.configuration import load_overlay

ARTEFACTS = Path(__file__).resolve().parents[1] / "artefacts"


def _read_design_csv(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = [
            row
            for row in reader
            if any((value or "").strip() for value in row.values())
        ]
        columns = reader.fieldnames or []
    return {"columns": columns, "rows": rows}


@pytest.fixture
def enterprise_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXOPS_API_TOKEN", "test-token")
    monkeypatch.setenv(
        "FIXOPS_EVIDENCE_KEY", "Zz6A0n4P3skS8F6edSxE2xe50Tzw9uQWGWp9JYG1ChE="
    )
    monkeypatch.setenv("FIXOPS_JIRA_TOKEN", "test-jira-token")
    monkeypatch.setenv("FIXOPS_JIRA_ENDPOINT", "https://jira.example.com")
    monkeypatch.setenv("FIXOPS_CONFLUENCE_TOKEN", "test-confluence-token")
    monkeypatch.setenv("FIXOPS_CONFLUENCE_ENDPOINT", "https://confluence.example.com")


def _execute_pipeline() -> dict[str, object]:
    normalizer = InputNormalizer()
    design = _read_design_csv(ARTEFACTS / "design.csv")
    sbom = normalizer.load_sbom((ARTEFACTS / "sbom.cdx.json").read_bytes())
    sarif = normalizer.load_sarif((ARTEFACTS / "snyk.sarif").read_bytes())
    cve = normalizer.load_cve_feed((ARTEFACTS / "cve.json").read_bytes())
    vex = normalizer.load_vex((ARTEFACTS / "vex.cdx.json").read_bytes())
    cnapp = normalizer.load_cnapp((ARTEFACTS / "cnapp.json").read_bytes())
    overlay = load_overlay()
    orchestrator = PipelineOrchestrator()
    return orchestrator.run(
        design_dataset=design,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
        vex=vex,
        cnapp=cnapp,
    )


@pytest.fixture
def pipeline_result(enterprise_env: None) -> dict[str, object]:
    return _execute_pipeline()


def test_vex_noise_reduction_and_cnapp_enrichment(
    pipeline_result: dict[str, object],
) -> None:
    result = pipeline_result
    noise = result.get("noise_reduction", {})
    assert isinstance(noise, dict)
    assert noise.get("suppressed_total", 0) >= 1
    cnapp_summary = result.get("cnapp_summary", {})
    assert isinstance(cnapp_summary, dict)
    added = cnapp_summary.get("added_severity", {})
    assert isinstance(added, dict)
    assert added.get("critical", 0) >= 1
    severity_overview = result.get("severity_overview", {})
    assert severity_overview.get("highest") == "critical"
    recommendations = result.get("marketplace_recommendations")
    assert isinstance(recommendations, list)
    assert recommendations, "Marketplace recommendations should be surfaced"
    first = recommendations[0]
    assert isinstance(first, dict)
    match = first.get("match", [])
    assert any("guardrail" in str(entry).lower() for entry in match)


def test_evidence_encrypted_when_overlay_requests_it(
    pipeline_result: dict[str, object],
) -> None:
    result = pipeline_result
    bundle = result.get("evidence_bundle", {})
    assert isinstance(bundle, dict)
    assert bundle.get("encrypted") is True


def test_module_matrix_includes_promised_modules(
    pipeline_result: dict[str, object],
) -> None:
    result = pipeline_result
    modules = result.get("modules", {})
    assert isinstance(modules, dict)
    status = modules.get("status", {})
    assert isinstance(status, dict)
    expected = {
        "context_engine",
        "guardrails",
        "compliance",
        "policy_automation",
        "ssdlc",
        "iac_posture",
        "exploit_signals",
        "probabilistic",
        "vector_store",
        "enhanced_decision",
    }
    for module in expected:
        assert status.get(module) == "executed"


def test_enhanced_decision_outputs_consensus(
    pipeline_result: dict[str, object],
) -> None:
    enhanced = pipeline_result.get("enhanced_decision", {})
    assert isinstance(enhanced, dict)
    assert enhanced.get("final_decision")
    assert 0.0 < enhanced.get("consensus_confidence", 0) <= 1.0
    assert enhanced.get("individual_analyses")
    telemetry = enhanced.get("telemetry", {})
    assert telemetry.get("models_consulted") >= 1
    assert telemetry.get("marketplace_references")
    knowledge = telemetry.get("knowledge_graph", {})
    assert knowledge.get("nodes") >= 0
    signals = enhanced.get("signals", {})
    assert signals.get("ssvc_label") in {"Act", "Attend", "Track"}


def test_pipeline_exposes_knowledge_graph(pipeline_result: dict[str, object]) -> None:
    graph = pipeline_result.get("knowledge_graph", {})
    assert isinstance(graph, dict)
    analytics = graph.get("analytics", {})
    assert analytics.get("entity_count", 0) >= 1
    structured = graph.get("graph", {})
    assert isinstance(structured, Mapping)
    nodes = structured.get("nodes", [])
    edges = structured.get("edges", [])
    assert nodes and edges


def test_vector_similarity_matches_patterns(pipeline_result: dict[str, object]) -> None:
    vector = pipeline_result.get("vector_similarity", {})
    assert isinstance(vector, Mapping)
    provider = vector.get("provider", {})
    assert isinstance(provider, Mapping)
    assert provider.get("provider")
    matches = vector.get("matches", [])
    assert matches, "Vector store should return similarity matches"
    first = matches[0]
    assert isinstance(first, Mapping)
    patterns = first.get("patterns", [])
    assert patterns, "Each match should include pattern recommendations"
