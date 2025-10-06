"""Tests for the modernised processing utilities."""

from __future__ import annotations

import importlib
import sys
import types

import pytest


@pytest.fixture(autouse=True)
def clear_processing_modules():
    for module_name in list(sys.modules):
        if module_name.startswith("new_backend.processing"):
            sys.modules.pop(module_name)
    yield


def test_knowledge_graph_processor_invokes_ctinexus(monkeypatch):
    fake_module = types.ModuleType("CTINexus")
    instances = []

    class FakeBuilder:
        def __init__(self) -> None:
            self.entities = []
            self.relationships = []
            self.extract_payload = None
            instances.append(self)

        def extract(self, payload):
            self.extract_payload = payload
            return payload

        def ingest_entities(self, entities):
            self.entities.extend(entities)

        def ingest_relationships(self, relationships):
            self.relationships.extend(relationships)

        def build(self):
            return {"nodes": list(self.entities), "edges": list(self.relationships)}

        def serialize(self, graph):
            return {"graph": graph}

        def analytics(self, graph):
            return {"density": 0.42}

    fake_module.GraphBuilder = FakeBuilder
    monkeypatch.setitem(sys.modules, "CTINexus", fake_module)

    module = importlib.import_module("new_backend.processing.knowledge_graph")
    processor = module.KnowledgeGraphProcessor()
    snapshot = {
        "entities": [
            {"id": "svc", "type": "service", "properties": {"critical": True}},
            {"name": "database", "category": "data"},
        ],
        "relationships": [
            {"from": "svc", "to": "database", "relationship": "queries"}
        ],
    }

    result = processor.build_graph(snapshot)

    assert isinstance(instances[0], FakeBuilder)
    assert instances[0].extract_payload == snapshot
    assert result["graph"]["nodes"][0]["id"] == "svc"
    assert result["graph"]["edges"][0]["source"] == "svc"
    assert result["analytics"]["entity_count"] == 2
    assert result["analytics"]["relationship_count"] == 1


def test_explanation_generator_uses_sentinel_gpt(monkeypatch):
    pkg = types.ModuleType("awesome_llm4cybersecurity")
    submodule = types.ModuleType("awesome_llm4cybersecurity.sentinel_gpt")

    class FakeClient:
        def __init__(self) -> None:
            self.calls = []

        def generate(self, *, prompt, max_tokens, temperature):
            self.calls.append({
                "prompt": prompt,
                "max_tokens": max_tokens,
                "temperature": temperature,
            })
            return {"text": "Critical dependency on payment-db. Prioritise patching."}

    submodule.SentinelGPT = FakeClient
    monkeypatch.setitem(sys.modules, "awesome_llm4cybersecurity", pkg)
    monkeypatch.setitem(sys.modules, "awesome_llm4cybersecurity.sentinel_gpt", submodule)
    setattr(pkg, "sentinel_gpt", submodule)

    module = importlib.import_module("new_backend.processing.explanation")

    class DummyLimiter:
        def __init__(self) -> None:
            self.calls = 0

        def acquire(self) -> None:
            self.calls += 1

    limiter = DummyLimiter()
    generator = module.ExplanationGenerator(rate_limiter=limiter)
    findings = [
        {
            "rule_id": "CWE-79",
            "severity": "high",
            "location": "app.py:42",
            "description": "Reflected XSS",
        }
    ]

    explanation = generator.generate(findings, {"summary": "Payment stack"})

    assert limiter.calls == 1
    prompt = generator._build_prompt(findings, {"summary": "Payment stack"})
    assert "Payment stack" in prompt
    client = generator._ensure_client()
    assert client.calls[0]["prompt"].startswith("You are SentinelGPT")
    assert "Critical dependency" in explanation


def test_sarif_analyzer_clusters_and_scores(monkeypatch):
    sarif_pkg = types.ModuleType("sarif")
    utils_module = types.ModuleType("sarif.sarif_file_utils")

    def combine_code_and_description(code, description):
        return f"{code}:{description}"[:120]

    def read_result_severity(result, run):
        return result.get("level", "warning")

    utils_module.combine_code_and_description = combine_code_and_description
    utils_module.read_result_severity = read_result_severity
    utils_module.SARIF_SEVERITIES_WITH_NONE = ["error", "warning", "note", "none"]

    monkeypatch.setitem(sys.modules, "sarif", sarif_pkg)
    monkeypatch.setitem(sys.modules, "sarif.sarif_file_utils", utils_module)
    setattr(sarif_pkg, "sarif_file_utils", utils_module)

    sarif_om = types.ModuleType("sarif_om")

    class FakeSarifLog:
        def __init__(self, data):
            self._data = data

        def to_dict(self):
            return self._data

        @classmethod
        def from_dict(cls, data):
            return cls(data)

    sarif_om.SarifLog = FakeSarifLog
    monkeypatch.setitem(sys.modules, "sarif_om", sarif_om)

    module = importlib.import_module("new_backend.processing.sarif")
    analyzer = module.SarifAnalyzer()

    payload = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "R1",
                        "level": "error",
                        "message": {"text": "SQL injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "svc.py"},
                                    "region": {"startLine": 12},
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }

    report = analyzer.analyze(payload)

    assert report["result_count"] == 1
    assert report["severity_breakdown"]["error"] == 1
    assert report["clusters"][0]["rule_id"] == "R1"
    result_id = report["clusters"][0]["results"][0]["id"]
    assert report["probabilities"][result_id] > 0.5


def test_bayesian_network_inference_produces_posteriors():
    module = importlib.import_module("new_backend.processing.bayesian")

    network = {
        "nodes": {
            "Firewall": {
                "states": ["secure", "breached"],
                "cpt": [0.9, 0.1],
            },
            "Database": {
                "states": ["healthy", "compromised"],
                "parents": ["Firewall"],
                "cpt": {
                    ("secure",): [0.95, 0.05],
                    ("breached",): [0.4, 0.6],
                },
            },
            "Service": {
                "states": ["operational", "degraded"],
                "parents": ["Database"],
                "cpt": {
                    ("healthy",): [0.9, 0.1],
                    ("compromised",): [0.3, 0.7],
                },
            },
        }
    }

    components = [
        {"id": "Firewall", "observed_state": "breached"},
        {"id": "Database"},
        {"id": "Service"},
    ]

    posteriors = module.update_probabilities(components, network)

    assert posteriors["Firewall"]["breached"] == pytest.approx(1.0)
    assert posteriors["Database"]["compromised"] == pytest.approx(0.6, abs=1e-6)
    assert posteriors["Service"]["degraded"] == pytest.approx(0.46, abs=1e-6)

    annotated = module.attach_component_posterior(components, posteriors)

    assert components[0].get("posterior") is None  # ensure originals untouched
    assert annotated[1]["posterior"]["compromised"] == pytest.approx(0.6, abs=1e-6)
