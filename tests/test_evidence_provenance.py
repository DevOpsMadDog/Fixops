"""A conclusion whose inputs cannot be reconstructed is not evidence.

In an accredited environment the question is not only "what did you conclude?" but "how,
and from what?" — asked months later by someone who was not in the room. The bundle
therefore has to carry the chain a verdict travelled: which tools the findings came from,
which feeds enriched them and whether that was live or an offline bundle, what the scoring
saw, which council members voted and whether they really ran, and what came out.

Two properties matter more than completeness:

* A stage that did not run must **say so**, not vanish. A missing key reads as an
  oversight; ``"not_enriched"`` is a fact an assessor can act on.
* ``is_real_inference`` must travel with the verdict. "AI decided" and "a heuristic
  decided while the model was unreachable" are different claims, and only one of them
  belongs in evidence.

See ADR-008 and ADR-003.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from core.brain_pipeline import BrainPipeline

FULL_CONTEXT: Dict[str, Any] = {
    "findings": [
        {"risk_score": 0.9, "source_tool": "semgrep"},
        {"risk_score": 0.4, "source_tool": "trivy"},
        {"risk_score": 0.2, "source_tool": "semgrep"},
    ],
    "risk_scores": {"avg": 0.5, "critical": 1},
    "_enrich_source": "live_api",
    "_enrich_feed_hits": 2,
    "clusters": [1, 2],
    "exposure_cases": [1],
    "council_verdict": {
        "source": "consensus",
        "is_real_inference": True,
        "council_models": ["gemini-2.5-flash", "deepseek-chat-v3.1"],
        "providers_responded": 5,
        "confidence": 0.94,
        "session_id": "3c9530a4",
    },
    "policy_decisions": [{"a": 1}],
    "playbook_results": [{"autofix": {"status": "generated"}}],
}


@pytest.fixture()
def provenance() -> Dict[str, Any]:
    return BrainPipeline._evidence_provenance(FULL_CONTEXT)


def test_the_whole_chain_is_present(provenance: Dict[str, Any]) -> None:
    for stage in ("ingest", "enrichment", "scoring", "council", "decision"):
        assert stage in provenance, f"provenance is missing the {stage} stage"


def test_ingest_names_the_tools_the_findings_came_from(
    provenance: Dict[str, Any],
) -> None:
    """'3 findings' is a number; 'semgrep and trivy' is a source."""
    assert provenance["ingest"]["findings"] == 3
    assert provenance["ingest"]["source_tools"] == ["semgrep", "trivy"]


def test_enrichment_records_whether_it_was_live_or_offline(
    provenance: Dict[str, Any],
) -> None:
    """Live versus an offline bundle changes how fresh the scoring inputs were."""
    assert provenance["enrichment"]["source"] == "live_api"
    assert provenance["enrichment"]["feed_hits"] == 2
    assert "feed_bundle_version" in provenance["enrichment"]


def test_council_records_who_voted(provenance: Dict[str, Any]) -> None:
    """Which models voted is the difference between 'AI decided' and an auditable one."""
    council = provenance["council"]
    assert council["ran"] is True
    assert council["members"] == ["gemini-2.5-flash", "deepseek-chat-v3.1"]
    assert council["method"] == "consensus"


def test_real_inference_travels_with_the_verdict(provenance: Dict[str, Any]) -> None:
    assert provenance["council"]["is_real_inference"] is True


def test_a_heuristic_verdict_is_not_dressed_up_as_a_model_decision() -> None:
    """The distinction that must never be lost in the bundle."""
    context = dict(FULL_CONTEXT)
    context["council_verdict"] = {
        "source": "heuristic",
        "is_real_inference": False,
        "council_models": [],
        "cost_usd": 0.0,
    }
    council = BrainPipeline._evidence_provenance(context)["council"]
    assert council["is_real_inference"] is False
    assert council["method"] == "heuristic"


def test_stages_that_did_not_run_say_so_rather_than_disappearing() -> None:
    """A missing key reads as an oversight; a stated absence is a fact."""
    provenance = BrainPipeline._evidence_provenance({})

    assert provenance["enrichment"]["source"] == "not_enriched"
    assert provenance["council"]["ran"] is False
    assert provenance["ingest"]["findings"] == 0
    for stage in ("ingest", "enrichment", "scoring", "council", "decision"):
        assert stage in provenance


def test_findings_without_a_tool_are_reported_as_unknown() -> None:
    """Unattributed input is itself worth recording."""
    provenance = BrainPipeline._evidence_provenance({"findings": [{"risk_score": 0.5}]})
    assert provenance["ingest"]["source_tools"] == ["unknown"]


def test_provenance_is_json_serialisable() -> None:
    """The bundle is signed and shipped; anything unserialisable breaks it."""
    import json

    json.dumps(BrainPipeline._evidence_provenance(FULL_CONTEXT))
