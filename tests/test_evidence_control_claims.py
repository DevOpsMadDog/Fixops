"""Every claim in the evidence bundle must be one we can defend.

The signed evidence bundle is what we ask an assessor to trust, and it is the commercial
wedge (ADR-008). A single unearned claim discredits the whole artifact, so nothing in it
may be asserted without something observed behind it.

Three claims could not be defended before 2026-08-17:

* ``change_management`` and ``logging_monitoring`` were hardcoded to ``"effective"`` —
  asserted on every run, including a run that did nothing at all.
* ``mean_time_to_detect`` was the string ``"< 24h"``. Nothing measured it. An assessor
  asking how it was determined would have found a literal.
* ``vulnerability_management`` used ``avg_risk < 0.6``, a threshold with no stated basis,
  presented as a control conclusion.

Controls now report ``effective`` / ``needs_improvement`` / ``not_assessed`` with the
criterion applied and the values observed. "Not assessed" is an honest gap an assessor can
work with; an assertion they can disprove is not.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from core.brain_pipeline import BrainPipeline

CONTROLS = ("vulnerability_management", "change_management", "logging_monitoring")


def _assess(ctx: Dict[str, Any]) -> Dict[str, Any]:
    return BrainPipeline._assess_controls(ctx)


def test_a_run_that_observed_nothing_asserts_nothing() -> None:
    """The decisive case: an empty pipeline run must not claim controls are effective."""
    controls = _assess({})
    for name in CONTROLS:
        assert controls[name]["status"] == "not_assessed", (
            f"{name} claims {controls[name]['status']!r} on a run that observed nothing"
        )
        assert controls[name].get("reason"), f"{name} gives no reason for not assessing"


def test_no_control_is_hardcoded_effective() -> None:
    """Vary the evidence and the status must vary with it."""
    empty = _assess({})
    populated = _assess(
        {
            "findings": [{"risk_score": 0.4}],
            "risk_scores": {"avg": 0.4},
            "playbook_results": [{"autofix": {"status": "generated"}}],
            "policy_decisions": [{"x": 1}],
            "graph_stats": {"total_nodes": 5},
        }
    )
    for name in CONTROLS:
        assert empty[name]["status"] != populated[name]["status"], (
            f"{name} reports the same status whether or not anything happened — "
            "it is not deriving a conclusion from evidence"
        )


def test_mean_time_to_detect_is_not_fabricated() -> None:
    """It was the literal '< 24h'. If we cannot measure it, we must say so."""
    controls = _assess(
        {"findings": [{"risk_score": 0.4}], "risk_scores": {"avg": 0.4}}
    )
    vuln = controls["vulnerability_management"]
    assert vuln["mean_time_to_detect"] is None
    assert "not measured" in vuln["mean_time_to_detect_note"]


def test_every_assessed_control_states_its_criterion_and_evidence() -> None:
    """A status without its basis is an opinion, not evidence."""
    controls = _assess(
        {
            "findings": [{"risk_score": 0.4}],
            "risk_scores": {"avg": 0.4},
            "playbook_results": [{"autofix": {"status": "generated"}}],
            "policy_decisions": [{"x": 1}],
            "graph_stats": {"total_nodes": 5},
        }
    )
    for name, control in controls.items():
        if control["status"] == "not_assessed":
            continue
        assert control.get("criterion"), f"{name} states a status with no criterion"
        assert control.get("observed"), f"{name} states a status with no observed values"


def test_untriaged_findings_downgrade_the_control() -> None:
    """Coverage is the defensible claim — and it must actually be computed."""
    controls = _assess(
        {
            "findings": [{"risk_score": 0.4}, {"risk_score": None}],
            "risk_scores": {"avg": 0.4},
        }
    )
    vuln = controls["vulnerability_management"]
    assert vuln["status"] == "needs_improvement"
    assert vuln["observed"]["triage_coverage"] == 0.5


def test_playbooks_without_artifacts_are_not_effective() -> None:
    controls = _assess({"playbook_results": [{"autofix": {"status": "skipped"}}]})
    assert controls["change_management"]["status"] == "needs_improvement"


@pytest.mark.parametrize(
    "ctx",
    [
        {"policy_decisions": [{"x": 1}]},
        {"graph_stats": {"total_nodes": 3}},
    ],
)
def test_logging_is_assessed_on_either_signal(ctx: Dict[str, Any]) -> None:
    assert _assess(ctx)["logging_monitoring"]["status"] == "effective"


def test_risk_threshold_no_longer_decides_effectiveness() -> None:
    """Whether the resulting risk is acceptable is the customer's judgement, not ours.

    Two runs with identical triage coverage but very different average risk must reach
    the same conclusion about the *control*, which is about process, not risk appetite.
    """
    low = _assess({"findings": [{"risk_score": 0.1}], "risk_scores": {"avg": 0.1}})
    high = _assess({"findings": [{"risk_score": 0.95}], "risk_scores": {"avg": 0.95}})
    assert (
        low["vulnerability_management"]["status"]
        == high["vulnerability_management"]["status"]
        == "effective"
    )
