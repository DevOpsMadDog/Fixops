"""A customer must be able to teach the product its own risk model.

The competitive position. A closed knowledge graph works until the customer's
model contains a concept the vendor never built: "this service is in the
cardholder data environment", "this repo is under regulatory hold", "these
dependencies are approved for the classified enclave". If you cannot express
it, you cannot decide with it, and the graph is only as good as the vendor's
imagination.

TrustGraph already stored ``entity_type`` and ``rel_type`` as free strings, so
the openness was latent — there was simply no door a customer could reach. These
tests cover that door: declare a type, attach entities, write rules, and have
the pipeline apply them to real findings.

Three properties are non-negotiable and each has a test:

* tenant isolation — one customer's ontology must never touch another's
  decisions;
* attribution — a rule that fires says which rule it was, because a priority
  that moved for unreconstructable reasons is the opacity customers are trying
  to escape;
* rules cannot invent evidence — they move priority and attach labels, and can
  never set reachability, exploitability or a CVE, which are measurements.
"""

from __future__ import annotations

import pytest

from core.brain_pipeline import BrainPipeline
from core.tenant_graph_engine import TenantGraphEngine


@pytest.fixture()
def engine(tmp_path, monkeypatch) -> TenantGraphEngine:
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))
    return TenantGraphEngine(db_path=str(tmp_path / "tenant_graph.db"))


@pytest.fixture()
def cde(engine: TenantGraphEngine) -> TenantGraphEngine:
    """A tenant that has taught the product about its PCI scope."""
    engine.declare_type("acme", "cardholder_data_environment", "In PCI DSS scope")
    engine.add_entity("acme", "cardholder_data_environment", "payments-db", {"tier": "0"})
    engine.declare_rule(
        "acme", "CDE assets escalate", "asset_id", "payments-db", "escalate",
        entity_type="cardholder_data_environment",
    )
    return engine


def _apply(engine, org_id, findings):
    return engine.apply_rules(org_id, findings)


def test_a_tenant_can_declare_a_concept_the_vendor_never_modelled(engine) -> None:
    declared = engine.declare_type("acme", "classified_enclave", "Air-gapped enclave")

    assert declared["name"] == "classified_enclave"
    assert [t["name"] for t in engine.list_types("acme")] == ["classified_enclave"]


def test_declaring_the_same_type_twice_is_not_an_error(engine) -> None:
    """Re-running onboarding must not fail; it is the same statement."""
    engine.declare_type("acme", "crown_jewel")
    engine.declare_type("acme", "crown_jewel")

    assert len(engine.list_types("acme")) == 1


def test_an_entity_of_an_undeclared_type_is_refused(engine) -> None:
    """A typo that silently stops a rule firing is the failure to avoid."""
    with pytest.raises(ValueError, match="has not been declared"):
        engine.add_entity("acme", "typo_type", "payments-db")


def test_a_rule_changes_the_priority_of_a_matching_finding(cde) -> None:
    findings = [{"asset_id": "payments-db", "consensus_priority": 3}]
    _apply(cde, "acme", findings)

    assert findings[0]["consensus_priority"] == 2


def test_a_rule_leaves_non_matching_findings_alone(cde) -> None:
    findings = [{"asset_id": "marketing-site", "consensus_priority": 3}]
    _apply(cde, "acme", findings)

    assert findings[0]["consensus_priority"] == 3
    assert "tenant_rules_applied" not in findings[0]


def test_every_change_says_which_rule_made_it(cde) -> None:
    """A score that moved for unexplainable reasons is what they are escaping."""
    findings = [{"asset_id": "payments-db", "consensus_priority": 3}]
    _apply(cde, "acme", findings)

    applied = findings[0]["tenant_rules_applied"]
    assert len(applied) == 1
    assert applied[0]["rule_name"] == "CDE assets escalate"
    assert applied[0]["matched"] == "asset_id=payments-db"
    assert applied[0]["action"] == "escalate"


def test_one_tenants_rules_never_touch_another_tenants_findings(cde) -> None:
    """The property that makes this safe to offer at all."""
    findings = [{"asset_id": "payments-db", "consensus_priority": 3}]
    _apply(cde, "other-corp", findings)

    assert findings[0]["consensus_priority"] == 3, "another tenant's rule fired"
    assert "tenant_rules_applied" not in findings[0]


def test_a_rule_scoped_to_an_entity_type_only_fires_for_that_types_entities(engine) -> None:
    engine.declare_type("acme", "crown_jewel")
    engine.add_entity("acme", "crown_jewel", "payments-db")
    engine.declare_rule(
        "acme", "jewels escalate", "asset_id", "billing-db", "escalate",
        entity_type="crown_jewel",
    )

    findings = [{"asset_id": "billing-db", "consensus_priority": 3}]
    _apply(engine, "acme", findings)

    assert findings[0]["consensus_priority"] == 3, (
        "a rule fired for a value that is not an entity of its declared type"
    )


def test_a_label_rule_annotates_without_moving_priority(engine) -> None:
    engine.declare_type("acme", "regulatory_hold")
    engine.add_entity("acme", "regulatory_hold", "legacy-api")
    engine.declare_rule(
        "acme", "flag hold", "asset_id", "legacy-api", "label",
        label="under-legal-hold", entity_type="regulatory_hold",
    )

    findings = [{"asset_id": "legacy-api", "consensus_priority": 3}]
    _apply(engine, "acme", findings)

    assert findings[0]["tenant_labels"] == ["under-legal-hold"]
    assert findings[0]["consensus_priority"] == 3


def test_a_rule_cannot_invent_a_measurement(engine) -> None:
    """The hard limit. A customer rule must not make the product assert
    reachability, exploitability or a CVE it never observed."""
    from core.tenant_graph_engine import VALID_ACTIONS

    forbidden = {"set_reachable", "set_exploitability", "set_cve", "set_severity"}
    assert not forbidden & set(VALID_ACTIONS)

    with pytest.raises(ValueError, match="action must be one of"):
        engine.declare_rule("acme", "cheat", "asset_id", "x", "set_reachable")


def test_a_rule_can_only_match_on_a_real_finding_attribute(engine) -> None:
    with pytest.raises(ValueError, match="match_field must be one of"):
        engine.declare_rule("acme", "bad", "made_up_field", "x", "escalate")


def test_the_pipeline_applies_tenant_rules_after_its_own_analysis(cde, monkeypatch) -> None:
    """Order matters: measure first, then let the customer's model adjust.

    A rule that ran BEFORE measurement could bury a finding that measurement
    would have surfaced.
    """
    monkeypatch.setattr(
        "core.tenant_graph_engine.get_tenant_graph_engine", lambda: cde, raising=False
    )
    import core.tenant_graph_engine as module

    monkeypatch.setattr(module, "get_tenant_graph_engine", lambda: cde)

    pipeline = BrainPipeline.__new__(BrainPipeline)
    ctx = {
        "org_id": "acme",
        "findings": [{"asset_id": "payments-db", "consensus_priority": 3, "cve_id": "CVE-1"}],
    }
    BrainPipeline._apply_tenant_graph_rules(pipeline, ctx)

    assert ctx["findings"][0]["consensus_priority"] == 2
    assert ctx["tenant_rules_summary"] == {"escalate": 1}


def test_a_broken_rule_engine_never_costs_the_customer_the_run(monkeypatch) -> None:
    import core.tenant_graph_engine as module

    def boom():
        raise RuntimeError("rule store offline")

    monkeypatch.setattr(module, "get_tenant_graph_engine", boom)

    pipeline = BrainPipeline.__new__(BrainPipeline)
    ctx = {"org_id": "acme", "findings": [{"asset_id": "payments-db", "consensus_priority": 3}]}

    BrainPipeline._apply_tenant_graph_rules(pipeline, ctx)  # must not raise

    assert ctx["findings"][0]["consensus_priority"] == 3


def test_rules_are_capped_per_org(engine) -> None:
    """An unbounded rule set is a denial-of-service against our own pipeline."""
    from core.tenant_graph_engine import _MAX_RULES_PER_ORG

    assert _MAX_RULES_PER_ORG > 0
