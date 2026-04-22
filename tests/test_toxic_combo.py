"""Tests for GAP-021 toxic-combo correlation.

Covers:
  - toxic_combo_rules builtin catalog (5 rules)
  - evaluate_combo() AND semantics + partial-match explainability
  - ThreatCorrelationEngine.correlate_toxic_combos(): persistence + dedup
  - AttackChainEngine.build_chain_from_toxic_combo(): upgrade path
  - SecurityEventCorrelationEngine.on_toxic_combo_matched(): subscriber
  - Toxic-combo router /evaluate, /matches, /rules, /simulate
  - Org-id isolation
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest


# ---------------------------------------------------------------------------
# Fixtures — per-test data dirs so no cross-test state
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_engines(tmp_path, monkeypatch):
    """Rebind engine DB dirs to a pytest tmp_path and reload the modules so
    the toxic-combo table is created under the tmp path instead of the
    repo-root ``.fixops_data``.
    """
    monkeypatch.setenv("FIXOPS_DATA_DIR", str(tmp_path))

    import core.toxic_combo_rules as tcr  # noqa: F401
    import core.threat_correlation_engine as tce
    import core.attack_chain_engine as ace
    import core.security_event_correlation_engine as sec_ece

    # Monkeypatch module-level data dirs.
    monkeypatch.setattr(tce, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(ace, "_DEFAULT_DB_DIR", str(tmp_path))
    monkeypatch.setattr(sec_ece, "_DEFAULT_DB_DIR", tmp_path)

    # Reset singleton cache so .for_org() re-resolves under tmp path.
    tce.ThreatCorrelationEngine._instances = {}

    return {
        "tcr": importlib.import_module("core.toxic_combo_rules"),
        "tce": tce,
        "ace": ace,
        "sec": sec_ece,
    }


@pytest.fixture
def tcr(fresh_engines):
    return fresh_engines["tcr"]


@pytest.fixture
def threat_engine(fresh_engines):
    return fresh_engines["tce"].ThreatCorrelationEngine.for_org("org1")


@pytest.fixture
def attack_engine(fresh_engines, tmp_path):
    return fresh_engines["ace"].AttackChainEngine(db_path=str(tmp_path / "attack_chain.db"))


@pytest.fixture
def sec_engine(fresh_engines, tmp_path):
    return fresh_engines["sec"].SecurityEventCorrelationEngine(
        db_path=str(tmp_path / "sec_ec.db")
    )


# ---------------------------------------------------------------------------
# Ruleset catalog
# ---------------------------------------------------------------------------


def test_builtin_rules_have_five(tcr):
    rules = tcr.list_builtin_rules()
    assert len(rules) == 5


def test_builtin_rule_ids_are_unique(tcr):
    ids = [r.id for r in tcr.list_builtin_rules()]
    assert len(ids) == len(set(ids))


def test_classic_rule_has_four_predicates(tcr):
    rule = tcr.get_rule("internet-exposed-crit-cve-pii")
    assert rule is not None
    assert len(rule.predicates) == 4
    attrs = [p.attribute for p in rule.predicates]
    assert "internet_exposed" in attrs
    assert "critical_cve" in attrs
    assert "over_permissive" in attrs
    assert "has_pii" in attrs


def test_get_rule_unknown_returns_none(tcr):
    assert tcr.get_rule("does-not-exist") is None


def test_rule_to_dict_has_required_fields(tcr):
    for rule in tcr.list_builtin_rules():
        d = rule.to_dict()
        assert d["id"]
        assert d["name"]
        assert d["severity"] in ("critical", "high", "medium", "low")
        assert isinstance(d["required_attributes"], list)
        assert isinstance(d["predicates"], list)


# ---------------------------------------------------------------------------
# evaluate_combo — AND semantics + partial match
# ---------------------------------------------------------------------------


def test_evaluate_classic_all_four_match(tcr):
    rule = tcr.get_rule("internet-exposed-crit-cve-pii")
    attrs = {
        "internet_exposed": True,
        "critical_cve": ["CVE-2024-0001"],
        "over_permissive": True,
        "has_pii": True,
    }
    matched, satisfied = tcr.evaluate_combo(rule, attrs)
    assert matched is True
    assert len(satisfied) == 4


def test_evaluate_classic_three_of_four_does_not_match(tcr):
    rule = tcr.get_rule("internet-exposed-crit-cve-pii")
    attrs = {
        "internet_exposed": True,
        "critical_cve": ["CVE-2024-0001"],
        "over_permissive": True,
        "has_pii": False,
    }
    matched, satisfied = tcr.evaluate_combo(rule, attrs)
    assert matched is False
    assert len(satisfied) == 3  # partial explainability


def test_evaluate_classic_empty_attrs(tcr):
    rule = tcr.get_rule("internet-exposed-crit-cve-pii")
    matched, satisfied = tcr.evaluate_combo(rule, {})
    assert matched is False
    assert satisfied == []


def test_evaluate_classic_with_string_values(tcr):
    rule = tcr.get_rule("internet-exposed-crit-cve-pii")
    attrs = {
        "internet_exposed": "public",
        "critical_cve": "CVE-2023-9999",
        "over_permissive": "admin",
        "has_pii": "PII",
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is True


def test_evaluate_bad_input_type_raises(tcr):
    rule = tcr.get_rule("internet-exposed-crit-cve-pii")
    with pytest.raises(TypeError):
        tcr.evaluate_combo(rule, "not-a-dict")


def test_evaluate_predicate_exception_treated_as_false(tcr):
    """If a predicate raises, the predicate counts as unsatisfied."""
    rule = tcr.get_rule("internet-exposed-crit-cve-pii")

    class Explodes:
        def __bool__(self):
            raise RuntimeError("boom")

    attrs = {
        "internet_exposed": True,
        "critical_cve": Explodes(),
        "over_permissive": True,
        "has_pii": True,
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


# ---------------------------------------------------------------------------
# Public-S3 rule
# ---------------------------------------------------------------------------


def test_public_s3_rule_matches(tcr):
    rule = tcr.get_rule("public-s3-with-pii")
    attrs = {
        "is_object_store": True,
        "public_access": "public",
        "has_pii": True,
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is True


def test_public_s3_missing_pii_does_not_match(tcr):
    rule = tcr.get_rule("public-s3-with-pii")
    attrs = {"is_object_store": True, "public_access": "public", "has_pii": False}
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


def test_public_s3_private_bucket_does_not_match(tcr):
    rule = tcr.get_rule("public-s3-with-pii")
    attrs = {"is_object_store": True, "public_access": False, "has_pii": True}
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


# ---------------------------------------------------------------------------
# Over-permissive-IAM-to-data-store rule
# ---------------------------------------------------------------------------


def test_over_perm_iam_matches(tcr):
    rule = tcr.get_rule("over-permissive-iam-to-data-store")
    attrs = {
        "over_permissive": True,
        "asset_type": "database",
        "crown_jewel": True,
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is True


def test_over_perm_iam_non_datastore_does_not_match(tcr):
    rule = tcr.get_rule("over-permissive-iam-to-data-store")
    attrs = {"over_permissive": True, "asset_type": "ec2", "crown_jewel": True}
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


def test_over_perm_iam_not_crown_jewel_does_not_match(tcr):
    rule = tcr.get_rule("over-permissive-iam-to-data-store")
    attrs = {"over_permissive": True, "asset_type": "database", "crown_jewel": False}
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


# ---------------------------------------------------------------------------
# Unpatched-internet-exposed-RDP rule
# ---------------------------------------------------------------------------


def test_rdp_rule_matches(tcr):
    rule = tcr.get_rule("unpatched-internet-exposed-rdp")
    attrs = {
        "internet_exposed": True,
        "exposed_ports": [80, 443, 3389],
        "os_family": "windows",
        "os_unpatched": True,
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is True


def test_rdp_wrong_os_does_not_match(tcr):
    rule = tcr.get_rule("unpatched-internet-exposed-rdp")
    attrs = {
        "internet_exposed": True,
        "exposed_ports": [3389],
        "os_family": "linux",
        "os_unpatched": True,
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


def test_rdp_patched_does_not_match(tcr):
    rule = tcr.get_rule("unpatched-internet-exposed-rdp")
    attrs = {
        "internet_exposed": True,
        "exposed_ports": [3389],
        "os_family": "windows",
        "os_unpatched": False,
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


def test_rdp_port_string_csv(tcr):
    rule = tcr.get_rule("unpatched-internet-exposed-rdp")
    attrs = {
        "internet_exposed": True,
        "exposed_ports": "22,80,3389",
        "os_family": "windows",
        "os_unpatched": True,
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is True


# ---------------------------------------------------------------------------
# Long-lived-access-key rule
# ---------------------------------------------------------------------------


def test_access_key_rule_matches(tcr):
    rule = tcr.get_rule("long-lived-access-key-on-production-admin")
    attrs = {
        "access_key_age_days": 120,
        "over_permissive": True,
        "environment": "production",
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is True


def test_access_key_under_90_days_does_not_match(tcr):
    rule = tcr.get_rule("long-lived-access-key-on-production-admin")
    attrs = {
        "access_key_age_days": 45,
        "over_permissive": True,
        "environment": "production",
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


def test_access_key_staging_does_not_match(tcr):
    rule = tcr.get_rule("long-lived-access-key-on-production-admin")
    attrs = {
        "access_key_age_days": 200,
        "over_permissive": True,
        "environment": "staging",
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


def test_access_key_invalid_age_is_not_matched(tcr):
    rule = tcr.get_rule("long-lived-access-key-on-production-admin")
    attrs = {
        "access_key_age_days": "not-a-number",
        "over_permissive": True,
        "environment": "production",
    }
    matched, _ = tcr.evaluate_combo(rule, attrs)
    assert matched is False


# ---------------------------------------------------------------------------
# evaluate_all
# ---------------------------------------------------------------------------


def test_evaluate_all_returns_empty_when_no_hits(tcr):
    results = tcr.evaluate_all({"random": "noise"})
    assert results == []


def test_evaluate_all_classic_attrs_flags_classic(tcr):
    attrs = {
        "internet_exposed": True,
        "critical_cve": ["CVE-2024-0001"],
        "over_permissive": True,
        "has_pii": True,
    }
    results = tcr.evaluate_all(attrs)
    assert any(r["combo_id"] == "internet-exposed-crit-cve-pii" and r["matched"] for r in results)


# ---------------------------------------------------------------------------
# ThreatCorrelationEngine — entity upsert + correlate_toxic_combos
# ---------------------------------------------------------------------------


def test_upsert_entity_creates_new(threat_engine):
    row = threat_engine.upsert_entity_attributes(
        "org1", "asset:ec2-1", {"internet_exposed": True}
    )
    assert row["entity_ref"] == "asset:ec2-1"
    assert row["attributes"]["internet_exposed"] is True


def test_upsert_entity_requires_ref(threat_engine):
    with pytest.raises(ValueError):
        threat_engine.upsert_entity_attributes("org1", "", {})


def test_upsert_entity_requires_dict(threat_engine):
    with pytest.raises(TypeError):
        threat_engine.upsert_entity_attributes("org1", "ref", "not-a-dict")


def test_upsert_is_idempotent(threat_engine):
    threat_engine.upsert_entity_attributes("org1", "asset:ec2-1", {"a": 1})
    threat_engine.upsert_entity_attributes("org1", "asset:ec2-1", {"a": 2, "b": 3})
    entities = threat_engine.list_entities("org1")
    refs = [e["entity_ref"] for e in entities]
    assert refs.count("asset:ec2-1") == 1
    only = [e for e in entities if e["entity_ref"] == "asset:ec2-1"][0]
    assert only["attributes"] == {"a": 2, "b": 3}


def test_correlate_empty_returns_empty(threat_engine):
    matches = threat_engine.correlate_toxic_combos("org1")
    assert matches == []


def test_correlate_single_toxic_entity(threat_engine):
    threat_engine.upsert_entity_attributes(
        "org1",
        "asset:ec2-crit",
        {
            "internet_exposed": True,
            "critical_cve": ["CVE-2024-0001"],
            "over_permissive": True,
            "has_pii": True,
        },
    )
    matches = threat_engine.correlate_toxic_combos("org1")
    ids = {m["combo_id"] for m in matches}
    assert "internet-exposed-crit-cve-pii" in ids


def test_correlate_dedup_via_unique_constraint(threat_engine):
    threat_engine.upsert_entity_attributes(
        "org1",
        "asset:ec2-crit",
        {
            "internet_exposed": True,
            "critical_cve": ["CVE-2024-0001"],
            "over_permissive": True,
            "has_pii": True,
        },
    )
    threat_engine.correlate_toxic_combos("org1")
    threat_engine.correlate_toxic_combos("org1")
    threat_engine.correlate_toxic_combos("org1")
    persisted = threat_engine.list_toxic_combo_matches(
        "org1", combo_id="internet-exposed-crit-cve-pii"
    )
    # Exactly one persisted row per (org_id, combo_id, entity_ref).
    matching = [p for p in persisted if p["entity_ref"] == "asset:ec2-crit"]
    assert len(matching) == 1


def test_correlate_multiple_rules_hit_one_entity(threat_engine):
    threat_engine.upsert_entity_attributes(
        "org1",
        "asset:super-bad",
        {
            "internet_exposed": True,
            "critical_cve": ["CVE-X"],
            "over_permissive": True,
            "has_pii": True,
            "is_object_store": True,
            "public_access": "public",
        },
    )
    matches = threat_engine.correlate_toxic_combos("org1")
    combo_ids = {m["combo_id"] for m in matches}
    assert "internet-exposed-crit-cve-pii" in combo_ids
    assert "public-s3-with-pii" in combo_ids


def test_list_matches_filters_by_combo_id(threat_engine):
    threat_engine.upsert_entity_attributes(
        "org1",
        "asset:1",
        {
            "internet_exposed": True,
            "critical_cve": ["c"],
            "over_permissive": True,
            "has_pii": True,
        },
    )
    threat_engine.correlate_toxic_combos("org1")
    same = threat_engine.list_toxic_combo_matches(
        "org1", combo_id="internet-exposed-crit-cve-pii"
    )
    other = threat_engine.list_toxic_combo_matches(
        "org1", combo_id="public-s3-with-pii"
    )
    assert len(same) >= 1
    assert other == []


def test_list_matches_filter_by_entity_ref(threat_engine):
    threat_engine.upsert_entity_attributes(
        "org1",
        "asset:A",
        {
            "internet_exposed": True,
            "critical_cve": ["c"],
            "over_permissive": True,
            "has_pii": True,
        },
    )
    threat_engine.upsert_entity_attributes(
        "org1",
        "asset:B",
        {
            "internet_exposed": True,
            "critical_cve": ["c"],
            "over_permissive": True,
            "has_pii": True,
        },
    )
    threat_engine.correlate_toxic_combos("org1")
    only_a = threat_engine.list_toxic_combo_matches("org1", entity_ref="asset:A")
    assert all(m["entity_ref"] == "asset:A" for m in only_a)


# ---------------------------------------------------------------------------
# Org-id isolation
# ---------------------------------------------------------------------------


def test_org_isolation(fresh_engines):
    tce = fresh_engines["tce"]
    e1 = tce.ThreatCorrelationEngine.for_org("orgA")
    e2 = tce.ThreatCorrelationEngine.for_org("orgB")
    e1.upsert_entity_attributes(
        "orgA",
        "asset:X",
        {
            "internet_exposed": True,
            "critical_cve": ["c"],
            "over_permissive": True,
            "has_pii": True,
        },
    )
    e1.correlate_toxic_combos("orgA")
    matches_b = e2.list_toxic_combo_matches("orgB")
    assert matches_b == []


# ---------------------------------------------------------------------------
# AttackChainEngine.build_chain_from_toxic_combo
# ---------------------------------------------------------------------------


def test_build_chain_from_toxic_combo_happy_path(threat_engine, attack_engine):
    threat_engine.upsert_entity_attributes(
        "org1",
        "asset:ec2-crit",
        {
            "internet_exposed": True,
            "critical_cve": ["CVE-2024-0001"],
            "over_permissive": True,
            "has_pii": True,
        },
    )
    threat_engine.correlate_toxic_combos("org1")
    match = threat_engine.list_toxic_combo_matches(
        "org1", combo_id="internet-exposed-crit-cve-pii"
    )[0]

    result = attack_engine.build_chain_from_toxic_combo(
        "org1", match["id"], threat_correlation_engine=threat_engine
    )
    assert result["chain_id"]
    assert result["steps_added"] == 4

    # Chain exists and has the expected number of steps.
    chain = attack_engine.get_chain("org1", result["chain_id"])
    assert chain is not None
    steps = attack_engine.list_chain_steps("org1", result["chain_id"])
    assert len(steps) == 4

    # Back-reference: match now has attack_chain_id set.
    updated = threat_engine.get_toxic_combo_match("org1", match["id"])
    assert updated["attack_chain_id"] == result["chain_id"]


def test_build_chain_unknown_match_raises(attack_engine, threat_engine):
    with pytest.raises(KeyError):
        attack_engine.build_chain_from_toxic_combo(
            "org1", "no-such-match", threat_correlation_engine=threat_engine
        )


def test_build_chain_missing_match_id_raises(attack_engine, threat_engine):
    with pytest.raises(ValueError):
        attack_engine.build_chain_from_toxic_combo(
            "org1", "", threat_correlation_engine=threat_engine
        )


# ---------------------------------------------------------------------------
# SecurityEventCorrelationEngine.on_toxic_combo_matched
# ---------------------------------------------------------------------------


def test_on_toxic_combo_matched_creates_event_and_incident(sec_engine):
    match = {
        "id": "match-1",
        "combo_id": "internet-exposed-crit-cve-pii",
        "entity_ref": "asset:ec2-1",
        "severity": "critical",
        "matched_attributes": ["reachable", "cve", "admin", "pii"],
    }
    result = sec_engine.on_toxic_combo_matched("org1", match)
    assert result["created_event"] is True
    assert result["created_incident"] is True
    assert result["severity"] == "critical"


def test_on_toxic_combo_matched_dedup_on_repeat(sec_engine):
    match = {
        "id": "match-42",
        "combo_id": "public-s3-with-pii",
        "entity_ref": "bucket:exposed",
        "severity": "critical",
        "matched_attributes": ["public", "pii"],
    }
    r1 = sec_engine.on_toxic_combo_matched("org1", match)
    r2 = sec_engine.on_toxic_combo_matched("org1", match)
    assert r1["created_event"] is True
    assert r2["created_event"] is False
    assert r1["event_id"] == r2["event_id"]
    assert r1["incident_id"] == r2["incident_id"]


def test_on_toxic_combo_matched_requires_id(sec_engine):
    with pytest.raises(ValueError):
        sec_engine.on_toxic_combo_matched("org1", {"combo_id": "c"})


def test_on_toxic_combo_matched_requires_dict(sec_engine):
    with pytest.raises(TypeError):
        sec_engine.on_toxic_combo_matched("org1", "not-a-dict")


def test_on_toxic_combo_matched_invalid_severity_coerces_to_high(sec_engine):
    match = {
        "id": "m-sev",
        "combo_id": "x",
        "entity_ref": "e",
        "severity": "mega-ultra-bad",
    }
    r = sec_engine.on_toxic_combo_matched("org1", match)
    assert r["severity"] == "high"


# ---------------------------------------------------------------------------
# End-to-end: correlate → event-correlation mirror
# ---------------------------------------------------------------------------


def test_correlate_populates_downstream_security_event(
    fresh_engines, threat_engine, tmp_path, monkeypatch
):
    """Ensure correlate_toxic_combos triggers on_toxic_combo_matched downstream."""
    import core.security_event_correlation_engine as sec_ece

    captured = []

    def fake_on(self, org_id, m):
        captured.append((org_id, m["combo_id"]))
        return {
            "event_id": "e",
            "incident_id": "i",
            "created_event": True,
            "created_incident": True,
            "severity": m.get("severity", "high"),
        }

    monkeypatch.setattr(
        sec_ece.SecurityEventCorrelationEngine,
        "on_toxic_combo_matched",
        fake_on,
    )

    threat_engine.upsert_entity_attributes(
        "orgZ",
        "asset:demo",
        {
            "internet_exposed": True,
            "critical_cve": ["x"],
            "over_permissive": True,
            "has_pii": True,
        },
    )
    threat_engine.correlate_toxic_combos("orgZ")
    assert any(
        org == "orgZ" and combo == "internet-exposed-crit-cve-pii"
        for org, combo in captured
    )


# ---------------------------------------------------------------------------
# Router smoke tests (FastAPI TestClient)
# ---------------------------------------------------------------------------


@pytest.fixture
def api_client(fresh_engines, tmp_path, monkeypatch):
    """Build a tiny FastAPI app mounting only the toxic_combo_router,
    isolated from the full 568-router app.py so tests stay fast.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Ensure imports resolve.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from apps.api import toxic_combo_router as mod  # noqa: F401

    # Monkeypatch the engine to use tmp_path-based threat engine.
    def _fake_get_engine(org_id):
        return fresh_engines["tce"].ThreatCorrelationEngine.for_org(org_id)

    monkeypatch.setattr(mod, "_get_engine", _fake_get_engine)

    app = FastAPI()
    app.include_router(mod.router)

    # Bypass api_key_auth for router smoke tests.
    async def _noop_auth():
        return "test-user"

    app.dependency_overrides[mod.api_key_auth] = _noop_auth
    return TestClient(app)


def test_router_rules_catalog(api_client):
    resp = api_client.get("/api/v1/toxic-combo/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 5
    assert len(data["rules"]) == 5


def test_router_simulate_classic_match(api_client):
    body = {
        "entity_attributes": {
            "internet_exposed": True,
            "critical_cve": ["CVE-2024-X"],
            "over_permissive": True,
            "has_pii": True,
        }
    }
    resp = api_client.post("/api/v1/toxic-combo/simulate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["matched_count"] >= 1
    classic = [r for r in data["results"] if r["combo_id"] == "internet-exposed-crit-cve-pii"][0]
    assert classic["matched"] is True


def test_router_simulate_no_match(api_client):
    resp = api_client.post(
        "/api/v1/toxic-combo/simulate",
        json={"entity_attributes": {"unrelated": True}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["matched_count"] == 0


def test_router_evaluate_flow(api_client):
    resp = api_client.post(
        "/api/v1/toxic-combo/evaluate?org_id=org_router_1",
        json={
            "entities": [
                {
                    "entity_ref": "asset:e1",
                    "attributes": {
                        "internet_exposed": True,
                        "critical_cve": ["c"],
                        "over_permissive": True,
                        "has_pii": True,
                    },
                }
            ]
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_matches"] >= 1
    assert data["by_combo"].get("internet-exposed-crit-cve-pii", 0) >= 1


def test_router_evaluate_rejects_bad_entity(api_client):
    resp = api_client.post(
        "/api/v1/toxic-combo/evaluate?org_id=org_router_bad",
        json={"entities": [{"entity_ref": "", "attributes": {}}]},
    )
    assert resp.status_code == 400


def test_router_matches_endpoint(api_client):
    # First, make a match.
    api_client.post(
        "/api/v1/toxic-combo/evaluate?org_id=org_router_m",
        json={
            "entities": [
                {
                    "entity_ref": "asset:m1",
                    "attributes": {
                        "internet_exposed": True,
                        "critical_cve": ["c"],
                        "over_permissive": True,
                        "has_pii": True,
                    },
                }
            ]
        },
    )
    resp = api_client.get("/api/v1/toxic-combo/matches?org_id=org_router_m")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] >= 1
    assert any(m["combo_id"] == "internet-exposed-crit-cve-pii" for m in data["matches"])
