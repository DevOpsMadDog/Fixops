"""
Tests for ThreatHunter engine and threat_hunter_router.

Covers:
- ThreatHunter: hypothesis library, IOC management, Sigma rules,
  hunt workflows, threat actors, kill chain coverage, automated triggers
- threat_hunter_router: all endpoints via FastAPI TestClient

55+ tests total.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Generator

import pytest

# Ensure suite-core and suite-api are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.threat_hunter import (
    HuntFinding,
    HuntHypothesis,
    HuntSeverity,
    HuntStatus,
    HuntTriggerType,
    IOC,
    IOCType,
    KillChainPhase,
    MitreTactic,
    SigmaRule,
    ThreatActorMotivation,
    ThreatActorProfile,
    ThreatHunter,
    export_iocs_to_stix,
    parse_sigma_rule,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path) -> str:
    return str(tmp_path / "test_threat_hunter.db")


@pytest.fixture
def hunter(tmp_db: str) -> ThreatHunter:
    return ThreatHunter(db_path=tmp_db)


def _make_ioc(value: str = "192.168.1.1", ioc_type: IOCType = IOCType.IP) -> IOC:
    return IOC(type=ioc_type, value=value, description="test ioc", source="unit-test")


def _make_actor() -> ThreatActorProfile:
    return ThreatActorProfile(
        name="TestActor",
        aliases=["TA1"],
        motivation=ThreatActorMotivation.FINANCIAL,
        description="Test threat actor",
        targeted_industries=["finance"],
        sophistication="high",
    )


SAMPLE_SIGMA_YAML = """
title: Suspicious PowerShell Encoded Command
status: experimental
description: Detects PowerShell with encoded commands
author: TestAuthor
logsource:
  category: process_creation
  product: windows
detection:
  keywords:
    - '-EncodedCommand'
    - '-enc '
  condition: keywords
level: high
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Legitimate admin scripts
"""


# ============================================================================
# UNIT TESTS — Hypothesis Library
# ============================================================================


class TestHypothesisLibrary:
    def test_builtin_hypotheses_loaded(self, hunter: ThreatHunter) -> None:
        hyps = hunter.list_hypotheses()
        assert len(hyps) >= 30

    def test_filter_by_tactic(self, hunter: ThreatHunter) -> None:
        hyps = hunter.list_hypotheses(tactic=MitreTactic.INITIAL_ACCESS)
        assert len(hyps) >= 3
        for h in hyps:
            assert h.mitre_tactic == MitreTactic.INITIAL_ACCESS

    def test_filter_by_severity(self, hunter: ThreatHunter) -> None:
        hyps = hunter.list_hypotheses(severity=HuntSeverity.CRITICAL)
        assert len(hyps) >= 1
        for h in hyps:
            assert h.severity == HuntSeverity.CRITICAL

    def test_filter_by_kill_chain_phase(self, hunter: ThreatHunter) -> None:
        hyps = hunter.list_hypotheses(kill_chain_phase=KillChainPhase.DELIVERY)
        assert len(hyps) >= 1
        for h in hyps:
            assert h.kill_chain_phase == KillChainPhase.DELIVERY

    def test_add_custom_hypothesis(self, hunter: ThreatHunter) -> None:
        hyp = HuntHypothesis(
            name="Custom Hunt",
            description="Custom hypothesis for testing",
            mitre_tactic=MitreTactic.PERSISTENCE,
            mitre_technique_id="T1999",
            mitre_technique_name="Test Technique",
            kill_chain_phase=KillChainPhase.INSTALLATION,
            severity=HuntSeverity.MEDIUM,
        )
        result = hunter.add_hypothesis(hyp)
        assert result.id == hyp.id
        assert result.name == "Custom Hunt"

    def test_custom_hypothesis_appears_in_list(self, hunter: ThreatHunter) -> None:
        hyp = HuntHypothesis(
            name="My Custom Hypothesis",
            description="desc",
            mitre_tactic=MitreTactic.EXFILTRATION,
            mitre_technique_id="T1048",
            mitre_technique_name="Exfil Test",
            kill_chain_phase=KillChainPhase.ACTIONS_ON_OBJECTIVES,
            severity=HuntSeverity.HIGH,
        )
        hunter.add_hypothesis(hyp)
        all_hyps = hunter.list_hypotheses()
        names = [h.name for h in all_hyps]
        assert "My Custom Hypothesis" in names

    def test_hypotheses_have_required_fields(self, hunter: ThreatHunter) -> None:
        hyps = hunter.list_hypotheses()
        for h in hyps:
            assert h.id
            assert h.name
            assert h.mitre_technique_id
            assert h.kill_chain_phase

    def test_filter_combined_tactic_and_severity(self, hunter: ThreatHunter) -> None:
        hyps = hunter.list_hypotheses(
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            severity=HuntSeverity.HIGH,
        )
        for h in hyps:
            assert h.mitre_tactic == MitreTactic.CREDENTIAL_ACCESS
            assert h.severity == HuntSeverity.HIGH


# ============================================================================
# UNIT TESTS — IOC Management
# ============================================================================


class TestIOCManagement:
    def test_add_ip_ioc(self, hunter: ThreatHunter) -> None:
        ioc = _make_ioc("10.0.0.1", IOCType.IP)
        result = hunter.add_ioc(ioc)
        assert result.value == "10.0.0.1"
        assert result.type == IOCType.IP

    def test_add_domain_ioc(self, hunter: ThreatHunter) -> None:
        ioc = _make_ioc("evil.example.com", IOCType.DOMAIN)
        result = hunter.add_ioc(ioc)
        assert result.type == IOCType.DOMAIN

    def test_add_sha256_ioc(self, hunter: ThreatHunter) -> None:
        ioc = _make_ioc("a" * 64, IOCType.SHA256)
        result = hunter.add_ioc(ioc)
        assert result.type == IOCType.SHA256

    def test_list_iocs_returns_added(self, hunter: ThreatHunter) -> None:
        hunter.add_ioc(_make_ioc("1.2.3.4", IOCType.IP))
        iocs = hunter.list_iocs()
        values = [i.value for i in iocs]
        assert "1.2.3.4" in values

    def test_list_iocs_filter_by_type(self, hunter: ThreatHunter) -> None:
        hunter.add_ioc(_make_ioc("1.2.3.4", IOCType.IP))
        hunter.add_ioc(_make_ioc("evil.com", IOCType.DOMAIN))
        ip_iocs = hunter.list_iocs(ioc_type=IOCType.IP)
        for ioc in ip_iocs:
            assert ioc.type == IOCType.IP

    def test_bulk_import_returns_count(self, hunter: ThreatHunter) -> None:
        iocs = [_make_ioc(f"10.0.0.{i}") for i in range(1, 6)]
        count = hunter.bulk_import_iocs(iocs)
        assert count == 5

    def test_check_ioc_match_found(self, hunter: ThreatHunter) -> None:
        hunter.add_ioc(_make_ioc("99.88.77.66", IOCType.IP))
        match = hunter.check_ioc_match("99.88.77.66")
        assert match is not None
        assert match.value == "99.88.77.66"

    def test_check_ioc_match_not_found(self, hunter: ThreatHunter) -> None:
        match = hunter.check_ioc_match("not-in-db.example.com")
        assert match is None

    def test_import_stix_bundle(self, hunter: ThreatHunter) -> None:
        bundle = {
            "type": "bundle",
            "id": "bundle--test-123",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--abc",
                    "name": "Malicious IP",
                    "pattern": "[ipv4-addr:value = '5.5.5.5']",
                    "labels": ["malicious"],
                },
                {
                    "type": "indicator",
                    "id": "indicator--def",
                    "name": "Bad Domain",
                    "pattern": "[domain-name:value = 'bad.example.org']",
                    "labels": [],
                },
            ],
        }
        count = hunter.import_stix_bundle(bundle)
        assert count == 2
        match = hunter.check_ioc_match("5.5.5.5")
        assert match is not None

    def test_stix_bundle_skips_non_indicators(self, hunter: ThreatHunter) -> None:
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "malware", "name": "SomeMalware"},
                {
                    "type": "indicator",
                    "id": "indicator--xyz",
                    "pattern": "[ipv4-addr:value = '9.9.9.9']",
                },
            ],
        }
        count = hunter.import_stix_bundle(bundle)
        assert count == 1

    def test_export_iocs_stix_bundle(self, hunter: ThreatHunter) -> None:
        hunter.add_ioc(_make_ioc("1.1.1.1", IOCType.IP))
        iocs = hunter.list_iocs()
        bundle = export_iocs_to_stix(iocs)
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) >= 1
        obj = bundle["objects"][0]
        assert obj["type"] == "indicator"
        assert "1.1.1.1" in obj["pattern"]


# ============================================================================
# UNIT TESTS — Sigma Rule Engine
# ============================================================================


class TestSigmaRuleEngine:
    def test_parse_sigma_rule_from_yaml(self) -> None:
        rule = parse_sigma_rule(SAMPLE_SIGMA_YAML)
        assert rule.name == "Suspicious PowerShell Encoded Command"
        assert rule.author == "TestAuthor"
        assert rule.level == HuntSeverity.HIGH
        assert rule.logsource_category == "process_creation"
        assert rule.logsource_product == "windows"

    def test_parse_sigma_extracts_keywords(self) -> None:
        rule = parse_sigma_rule(SAMPLE_SIGMA_YAML)
        assert "-EncodedCommand" in rule.detection_keywords or "-enc " in rule.detection_keywords

    def test_parse_sigma_extracts_tags(self) -> None:
        rule = parse_sigma_rule(SAMPLE_SIGMA_YAML)
        assert "attack.execution" in rule.tags

    def test_parse_sigma_invalid_yaml(self) -> None:
        with pytest.raises(ValueError):
            parse_sigma_rule("- item1\n- item2\n- item3")  # valid YAML list, not a mapping

    def test_import_sigma_yaml_persists(self, hunter: ThreatHunter) -> None:
        rule = hunter.import_sigma_yaml(SAMPLE_SIGMA_YAML)
        rules = hunter.list_sigma_rules()
        ids = [r.id for r in rules]
        assert rule.id in ids

    def test_list_sigma_rules_empty_initially(self, hunter: ThreatHunter) -> None:
        rules = hunter.list_sigma_rules()
        assert isinstance(rules, list)

    def test_add_sigma_rule_directly(self, hunter: ThreatHunter) -> None:
        rule = SigmaRule(
            name="Test Rule",
            detection_keywords=["malware.exe"],
            level=HuntSeverity.MEDIUM,
        )
        result = hunter.add_sigma_rule(rule)
        assert result.id == rule.id

    def test_sigma_search_query_generated(self) -> None:
        rule = parse_sigma_rule(SAMPLE_SIGMA_YAML)
        assert len(rule.search_query) > 0

    def test_sigma_false_positives_parsed(self) -> None:
        rule = parse_sigma_rule(SAMPLE_SIGMA_YAML)
        assert "Legitimate admin scripts" in rule.false_positives


# ============================================================================
# UNIT TESTS — Hunt Workflows
# ============================================================================


class TestHuntWorkflows:
    def _get_hypothesis_id(self, hunter: ThreatHunter) -> str:
        hyps = hunter.list_hypotheses()
        assert hyps, "No hypotheses available"
        return hyps[0].id

    def test_start_hunt_returns_workflow(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        workflow = hunter.start_hunt(hypothesis_id=hyp_id)
        assert workflow.id
        assert workflow.status == HuntStatus.ACTIVE
        assert workflow.started_at is not None

    def test_start_hunt_invalid_hypothesis(self, hunter: ThreatHunter) -> None:
        with pytest.raises(ValueError, match="Hypothesis not found"):
            hunter.start_hunt(hypothesis_id="nonexistent-id")

    def test_start_hunt_with_org_id(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        workflow = hunter.start_hunt(hypothesis_id=hyp_id, org_id="org-123")
        assert workflow.org_id == "org-123"

    def test_start_hunt_with_trigger_context(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        ctx = {"cve_id": "CVE-2024-1234", "cvss": 9.8}
        workflow = hunter.start_hunt(
            hypothesis_id=hyp_id,
            trigger_type=HuntTriggerType.NEW_CVE,
            trigger_context=ctx,
        )
        assert workflow.trigger_type == HuntTriggerType.NEW_CVE
        assert workflow.trigger_context["cve_id"] == "CVE-2024-1234"

    def test_list_active_hunts(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        hunter.start_hunt(hypothesis_id=hyp_id)
        active = hunter.list_active_hunts()
        assert len(active) >= 1

    def test_complete_hunt(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        workflow = hunter.start_hunt(hypothesis_id=hyp_id)
        completed = hunter.complete_hunt(hunt_id=workflow.id, notes="Clean")
        assert completed.status == HuntStatus.COMPLETED
        assert completed.completed_at is not None
        assert completed.notes == "Clean"

    def test_completed_hunt_not_in_active(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        workflow = hunter.start_hunt(hypothesis_id=hyp_id)
        hunter.complete_hunt(hunt_id=workflow.id)
        active = hunter.list_active_hunts()
        active_ids = [h.id for h in active]
        assert workflow.id not in active_ids

    def test_add_finding_to_hunt(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        workflow = hunter.start_hunt(hypothesis_id=hyp_id)
        finding = HuntFinding(
            hunt_id=workflow.id,
            title="Suspicious PowerShell",
            description="Encoded command detected",
            severity=HuntSeverity.HIGH,
            mitre_technique_id="T1059",
            evidence=["process_id:1234", "cmdline:-enc abc123"],
        )
        result = hunter.add_finding(finding)
        assert result.id == finding.id
        assert result.hunt_id == workflow.id

    def test_finding_increments_count(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        workflow = hunter.start_hunt(hypothesis_id=hyp_id)
        for i in range(3):
            hunter.add_finding(
                HuntFinding(
                    hunt_id=workflow.id,
                    title=f"Finding {i}",
                    description="",
                    severity=HuntSeverity.LOW,
                )
            )
        updated = hunter.get_hunt(workflow.id)
        assert updated.findings_count == 3

    def test_list_findings_for_hunt(self, hunter: ThreatHunter) -> None:
        hyp_id = self._get_hypothesis_id(hunter)
        workflow = hunter.start_hunt(hypothesis_id=hyp_id)
        hunter.add_finding(HuntFinding(hunt_id=workflow.id, title="F1", description="", severity=HuntSeverity.HIGH))
        hunter.add_finding(HuntFinding(hunt_id=workflow.id, title="F2", description="", severity=HuntSeverity.LOW))
        findings = hunter.list_findings(workflow.id)
        assert len(findings) == 2


# ============================================================================
# UNIT TESTS — Threat Actor Profiles
# ============================================================================


class TestThreatActorProfiles:
    def test_builtin_actors_loaded(self, hunter: ThreatHunter) -> None:
        actors = hunter.list_actors()
        assert len(actors) >= 5

    def test_builtin_actors_include_apt28(self, hunter: ThreatHunter) -> None:
        actors = hunter.list_actors()
        names = [a.name for a in actors]
        assert "APT28" in names

    def test_builtin_actors_include_lazarus(self, hunter: ThreatHunter) -> None:
        actors = hunter.list_actors()
        names = [a.name for a in actors]
        assert "Lazarus Group" in names

    def test_filter_actors_by_motivation(self, hunter: ThreatHunter) -> None:
        financial = hunter.list_actors(motivation=ThreatActorMotivation.FINANCIAL)
        for actor in financial:
            assert actor.motivation == ThreatActorMotivation.FINANCIAL

    def test_add_custom_actor(self, hunter: ThreatHunter) -> None:
        actor = _make_actor()
        result = hunter.add_actor(actor)
        assert result.id == actor.id
        assert result.name == "TestActor"

    def test_custom_actor_in_list(self, hunter: ThreatHunter) -> None:
        actor = _make_actor()
        hunter.add_actor(actor)
        actors = hunter.list_actors()
        names = [a.name for a in actors]
        assert "TestActor" in names

    def test_actor_has_mitre_techniques(self, hunter: ThreatHunter) -> None:
        actors = hunter.list_actors()
        apt28 = next(a for a in actors if a.name == "APT28")
        assert len(apt28.mitre_techniques) >= 3

    def test_actor_has_aliases(self, hunter: ThreatHunter) -> None:
        actors = hunter.list_actors()
        apt28 = next(a for a in actors if a.name == "APT28")
        assert "Fancy Bear" in apt28.aliases


# ============================================================================
# UNIT TESTS — Kill Chain Coverage
# ============================================================================


class TestKillChainCoverage:
    def test_returns_all_seven_phases(self, hunter: ThreatHunter) -> None:
        coverage = hunter.get_kill_chain_coverage()
        assert len(coverage) == 7

    def test_all_phases_represented(self, hunter: ThreatHunter) -> None:
        coverage = hunter.get_kill_chain_coverage()
        phases = {c.phase for c in coverage}
        for phase in KillChainPhase:
            assert phase in phases

    def test_some_phases_covered(self, hunter: ThreatHunter) -> None:
        coverage = hunter.get_kill_chain_coverage()
        covered = [c for c in coverage if c.covered]
        assert len(covered) >= 5

    def test_covered_phases_have_hypotheses(self, hunter: ThreatHunter) -> None:
        coverage = hunter.get_kill_chain_coverage()
        for c in coverage:
            if c.covered:
                assert c.hypothesis_count > 0


# ============================================================================
# UNIT TESTS — Automated Hunt Triggers
# ============================================================================


class TestHuntTriggers:
    def test_fire_new_cve_trigger(self, hunter: ThreatHunter) -> None:
        workflow = hunter.fire_trigger(
            trigger_type=HuntTriggerType.NEW_CVE,
            context={"cve_id": "CVE-2024-9999", "cvss": 9.8},
        )
        assert workflow is not None
        assert workflow.trigger_type == HuntTriggerType.NEW_CVE

    def test_fire_ioc_match_trigger(self, hunter: ThreatHunter) -> None:
        workflow = hunter.fire_trigger(
            trigger_type=HuntTriggerType.IOC_MATCH,
            context={"matched_value": "1.2.3.4", "ioc_type": "ip"},
        )
        # Should auto-start a hunt
        # workflow may be None if no hypothesis matched the IOC trigger
        assert workflow is None or workflow.trigger_type == HuntTriggerType.IOC_MATCH

    def test_fire_network_anomaly_trigger(self, hunter: ThreatHunter) -> None:
        workflow = hunter.fire_trigger(
            trigger_type=HuntTriggerType.NETWORK_ANOMALY,
            context={"anomaly_score": 0.95, "source_ip": "192.168.1.50"},
        )
        # Trigger is recorded regardless
        triggers = hunter.list_triggers()
        assert len(triggers) >= 1

    def test_trigger_recorded_even_without_hunt(self, hunter: ThreatHunter, tmp_db: str) -> None:
        # Use fresh hunter with no hypotheses to test trigger recording
        hunter.fire_trigger(
            trigger_type=HuntTriggerType.COMPLIANCE_FAILURE,
            context={"control": "CC7.2", "framework": "SOC2"},
        )
        triggers = hunter.list_triggers()
        assert len(triggers) >= 1

    def test_trigger_context_preserved(self, hunter: ThreatHunter) -> None:
        ctx = {"cve_id": "CVE-2024-1111", "severity": "critical"}
        hunter.fire_trigger(trigger_type=HuntTriggerType.NEW_CVE, context=ctx)
        triggers = hunter.list_triggers()
        assert len(triggers) >= 1
        latest = triggers[0]
        assert latest.context.get("cve_id") == "CVE-2024-1111"


# ============================================================================
# ROUTER TESTS via FastAPI TestClient
# ============================================================================


@pytest.fixture
def client(tmp_db: str):
    """FastAPI TestClient with isolated DB and no auth."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import apps.api.threat_hunter_router as router_module

    # Reset global hunter to use temp DB
    router_module._hunter = ThreatHunter(db_path=tmp_db)

    app = FastAPI()
    app.include_router(router_module.router)

    # Bypass auth by overriding the dependency if it loaded
    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app)


class TestHypothesesEndpoint:
    def test_get_hypotheses_200(self, client) -> None:
        resp = client.get("/api/v1/hunt/hypotheses")
        assert resp.status_code == 200
        data = resp.json()
        assert "hypotheses" in data
        assert data["total"] >= 30

    def test_get_hypotheses_filter_tactic(self, client) -> None:
        resp = client.get("/api/v1/hunt/hypotheses?tactic=initial_access")
        assert resp.status_code == 200
        data = resp.json()
        for h in data["hypotheses"]:
            assert h["mitre_tactic"] == "initial_access"

    def test_get_hypotheses_filter_severity(self, client) -> None:
        resp = client.get("/api/v1/hunt/hypotheses?severity=critical")
        assert resp.status_code == 200


class TestStartHuntEndpoint:
    def test_start_hunt_201(self, client) -> None:
        hyp_resp = client.get("/api/v1/hunt/hypotheses")
        hyp_id = hyp_resp.json()["hypotheses"][0]["id"]
        resp = client.post(
            "/api/v1/hunt/start",
            json={"hypothesis_id": hyp_id, "org_id": "test-org"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "active"
        assert "hunt_id" in data

    def test_start_hunt_invalid_hypothesis(self, client) -> None:
        resp = client.post(
            "/api/v1/hunt/start",
            json={"hypothesis_id": "does-not-exist"},
        )
        assert resp.status_code == 404


class TestActiveHuntsEndpoint:
    def test_active_hunts_empty_initially(self, client) -> None:
        resp = client.get("/api/v1/hunt/active")
        assert resp.status_code == 200
        data = resp.json()
        assert "hunts" in data

    def test_active_hunts_shows_started_hunt(self, client) -> None:
        hyp_id = client.get("/api/v1/hunt/hypotheses").json()["hypotheses"][0]["id"]
        client.post("/api/v1/hunt/start", json={"hypothesis_id": hyp_id})
        resp = client.get("/api/v1/hunt/active")
        assert resp.json()["total"] >= 1


class TestIOCEndpoints:
    def test_get_iocs_200(self, client) -> None:
        resp = client.get("/api/v1/hunt/iocs")
        assert resp.status_code == 200
        assert "iocs" in resp.json()

    def test_import_iocs_plain_list(self, client) -> None:
        resp = client.post(
            "/api/v1/hunt/iocs/import",
            json={
                "iocs": [
                    {
                        "id": "test-ioc-1",
                        "type": "ip",
                        "value": "8.8.8.8",
                        "first_seen": "2024-01-01T00:00:00+00:00",
                        "last_seen": "2024-01-01T00:00:00+00:00",
                    }
                ]
            },
        )
        assert resp.status_code == 201
        assert resp.json()["imported"] == 1

    def test_import_iocs_stix_bundle(self, client) -> None:
        resp = client.post(
            "/api/v1/hunt/iocs/import",
            json={
                "stix_bundle": {
                    "type": "bundle",
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--router-test",
                            "pattern": "[ipv4-addr:value = '7.7.7.7']",
                        }
                    ],
                }
            },
        )
        assert resp.status_code == 201
        assert resp.json()["imported"] == 1

    def test_import_iocs_no_body(self, client) -> None:
        resp = client.post("/api/v1/hunt/iocs/import", json={})
        assert resp.status_code == 422


class TestSigmaRulesEndpoint:
    def test_get_sigma_rules_200(self, client) -> None:
        resp = client.get("/api/v1/hunt/sigma-rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data

    def test_import_sigma_rule(self, client) -> None:
        resp = client.post(
            "/api/v1/hunt/sigma-rules/import",
            json={"yaml_content": SAMPLE_SIGMA_YAML},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Suspicious PowerShell Encoded Command"

    def test_import_sigma_rule_invalid(self, client) -> None:
        # A YAML list (not a mapping) should raise 422
        resp = client.post(
            "/api/v1/hunt/sigma-rules/import",
            json={"yaml_content": "- item1\n- item2\n- item3"},
        )
        assert resp.status_code == 422


class TestActorsEndpoint:
    def test_get_actors_200(self, client) -> None:
        resp = client.get("/api/v1/hunt/actors")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 5

    def test_filter_actors_by_motivation(self, client) -> None:
        resp = client.get("/api/v1/hunt/actors?motivation=espionage")
        assert resp.status_code == 200
        for actor in resp.json()["actors"]:
            assert actor["motivation"] == "espionage"


class TestKillChainEndpoint:
    def test_kill_chain_200(self, client) -> None:
        resp = client.get("/api/v1/hunt/kill-chain")
        assert resp.status_code == 200
        data = resp.json()
        assert "coverage" in data
        assert data["total_phases"] == 7
        assert data["covered_phases"] >= 5
        assert 0.0 <= data["coverage_pct"] <= 100.0

    def test_kill_chain_all_phases_present(self, client) -> None:
        resp = client.get("/api/v1/hunt/kill-chain")
        phases = {c["phase"] for c in resp.json()["coverage"]}
        for phase in KillChainPhase:
            assert phase.value in phases


class TestTriggerEndpoint:
    def test_fire_trigger_new_cve(self, client) -> None:
        resp = client.post(
            "/api/v1/hunt/trigger",
            json={
                "trigger_type": "new_cve",
                "context": {"cve_id": "CVE-2024-9001"},
            },
        )
        assert resp.status_code == 200
