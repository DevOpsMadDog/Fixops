"""Tests for CyberThreatModelingEngine.

Covers: full risk_level matrix, risk_score unmitigated-only average,
mitigate idempotency, mitigated_count increment, path_steps JSON,
threat_actor target_assets/tactics JSON, org isolation, summary, finalize.
"""
from __future__ import annotations

import json
import pytest

from core.cyber_threat_modeling_engine import CyberThreatModelingEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ctm_test.db")
    return CyberThreatModelingEngine(db_path=db)


def _make_model(engine, org_id="org1", model_type="application"):
    return engine.create_model(
        org_id=org_id,
        model_name="Test Model",
        system_name="Test System",
        model_type=model_type,
        scope="Full scope",
        created_by="tester",
    )


def _add_tree(engine, model_id, org_id="org1", likelihood="medium", impact="medium"):
    return engine.add_attack_tree(
        model_id=model_id,
        org_id=org_id,
        root_goal="Exfiltrate data",
        attack_vector="phishing",
        likelihood=likelihood,
        impact=impact,
        path_steps=["recon", "deliver", "exploit"],
    )


# ---------------------------------------------------------------------------
# Model creation
# ---------------------------------------------------------------------------

class TestCreateModel:
    def test_model_created_with_draft_status(self, engine):
        m = _make_model(engine)
        assert m["status"] == "draft"

    def test_model_initial_threat_count_zero(self, engine):
        m = _make_model(engine)
        assert m["threat_count"] == 0

    def test_model_initial_risk_score_zero(self, engine):
        m = _make_model(engine)
        assert m["risk_score"] == 0.0

    def test_model_has_id_and_org(self, engine):
        m = _make_model(engine, org_id="orgX")
        assert m["id"]
        assert m["org_id"] == "orgX"


# ---------------------------------------------------------------------------
# Risk level matrix — full coverage
# ---------------------------------------------------------------------------

class TestRiskLevelMatrix:
    @pytest.mark.parametrize("likelihood,impact,expected", [
        ("critical", "critical", "critical"),
        ("critical", "high",     "critical"),
        ("critical", "medium",   "high"),
        ("critical", "low",      "high"),
        ("high",     "critical", "critical"),
        ("high",     "high",     "high"),
        ("high",     "medium",   "high"),
        ("high",     "low",      "medium"),
        ("medium",   "critical", "high"),
        ("medium",   "high",     "high"),
        ("medium",   "medium",   "medium"),
        ("medium",   "low",      "low"),
        ("low",      "critical", "high"),
        ("low",      "high",     "medium"),
        ("low",      "medium",   "low"),
        ("low",      "low",      "low"),
    ])
    def test_risk_matrix(self, engine, likelihood, impact, expected):
        m = _make_model(engine)
        tree = engine.add_attack_tree(
            model_id=m["id"], org_id="org1",
            root_goal="Goal", attack_vector="vector",
            likelihood=likelihood, impact=impact,
            path_steps=["step1"],
        )
        assert tree["risk_level"] == expected


# ---------------------------------------------------------------------------
# Attack tree — path_steps JSON
# ---------------------------------------------------------------------------

class TestAttackTree:
    def test_path_steps_stored_as_list(self, engine):
        m = _make_model(engine)
        steps = ["recon", "weaponize", "deliver", "exploit", "c2"]
        tree = engine.add_attack_tree(
            model_id=m["id"], org_id="org1",
            root_goal="Full chain", attack_vector="spear-phishing",
            likelihood="high", impact="high",
            path_steps=steps,
        )
        assert tree["path_steps"] == steps

    def test_threat_count_incremented(self, engine):
        m = _make_model(engine)
        _add_tree(engine, m["id"])
        _add_tree(engine, m["id"])
        detail = engine.get_model_detail(m["id"], "org1")
        assert detail["threat_count"] == 2

    def test_risk_score_avg_of_unmitigated(self, engine):
        m = _make_model(engine)
        # critical=4, medium=2 → avg = 3.0
        _add_tree(engine, m["id"], likelihood="critical", impact="critical")  # critical=4
        _add_tree(engine, m["id"], likelihood="medium", impact="medium")      # medium=2
        detail = engine.get_model_detail(m["id"], "org1")
        assert detail["risk_score"] == pytest.approx(3.0)

    def test_risk_score_only_unmitigated(self, engine):
        m = _make_model(engine)
        t1 = _add_tree(engine, m["id"], likelihood="critical", impact="critical")  # critical=4
        _add_tree(engine, m["id"], likelihood="low", impact="low")                  # low=1
        # Mitigate the low tree → only critical remains → score=4
        # Add and mitigate the low one
        t2 = _add_tree(engine, m["id"], likelihood="low", impact="low")
        engine.mitigate_tree(t2["id"], m["id"], "org1", "patch applied")
        detail = engine.get_model_detail(m["id"], "org1")
        # Unmitigated: critical(4) + low(1) → avg = 2.5
        # (t1=critical unmitigated, first t2=low unmitigated, second t2=low mitigated)
        # Actually we have 3 trees: critical, low, low(mitigated) → unmitigated: critical+low → (4+1)/2=2.5
        assert detail["risk_score"] == pytest.approx(2.5)

    def test_risk_score_zero_when_all_mitigated(self, engine):
        m = _make_model(engine)
        t = _add_tree(engine, m["id"], likelihood="high", impact="high")
        engine.mitigate_tree(t["id"], m["id"], "org1", "fixed")
        detail = engine.get_model_detail(m["id"], "org1")
        assert detail["risk_score"] == 0.0

    def test_org_isolation_add_tree(self, engine):
        m = _make_model(engine, org_id="org_a")
        # Adding tree with wrong org still works (model lookup uses org_id in recompute)
        # but model detail for org_b should not see it
        t = engine.add_attack_tree(
            model_id=m["id"], org_id="org_b",
            root_goal="Goal", attack_vector="vector",
            likelihood="high", impact="high", path_steps=[],
        )
        detail_a = engine.get_model_detail(m["id"], "org_a")
        # Trees belong to org_b, model to org_a → model_detail queries trees by org_id
        assert len(detail_a["attack_trees"]) == 0


# ---------------------------------------------------------------------------
# Mitigate — idempotency and counter
# ---------------------------------------------------------------------------

class TestMitigate:
    def test_mitigate_sets_mitigated_flag(self, engine):
        m = _make_model(engine)
        t = _add_tree(engine, m["id"])
        result = engine.mitigate_tree(t["id"], m["id"], "org1", "Applied patch")
        assert result["mitigated"] == 1

    def test_mitigate_stores_mitigation_text(self, engine):
        m = _make_model(engine)
        t = _add_tree(engine, m["id"])
        result = engine.mitigate_tree(t["id"], m["id"], "org1", "Deploy WAF")
        assert result["mitigation"] == "Deploy WAF"

    def test_mitigate_increments_mitigated_count_once(self, engine):
        m = _make_model(engine)
        t = _add_tree(engine, m["id"])
        engine.mitigate_tree(t["id"], m["id"], "org1", "fix")
        # Mitigate again (idempotent — should not double-count)
        engine.mitigate_tree(t["id"], m["id"], "org1", "fix again")
        detail = engine.get_model_detail(m["id"], "org1")
        assert detail["mitigated_count"] == 1

    def test_mitigate_idempotent_risk_score(self, engine):
        m = _make_model(engine)
        t = _add_tree(engine, m["id"])
        engine.mitigate_tree(t["id"], m["id"], "org1", "fix")
        score1 = engine.get_model_detail(m["id"], "org1")["risk_score"]
        engine.mitigate_tree(t["id"], m["id"], "org1", "fix again")
        score2 = engine.get_model_detail(m["id"], "org1")["risk_score"]
        assert score1 == score2

    def test_mitigate_unknown_tree_returns_none(self, engine):
        m = _make_model(engine)
        result = engine.mitigate_tree("nonexistent", m["id"], "org1", "fix")
        assert result is None

    def test_mitigate_recomputes_risk_score(self, engine):
        m = _make_model(engine)
        t = _add_tree(engine, m["id"], likelihood="critical", impact="critical")
        before = engine.get_model_detail(m["id"], "org1")["risk_score"]
        assert before == pytest.approx(4.0)
        engine.mitigate_tree(t["id"], m["id"], "org1", "mitigated")
        after = engine.get_model_detail(m["id"], "org1")["risk_score"]
        assert after == pytest.approx(0.0)

    def test_multiple_trees_partial_mitigation(self, engine):
        m = _make_model(engine)
        t1 = _add_tree(engine, m["id"], likelihood="critical", impact="critical")  # 4
        t2 = _add_tree(engine, m["id"], likelihood="high", impact="high")           # 3
        t3 = _add_tree(engine, m["id"], likelihood="low", impact="low")             # 1
        engine.mitigate_tree(t1["id"], m["id"], "org1", "patch")
        # Remaining unmitigated: high(3), low(1) → avg = 2.0
        detail = engine.get_model_detail(m["id"], "org1")
        assert detail["risk_score"] == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# Threat actors — JSON fields
# ---------------------------------------------------------------------------

class TestThreatActor:
    def test_target_assets_stored_as_list(self, engine):
        m = _make_model(engine)
        assets = ["Database", "API Gateway", "S3 Bucket"]
        actor = engine.add_threat_actor(
            model_id=m["id"], org_id="org1",
            actor_name="APT28", actor_type="nation_state",
            motivation="espionage", capability="sophisticated",
            target_assets=assets, tactics=["T1059", "T1566"],
        )
        assert actor["target_assets"] == assets

    def test_tactics_stored_as_list(self, engine):
        m = _make_model(engine)
        tactics = ["T1059", "T1566", "T1486"]
        actor = engine.add_threat_actor(
            model_id=m["id"], org_id="org1",
            actor_name="Lazarus", actor_type="nation_state",
            motivation="financial", capability="sophisticated",
            target_assets=["Banks"], tactics=tactics,
        )
        assert actor["tactics"] == tactics

    def test_actor_has_id_and_model_id(self, engine):
        m = _make_model(engine)
        actor = engine.add_threat_actor(
            model_id=m["id"], org_id="org1",
            actor_name="Actor", actor_type="criminal",
            motivation="financial", capability="moderate",
            target_assets=[], tactics=[],
        )
        assert actor["id"]
        assert actor["model_id"] == m["id"]

    def test_actor_appears_in_model_detail(self, engine):
        m = _make_model(engine)
        engine.add_threat_actor(
            model_id=m["id"], org_id="org1",
            actor_name="Actor1", actor_type="insider",
            motivation="revenge", capability="basic",
            target_assets=["HR system"], tactics=["T1078"],
        )
        detail = engine.get_model_detail(m["id"], "org1")
        assert len(detail["threat_actors"]) == 1
        assert detail["threat_actors"][0]["actor_name"] == "Actor1"
        assert isinstance(detail["threat_actors"][0]["target_assets"], list)
        assert isinstance(detail["threat_actors"][0]["tactics"], list)


# ---------------------------------------------------------------------------
# Finalize model
# ---------------------------------------------------------------------------

class TestFinalizeModel:
    def test_finalize_sets_status_finalized(self, engine):
        m = _make_model(engine)
        result = engine.finalize_model(m["id"], "org1", "ciso@example.com")
        assert result["status"] == "finalized"

    def test_finalize_stores_reviewed_by(self, engine):
        m = _make_model(engine)
        result = engine.finalize_model(m["id"], "org1", "reviewer@example.com")
        assert result["reviewed_by"] == "reviewer@example.com"

    def test_finalize_unknown_model_returns_none(self, engine):
        result = engine.finalize_model("nonexistent", "org1", "reviewer")
        assert result is None

    def test_finalize_org_isolation(self, engine):
        m = _make_model(engine, org_id="org_a")
        result = engine.finalize_model(m["id"], "org_b", "reviewer")
        assert result is None


# ---------------------------------------------------------------------------
# Get unmitigated threats
# ---------------------------------------------------------------------------

class TestGetUnmitigated:
    def test_unmitigated_includes_model_name(self, engine):
        m = _make_model(engine)
        _add_tree(engine, m["id"])
        unmitigated = engine.get_unmitigated_threats("org1")
        assert len(unmitigated) == 1
        assert unmitigated[0]["model_name"] == "Test Model"

    def test_mitigated_excluded(self, engine):
        m = _make_model(engine)
        t = _add_tree(engine, m["id"])
        engine.mitigate_tree(t["id"], m["id"], "org1", "fixed")
        unmitigated = engine.get_unmitigated_threats("org1")
        assert len(unmitigated) == 0

    def test_path_steps_deserialized(self, engine):
        m = _make_model(engine)
        _add_tree(engine, m["id"])
        unmitigated = engine.get_unmitigated_threats("org1")
        assert isinstance(unmitigated[0]["path_steps"], list)

    def test_org_isolation(self, engine):
        m = _make_model(engine, org_id="org_a")
        engine.add_attack_tree(
            model_id=m["id"], org_id="org_a",
            root_goal="Goal", attack_vector="vec",
            likelihood="high", impact="high", path_steps=[],
        )
        unmitigated = engine.get_unmitigated_threats("org_b")
        assert len(unmitigated) == 0


# ---------------------------------------------------------------------------
# Model summary
# ---------------------------------------------------------------------------

class TestModelSummary:
    def test_summary_total_models(self, engine):
        _make_model(engine, org_id="org1", model_type="application")
        _make_model(engine, org_id="org1", model_type="cloud")
        summary = engine.get_model_summary("org1")
        assert summary["total_models"] == 2

    def test_summary_by_type(self, engine):
        _make_model(engine, org_id="org1", model_type="application")
        _make_model(engine, org_id="org1", model_type="application")
        _make_model(engine, org_id="org1", model_type="cloud")
        summary = engine.get_model_summary("org1")
        assert summary["by_type"]["application"] == 2
        assert summary["by_type"]["cloud"] == 1

    def test_summary_total_threats(self, engine):
        m = _make_model(engine)
        _add_tree(engine, m["id"])
        _add_tree(engine, m["id"])
        summary = engine.get_model_summary("org1")
        assert summary["total_threats"] == 2

    def test_summary_unmitigated_count(self, engine):
        m = _make_model(engine)
        t1 = _add_tree(engine, m["id"])
        _add_tree(engine, m["id"])
        engine.mitigate_tree(t1["id"], m["id"], "org1", "patch")
        summary = engine.get_model_summary("org1")
        assert summary["unmitigated_count"] == 1

    def test_summary_critical_models_threshold(self, engine):
        m = _make_model(engine)
        # Add critical+critical tree → risk_score = 4.0 >= 3.5 → critical model
        _add_tree(engine, m["id"], likelihood="critical", impact="critical")
        summary = engine.get_model_summary("org1")
        assert summary["critical_models"] == 1

    def test_summary_non_critical_model(self, engine):
        m = _make_model(engine)
        # medium+medium → risk_score = 2.0 < 3.5
        _add_tree(engine, m["id"], likelihood="medium", impact="medium")
        summary = engine.get_model_summary("org1")
        assert summary["critical_models"] == 0

    def test_summary_org_isolation(self, engine):
        _make_model(engine, org_id="org_a")
        _make_model(engine, org_id="org_b")
        summary = engine.get_model_summary("org_a")
        assert summary["total_models"] == 1

    def test_summary_empty_org(self, engine):
        summary = engine.get_model_summary("empty_org")
        assert summary["total_models"] == 0
        assert summary["total_threats"] == 0
        assert summary["avg_risk_score"] == 0.0
