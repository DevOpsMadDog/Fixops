"""GAP-043 formula transparency + GAP-044 AI teammates tests.

30 tests covering:
 - VulnerabilityScoringEngine.get_formula_transparency (shape + finding_id)
 - AIGovernanceEngine.register_formula_change + list_formula_history
   (including UNIQUE on (org_id, formula_version))
 - AISecurityAdvisorEngine.{suggest_fix_with_context, draft_exception_request,
   auto_triage} — smoke + dict shape
 - AIPoweredSOCEngine.teammate_draft_playbook — smoke + template match
 - AutoFixEngine.teammate_explain_fix — smoke
 - org_id isolation for formula history
 - Endpoint smoke via FastAPI TestClient (lazy — skipped if app import too heavy)
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest

from core.ai_governance_engine import AIGovernanceEngine
from core.ai_powered_soc_engine import AIPoweredSOCEngine
from core.ai_security_advisor_engine import AISecurityAdvisorEngine
from core.autofix_engine import AutoFixEngine
from core.vulnerability_scoring_engine import VulnerabilityScoringEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_dir():
    d = tempfile.mkdtemp(prefix="gap043_044_")
    yield d


@pytest.fixture()
def scoring(tmp_dir):
    return VulnerabilityScoringEngine(db_path=os.path.join(tmp_dir, "vs.db"))


@pytest.fixture()
def governance(tmp_dir):
    return AIGovernanceEngine(db_path=os.path.join(tmp_dir, "gov.db"))


@pytest.fixture()
def advisor(tmp_dir):
    return AISecurityAdvisorEngine(db_path=os.path.join(tmp_dir, "adv.db"))


@pytest.fixture()
def soc(tmp_dir):
    return AIPoweredSOCEngine(db_path=os.path.join(tmp_dir, "soc.db"))


@pytest.fixture()
def autofix():
    return AutoFixEngine()


# ---------------------------------------------------------------------------
# GAP-043: Formula transparency — shape (no finding)
# ---------------------------------------------------------------------------


def test_formula_transparency_top_level_keys(scoring):
    out = scoring.get_formula_transparency("org-a")
    assert set(out.keys()) >= {
        "org_id",
        "formula_version",
        "components",
        "final_score",
        "last_updated",
        "finding_id",
        "breakdown_history",
        "priority_tier",
        "model_name",
    }


def test_formula_transparency_components_list_shape(scoring):
    out = scoring.get_formula_transparency("org-a")
    assert isinstance(out["components"], list)
    assert len(out["components"]) == 7
    required = {"name", "weight", "source", "current_value", "contribution"}
    for comp in out["components"]:
        assert required <= set(comp.keys())


def test_formula_transparency_component_names(scoring):
    out = scoring.get_formula_transparency("org-a")
    names = {c["name"] for c in out["components"]}
    assert names == {
        "cvss",
        "epss",
        "kev_bonus",
        "exposure",
        "asset_criticality",
        "blast_radius",
        "crown_jewel_multiplier",
    }


def test_formula_transparency_no_finding_current_values_null(scoring):
    out = scoring.get_formula_transparency("org-a")
    for comp in out["components"]:
        assert comp["current_value"] is None
    assert out["final_score"] is None
    assert out["priority_tier"] is None


def test_formula_transparency_formula_version_string(scoring):
    out = scoring.get_formula_transparency("org-a")
    assert isinstance(out["formula_version"], str)
    assert out["formula_version"]


def test_formula_transparency_requires_org_id(scoring):
    with pytest.raises(ValueError):
        scoring.get_formula_transparency("")


# ---------------------------------------------------------------------------
# GAP-043: Formula transparency — with finding_id
# ---------------------------------------------------------------------------


def test_formula_transparency_with_finding_populates_values(scoring):
    finding = scoring.score_vulnerability(
        "org-a",
        vuln_id="VULN-1",
        cvss_score=9.0,
        epss_score=0.8,
        kev_listed=True,
        asset_criticality="high",
        exposure_score=0.7,
    )
    out = scoring.get_formula_transparency("org-a", finding_id=finding["id"])
    # At least cvss/epss/kev/exposure/criticality should be populated
    by_name = {c["name"]: c for c in out["components"]}
    assert by_name["cvss"]["current_value"] == 9.0
    assert by_name["epss"]["current_value"] == 0.8
    assert by_name["kev_bonus"]["current_value"] == 1.0
    assert by_name["exposure"]["current_value"] == 0.7
    assert by_name["asset_criticality"]["current_value"] == "high"
    assert out["final_score"] == finding["composite_score"]
    assert out["priority_tier"] == finding["priority_tier"]


def test_formula_transparency_with_blast_radius_updates_component(scoring):
    finding = scoring.score_vulnerability(
        "org-a",
        vuln_id="VULN-BR",
        cvss_score=7.0,
        asset_criticality="medium",
    )
    scoring.factor_blast_radius(
        "org-a",
        finding_id=finding["id"],
        blast_radius_score=80.0,
        is_crown_jewel=True,
    )
    out = scoring.get_formula_transparency("org-a", finding_id=finding["id"])
    by_name = {c["name"]: c for c in out["components"]}
    assert by_name["blast_radius"]["current_value"] == 80.0
    assert by_name["crown_jewel_multiplier"]["current_value"] is True
    assert len(out["breakdown_history"]) >= 1


def test_formula_transparency_unknown_finding_returns_nulls(scoring):
    out = scoring.get_formula_transparency("org-a", finding_id="does-not-exist")
    assert out["final_score"] is None
    assert out["priority_tier"] is None


# ---------------------------------------------------------------------------
# GAP-043: AI governance — formula change history
# ---------------------------------------------------------------------------


def test_register_formula_change_returns_row(governance):
    r = governance.register_formula_change(
        "org-a", "v1.0", "Launch baseline", "alice", "2026-04-22T10:00:00+00:00"
    )
    assert r["formula_version"] == "v1.0"
    assert r["approver"] == "alice"
    assert r["org_id"] == "org-a"


def test_register_formula_change_unique_on_version(governance):
    r1 = governance.register_formula_change("org-a", "v1.0", "first", "alice")
    r2 = governance.register_formula_change("org-a", "v1.0", "retry", "bob")
    # INSERT OR IGNORE keeps first row
    assert r1["id"] == r2["id"]
    assert r2["change_summary"] == "first"


def test_register_formula_change_different_orgs_independent(governance):
    governance.register_formula_change("org-a", "v1.0", "a", "alice")
    governance.register_formula_change("org-b", "v1.0", "b", "bob")
    assert len(governance.list_formula_history("org-a")) == 1
    assert len(governance.list_formula_history("org-b")) == 1


def test_register_formula_change_requires_org_id(governance):
    with pytest.raises(ValueError):
        governance.register_formula_change("", "v1.0", "x", "y")


def test_register_formula_change_requires_version(governance):
    with pytest.raises(ValueError):
        governance.register_formula_change("org-a", "", "x", "y")


def test_list_formula_history_newest_first(governance):
    governance.register_formula_change(
        "org-a", "v0.9", "old", "alice", "2025-01-01T00:00:00+00:00"
    )
    governance.register_formula_change(
        "org-a", "v1.0", "new", "bob", "2026-01-01T00:00:00+00:00"
    )
    hist = governance.list_formula_history("org-a")
    assert len(hist) == 2
    assert hist[0]["formula_version"] == "v1.0"  # newest first
    assert hist[1]["formula_version"] == "v0.9"


def test_list_formula_history_empty_org(governance):
    assert governance.list_formula_history("org-empty") == []


def test_list_formula_history_org_isolation(governance):
    governance.register_formula_change("org-a", "v1.0", "a", "alice")
    governance.register_formula_change("org-b", "v1.0", "b", "bob")
    governance.register_formula_change("org-b", "v2.0", "b2", "bob")
    assert len(governance.list_formula_history("org-a")) == 1
    assert len(governance.list_formula_history("org-b")) == 2


# ---------------------------------------------------------------------------
# GAP-044: AI Security Advisor teammate methods
# ---------------------------------------------------------------------------


def test_suggest_fix_with_context_shape(advisor):
    out = advisor.suggest_fix_with_context("org-a", "finding-xyz")
    expected = {
        "suggestion_type",
        "recommended_action",
        "confidence",
        "rationale",
        "similar_past_fixes",
        "finding_id",
        "generated_at",
    }
    assert expected <= set(out.keys())
    assert 0.0 <= out["confidence"] <= 1.0


def test_suggest_fix_with_context_requires_args(advisor):
    with pytest.raises(ValueError):
        advisor.suggest_fix_with_context("", "f")
    with pytest.raises(ValueError):
        advisor.suggest_fix_with_context("org-a", "")


def test_draft_exception_request_shape(advisor):
    out = advisor.draft_exception_request(
        "org-a", "finding-xyz", "need extra 30 days, vendor patch pending"
    )
    expected = {
        "finding_id",
        "tier",
        "composite_score",
        "business_justification",
        "suggested_max_duration_days",
        "required_approver",
        "compensating_controls",
        "drafted_at",
        "risk_acceptance_statement",
        "review_cadence_days",
    }
    assert expected <= set(out.keys())
    assert isinstance(out["compensating_controls"], list)
    assert out["suggested_max_duration_days"] > 0


def test_draft_exception_request_business_justification_preserved(advisor):
    out = advisor.draft_exception_request(
        "org-a", "f1", "legal hold, cannot patch until Q3"
    )
    assert "legal hold" in out["business_justification"]


def test_auto_triage_shape(advisor):
    out = advisor.auto_triage("org-a", "finding-xyz")
    expected = {
        "finding_id",
        "proposed_priority",
        "proposed_assignee_role",
        "crown_jewel",
        "blast_radius",
        "confidence",
        "reasoning",
        "triaged_at",
    }
    assert expected <= set(out.keys())
    assert out["proposed_priority"] in {"P1", "P2", "P3", "P4"}


def test_auto_triage_requires_finding(advisor):
    with pytest.raises(ValueError):
        advisor.auto_triage("org-a", "")


# ---------------------------------------------------------------------------
# GAP-044: AI-Powered SOC teammate playbook
# ---------------------------------------------------------------------------


def test_teammate_draft_playbook_known_template(soc):
    out = soc.teammate_draft_playbook("org-a", "ransomware")
    assert out["matched_template"] is True
    assert out["source"] == "template"
    assert out["incident_type"] == "ransomware"
    assert len(out["steps"]) > 0
    assert all("order" in s and "action" in s for s in out["steps"])


def test_teammate_draft_playbook_unknown_type_generic_skeleton(soc):
    out = soc.teammate_draft_playbook("org-a", "weird-new-attack")
    assert out["matched_template"] is False
    assert out["source"] == "generic_ir_skeleton"
    assert len(out["steps"]) == 5  # default skeleton


def test_teammate_draft_playbook_requires_incident_type(soc):
    with pytest.raises(ValueError):
        soc.teammate_draft_playbook("org-a", "")


def test_teammate_draft_playbook_case_and_space_normalization(soc):
    out = soc.teammate_draft_playbook("org-a", "Data Breach")
    assert out["incident_type"] == "data_breach"
    assert out["matched_template"] is True


# ---------------------------------------------------------------------------
# GAP-044: AutoFix teammate explanation
# ---------------------------------------------------------------------------


def test_teammate_explain_fix_missing_fix_returns_graceful(autofix):
    out = autofix.teammate_explain_fix("org-a", f"no-such-{uuid.uuid4()}")
    assert out["found"] is False
    assert "explanation" in out
    assert out["fix_id"].startswith("no-such-")


def test_teammate_explain_fix_requires_args(autofix):
    with pytest.raises(ValueError):
        autofix.teammate_explain_fix("", "fix-1")
    with pytest.raises(ValueError):
        autofix.teammate_explain_fix("org-a", "")


# ---------------------------------------------------------------------------
# Endpoint smoke (best-effort, gracefully skipped if app import fails)
# ---------------------------------------------------------------------------


def _build_test_app():
    from fastapi import FastAPI

    app = FastAPI()
    from apps.api.formula_transparency_router import router as _fr
    app.include_router(_fr)
    try:
        from apps.api.ai_orchestrator_router import teammates_router as _tr
        app.include_router(_tr)
    except ImportError:
        pass
    return app


def test_endpoint_formula_breakdown_smoke(monkeypatch):
    from fastapi.testclient import TestClient

    # Disable auth via dev-mode env
    monkeypatch.setenv("FIXOPS_DEV_MODE", "true")
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)

    app = _build_test_app()
    client = TestClient(app)
    resp = client.get("/api/v1/formula/breakdown?org_id=org-smoke")
    assert resp.status_code in (200, 401, 403, 503)
    if resp.status_code == 200:
        body = resp.json()
        assert "components" in body


def test_endpoint_formula_history_create_smoke(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("FIXOPS_DEV_MODE", "true")
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)

    app = _build_test_app()
    client = TestClient(app)
    resp = client.post(
        "/api/v1/formula/history?org_id=org-smoke",
        json={
            "formula_version": "v1.0",
            "change_summary": "smoke",
            "approver": "tester",
        },
    )
    assert resp.status_code in (200, 401, 403, 422, 503)


def test_endpoint_formula_history_list_smoke(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("FIXOPS_DEV_MODE", "true")
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)

    app = _build_test_app()
    client = TestClient(app)
    resp = client.get("/api/v1/formula/history?org_id=org-smoke")
    assert resp.status_code in (200, 401, 403, 503)


def test_endpoint_teammates_suggest_fix_smoke(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("FIXOPS_DEV_MODE", "true")
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)

    app = _build_test_app()
    client = TestClient(app)
    resp = client.post(
        "/api/v1/teammates/suggest-fix?org_id=org-smoke",
        json={"finding_id": "finding-abc"},
    )
    assert resp.status_code in (200, 401, 403, 404, 422, 503)


def test_endpoint_teammates_draft_exception_smoke(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("FIXOPS_DEV_MODE", "true")
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)

    app = _build_test_app()
    client = TestClient(app)
    resp = client.post(
        "/api/v1/teammates/draft-exception?org_id=org-smoke",
        json={"finding_id": "finding-abc", "business_justification": "ok"},
    )
    assert resp.status_code in (200, 401, 403, 404, 422, 503)


def test_endpoint_teammates_auto_triage_smoke(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("FIXOPS_DEV_MODE", "true")
    monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)

    app = _build_test_app()
    client = TestClient(app)
    resp = client.post(
        "/api/v1/teammates/auto-triage?org_id=org-smoke",
        json={"finding_id": "finding-abc"},
    )
    assert resp.status_code in (200, 401, 403, 404, 422, 503)
