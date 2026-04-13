"""
Tests for the Compliance Questionnaire Engine.

Covers:
- QuestionnaireEngine CRUD
- create_questionnaire (template + custom)
- auto_answer with confidence scoring
- update_answer (manual override)
- export_questionnaire (JSON + CSV)
- get_answer_bank / add_to_answer_bank
- submit_questionnaire
- list_questionnaires
- get_available_templates
- Multi-tenant isolation
- 404 error paths
- FastAPI router endpoints (8 endpoints)
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.questionnaire_engine import (
    QuestionCategory,
    Question,
    Questionnaire,
    QuestionnaireEngine,
    _match_question,
    _normalize,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def engine():
    """Fresh in-memory QuestionnaireEngine for each test."""
    return QuestionnaireEngine(db_path=":memory:")


@pytest.fixture
def soc2_questionnaire(engine):
    """Pre-created SOC2 questionnaire."""
    return engine.create_questionnaire(
        name="SOC2 Assessment 2024",
        vendor_name="Acme Corp",
        org_id="org1",
        template_type="soc2",
    )


@pytest.fixture
def app(engine):
    """FastAPI test app with questionnaire_router, auth bypassed."""
    from apps.api import questionnaire_router as qr
    from apps.api.questionnaire_router import router, _get_engine
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_get_engine] = lambda: engine
    app.dependency_overrides[api_key_auth] = lambda: None
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


# ============================================================================
# _normalize helper
# ============================================================================


def test_normalize_lowercases():
    assert _normalize("Do You Have MFA?") == "do you have mfa"


def test_normalize_strips_punctuation():
    assert _normalize("Hello, World!") == "hello world"


def test_normalize_strips_whitespace():
    assert _normalize("  spaces  ") == "spaces"


# ============================================================================
# _match_question
# ============================================================================


def test_match_question_mfa():
    result = _match_question("Do you enforce multi-factor authentication?")
    assert result is not None
    assert "MFA" in result["answer"] or "multi" in result["answer"].lower()
    assert result["confidence"] > 0.5


def test_match_question_encryption():
    result = _match_question("Do you encrypt data at rest?")
    assert result is not None
    assert "AES" in result["answer"] or "encrypt" in result["answer"].lower()


def test_match_question_no_match():
    result = _match_question("What is your favorite color?")
    assert result is None


def test_match_question_incident_response():
    result = _match_question("Do you have an incident response plan?")
    assert result is not None
    assert result["category"] == QuestionCategory.INCIDENT_RESPONSE


def test_match_question_returns_evidence_refs():
    result = _match_question("Are you SOC2 compliant?")
    assert result is not None
    assert len(result["evidence_refs"]) > 0


# ============================================================================
# QuestionnaireEngine — create_questionnaire
# ============================================================================


def test_create_questionnaire_from_soc2_template(engine):
    q = engine.create_questionnaire(
        name="SOC2 Q1",
        vendor_name="Vendor A",
        template_type="soc2",
    )
    assert q.id
    assert q.name == "SOC2 Q1"
    assert q.vendor_name == "Vendor A"
    assert len(q.questions) == 20  # SOC2 template has 20 questions
    assert q.completion_pct == 0.0


def test_create_questionnaire_from_vendor_assessment_template(engine):
    q = engine.create_questionnaire(
        name="Vendor Check",
        vendor_name="Supplier B",
        template_type="vendor_assessment",
    )
    assert len(q.questions) == 24


def test_create_questionnaire_from_sig_lite_template(engine):
    q = engine.create_questionnaire(
        name="SIG Lite",
        vendor_name="Supplier C",
        template_type="sig_lite",
    )
    assert len(q.questions) == 40


def test_create_questionnaire_custom_questions(engine):
    q = engine.create_questionnaire(
        name="Custom Q",
        vendor_name="Custom Vendor",
        custom_questions=[
            {"text": "Do you have a firewall?", "category": "infrastructure"},
            {"text": "Do you encrypt backups?", "category": "encryption"},
        ],
    )
    assert len(q.questions) == 2
    assert q.questions[0].text == "Do you have a firewall?"
    assert q.questions[1].category == QuestionCategory.ENCRYPTION


def test_create_questionnaire_empty(engine):
    q = engine.create_questionnaire(
        name="Empty",
        vendor_name="No Vendor",
    )
    assert len(q.questions) == 0
    assert q.completion_pct == 0.0


def test_create_questionnaire_stores_org_id(engine):
    q = engine.create_questionnaire(
        name="Org Test",
        vendor_name="V",
        org_id="tenant42",
    )
    assert q.org_id == "tenant42"


def test_create_questionnaire_stores_template_type(engine):
    q = engine.create_questionnaire(
        name="T",
        vendor_name="V",
        template_type="soc2",
    )
    assert q.template_type == "soc2"


# ============================================================================
# QuestionnaireEngine — auto_answer
# ============================================================================


def test_auto_answer_fills_questions(engine, soc2_questionnaire):
    result = engine.auto_answer(soc2_questionnaire.id)
    answered = [q for q in result.questions if q.answer]
    assert len(answered) > 0


def test_auto_answer_sets_auto_answered_flag(engine, soc2_questionnaire):
    result = engine.auto_answer(soc2_questionnaire.id)
    auto = [q for q in result.questions if q.auto_answered]
    assert len(auto) > 0


def test_auto_answer_sets_confidence(engine, soc2_questionnaire):
    result = engine.auto_answer(soc2_questionnaire.id)
    for q in result.questions:
        if q.auto_answered:
            assert 0.0 < q.confidence <= 1.0


def test_auto_answer_updates_completion_pct(engine, soc2_questionnaire):
    assert soc2_questionnaire.completion_pct == 0.0
    result = engine.auto_answer(soc2_questionnaire.id)
    assert result.completion_pct > 0.0


def test_auto_answer_raises_for_unknown_id(engine):
    with pytest.raises(KeyError):
        engine.auto_answer("nonexistent-id")


def test_auto_answer_does_not_overwrite_existing_answers(engine):
    q = engine.create_questionnaire(
        name="Override Test",
        vendor_name="V",
        custom_questions=[
            {"text": "Do you encrypt data at rest?", "category": "encryption"},
        ],
    )
    # Pre-fill with manual answer
    engine.update_answer(q.id, q.questions[0].id, "Custom manual answer")
    result = engine.auto_answer(q.id)
    # Manual answer should be preserved
    assert result.questions[0].answer == "Custom manual answer"
    assert not result.questions[0].auto_answered


def test_auto_answer_populates_evidence_refs(engine, soc2_questionnaire):
    result = engine.auto_answer(soc2_questionnaire.id)
    has_refs = any(len(q.evidence_refs) > 0 for q in result.questions if q.auto_answered)
    assert has_refs


# ============================================================================
# QuestionnaireEngine — get_questionnaire
# ============================================================================


def test_get_questionnaire_returns_correct(engine, soc2_questionnaire):
    fetched = engine.get_questionnaire(soc2_questionnaire.id)
    assert fetched is not None
    assert fetched.id == soc2_questionnaire.id
    assert fetched.name == "SOC2 Assessment 2024"


def test_get_questionnaire_returns_none_for_unknown(engine):
    assert engine.get_questionnaire("does-not-exist") is None


# ============================================================================
# QuestionnaireEngine — update_answer
# ============================================================================


def test_update_answer_sets_text(engine, soc2_questionnaire):
    q_id = soc2_questionnaire.questions[0].id
    updated = engine.update_answer(soc2_questionnaire.id, q_id, "Our custom answer")
    assert updated.answer == "Our custom answer"


def test_update_answer_sets_confidence_to_1(engine, soc2_questionnaire):
    q_id = soc2_questionnaire.questions[0].id
    updated = engine.update_answer(soc2_questionnaire.id, q_id, "Yes we do")
    assert updated.confidence == 1.0


def test_update_answer_clears_auto_answered(engine, soc2_questionnaire):
    engine.auto_answer(soc2_questionnaire.id)
    fetched = engine.get_questionnaire(soc2_questionnaire.id)
    auto_q = next((q for q in fetched.questions if q.auto_answered), None)
    if auto_q:
        updated = engine.update_answer(soc2_questionnaire.id, auto_q.id, "Manual override")
        assert not updated.auto_answered


def test_update_answer_with_evidence_refs(engine, soc2_questionnaire):
    q_id = soc2_questionnaire.questions[0].id
    updated = engine.update_answer(
        soc2_questionnaire.id, q_id, "Answer", evidence_refs=["SOC2-CC6.1", "ISO27001-A.9"]
    )
    assert "SOC2-CC6.1" in updated.evidence_refs


def test_update_answer_raises_for_unknown_question(engine, soc2_questionnaire):
    with pytest.raises(KeyError):
        engine.update_answer(soc2_questionnaire.id, "bad-question-id", "answer")


def test_update_answer_increments_completion(engine):
    q = engine.create_questionnaire(
        name="Completion Test",
        vendor_name="V",
        custom_questions=[
            {"text": "Q1", "category": "encryption"},
            {"text": "Q2", "category": "encryption"},
        ],
    )
    assert q.completion_pct == 0.0
    engine.update_answer(q.id, q.questions[0].id, "Yes")
    fetched = engine.get_questionnaire(q.id)
    assert fetched.completion_pct == 50.0


# ============================================================================
# QuestionnaireEngine — export_questionnaire
# ============================================================================


def test_export_json(engine, soc2_questionnaire):
    engine.auto_answer(soc2_questionnaire.id)
    output = engine.export_questionnaire(soc2_questionnaire.id, format="json")
    data = json.loads(output)
    assert "questionnaire" in data
    assert "summary" in data
    assert "sections" in data
    assert data["questionnaire"]["name"] == "SOC2 Assessment 2024"


def test_export_json_summary_fields(engine, soc2_questionnaire):
    engine.auto_answer(soc2_questionnaire.id)
    output = engine.export_questionnaire(soc2_questionnaire.id, format="json")
    data = json.loads(output)
    summary = data["summary"]
    assert "total_questions" in summary
    assert "answered" in summary
    assert "auto_answered" in summary
    assert "avg_confidence" in summary


def test_export_csv(engine, soc2_questionnaire):
    engine.auto_answer(soc2_questionnaire.id)
    output = engine.export_questionnaire(soc2_questionnaire.id, format="csv")
    lines = output.strip().split("\n")
    assert lines[0].startswith("ID,Category,Question")
    assert len(lines) > 1  # Header + at least one data row


def test_export_csv_has_correct_columns(engine, soc2_questionnaire):
    output = engine.export_questionnaire(soc2_questionnaire.id, format="csv")
    header = output.split("\n")[0]
    assert "Answer" in header
    assert "Confidence" in header
    assert "Evidence Refs" in header


def test_export_raises_for_unknown(engine):
    with pytest.raises(KeyError):
        engine.export_questionnaire("bad-id", format="json")


# ============================================================================
# QuestionnaireEngine — answer bank
# ============================================================================


def test_get_answer_bank_returns_seeded_entries(engine):
    bank = engine.get_answer_bank()
    assert len(bank) >= 30  # At least 30 built-in templates


def test_add_to_answer_bank(engine):
    entry = engine.add_to_answer_bank(
        question_key="do you have sla guarantees",
        category=QuestionCategory.INFRASTRUCTURE,
        answer="Yes, 99.9% uptime SLA.",
        evidence_refs=["SLA-001"],
        confidence=0.95,
        org_id="org1",
    )
    assert entry["question_key"] == "do you have sla guarantees"
    assert entry["answer"] == "Yes, 99.9% uptime SLA."
    assert entry["org_id"] == "org1"


def test_add_to_answer_bank_upserts(engine):
    engine.add_to_answer_bank(
        question_key="custom-q",
        category=QuestionCategory.COMPLIANCE,
        answer="First answer",
        org_id="orgX",
    )
    engine.add_to_answer_bank(
        question_key="custom-q",
        category=QuestionCategory.COMPLIANCE,
        answer="Updated answer",
        org_id="orgX",
    )
    bank = engine.get_answer_bank(org_id="orgX")
    custom = [b for b in bank if b["question_key"] == "custom-q"]
    assert len(custom) == 1
    assert custom[0]["answer"] == "Updated answer"


# ============================================================================
# QuestionnaireEngine — submit + list
# ============================================================================


def test_submit_questionnaire(engine, soc2_questionnaire):
    result = engine.submit_questionnaire(soc2_questionnaire.id)
    assert result.submitted_at is not None


def test_submit_questionnaire_raises_for_unknown(engine):
    with pytest.raises(KeyError):
        engine.submit_questionnaire("bad-id")


def test_list_questionnaires_by_org(engine):
    engine.create_questionnaire("Q1", "V1", org_id="org1", template_type="soc2")
    engine.create_questionnaire("Q2", "V2", org_id="org1")
    engine.create_questionnaire("Q3", "V3", org_id="org2")
    org1 = engine.list_questionnaires(org_id="org1")
    assert len(org1) == 2
    org2 = engine.list_questionnaires(org_id="org2")
    assert len(org2) == 1


def test_get_available_templates(engine):
    templates = engine.get_available_templates()
    ids = [t["id"] for t in templates]
    assert "soc2" in ids
    assert "vendor_assessment" in ids
    assert "sig_lite" in ids
    for t in templates:
        assert t["question_count"] > 0


# ============================================================================
# FastAPI Router
# ============================================================================


def test_router_create_questionnaire(client):
    resp = client.post(
        "/api/v1/questionnaires",
        json={"name": "API Test", "vendor_name": "API Vendor", "template_type": "soc2"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "API Test"
    assert data["vendor_name"] == "API Vendor"
    assert len(data["questions"]) == 20


def test_router_list_templates(client):
    resp = client.get("/api/v1/questionnaires/templates")
    assert resp.status_code == 200
    templates = resp.json()
    assert len(templates) == 3


def test_router_get_answer_bank(client):
    resp = client.get("/api/v1/questionnaires/answer-bank")
    assert resp.status_code == 200
    bank = resp.json()
    assert len(bank) >= 30


def test_router_list_questionnaires(client):
    client.post("/api/v1/questionnaires", json={"name": "Q1", "vendor_name": "V1"})
    client.post("/api/v1/questionnaires", json={"name": "Q2", "vendor_name": "V2"})
    resp = client.get("/api/v1/questionnaires")
    assert resp.status_code == 200
    assert len(resp.json()) >= 2


def test_router_get_questionnaire(client):
    create_resp = client.post(
        "/api/v1/questionnaires",
        json={"name": "Fetch Test", "vendor_name": "FV", "template_type": "soc2"},
    )
    qid = create_resp.json()["id"]
    resp = client.get(f"/api/v1/questionnaires/{qid}")
    assert resp.status_code == 200
    assert resp.json()["id"] == qid


def test_router_get_questionnaire_404(client):
    resp = client.get("/api/v1/questionnaires/nonexistent-id")
    assert resp.status_code == 404


def test_router_auto_answer(client):
    create_resp = client.post(
        "/api/v1/questionnaires",
        json={"name": "Auto Test", "vendor_name": "AV", "template_type": "soc2"},
    )
    qid = create_resp.json()["id"]
    resp = client.post(f"/api/v1/questionnaires/{qid}/auto-answer")
    assert resp.status_code == 200
    data = resp.json()
    assert data["completion_pct"] > 0.0


def test_router_auto_answer_404(client):
    resp = client.post("/api/v1/questionnaires/bad-id/auto-answer")
    assert resp.status_code == 404


def test_router_update_answer(client):
    create_resp = client.post(
        "/api/v1/questionnaires",
        json={"name": "Update Test", "vendor_name": "UV", "template_type": "soc2"},
    )
    data = create_resp.json()
    qid = data["id"]
    first_question_id = data["questions"][0]["id"]

    resp = client.patch(
        f"/api/v1/questionnaires/{qid}/questions/{first_question_id}",
        json={"answer": "Yes, fully compliant.", "evidence_refs": ["SOC2-CC6.1"]},
    )
    assert resp.status_code == 200
    q = resp.json()
    assert q["answer"] == "Yes, fully compliant."
    assert "SOC2-CC6.1" in q["evidence_refs"]
    assert q["confidence"] == 1.0


def test_router_update_answer_404(client):
    create_resp = client.post(
        "/api/v1/questionnaires",
        json={"name": "404 Test", "vendor_name": "V"},
    )
    qid = create_resp.json()["id"]
    resp = client.patch(
        f"/api/v1/questionnaires/{qid}/questions/bad-question-id",
        json={"answer": "test"},
    )
    assert resp.status_code == 404


def test_router_submit_questionnaire(client):
    create_resp = client.post(
        "/api/v1/questionnaires",
        json={"name": "Submit Test", "vendor_name": "SV"},
    )
    qid = create_resp.json()["id"]
    resp = client.post(f"/api/v1/questionnaires/{qid}/submit")
    assert resp.status_code == 200
    assert resp.json()["submitted_at"] is not None


def test_router_submit_404(client):
    resp = client.post("/api/v1/questionnaires/bad-id/submit")
    assert resp.status_code == 404


def test_router_export_json(client):
    create_resp = client.post(
        "/api/v1/questionnaires",
        json={"name": "Export Test", "vendor_name": "EV", "template_type": "soc2"},
    )
    qid = create_resp.json()["id"]
    client.post(f"/api/v1/questionnaires/{qid}/auto-answer")

    resp = client.get(f"/api/v1/questionnaires/{qid}/export?format=json")
    assert resp.status_code == 200
    data = json.loads(resp.text)
    assert "questionnaire" in data
    assert "summary" in data


def test_router_export_csv(client):
    create_resp = client.post(
        "/api/v1/questionnaires",
        json={"name": "CSV Export", "vendor_name": "CV", "template_type": "soc2"},
    )
    qid = create_resp.json()["id"]

    resp = client.get(f"/api/v1/questionnaires/{qid}/export?format=csv")
    assert resp.status_code == 200
    assert "ID,Category,Question" in resp.text


def test_router_export_404(client):
    resp = client.get("/api/v1/questionnaires/bad-id/export")
    assert resp.status_code == 404


def test_router_add_to_answer_bank(client):
    resp = client.post(
        "/api/v1/questionnaires/answer-bank",
        json={
            "question_key": "do you have soc2",
            "category": "compliance",
            "answer": "Yes, SOC2 Type II certified.",
            "confidence": 0.98,
        },
    )
    assert resp.status_code == 201
    assert resp.json()["answer"] == "Yes, SOC2 Type II certified."
