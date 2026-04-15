"""Tests for AISecurityAdvisorEngine.

Covers:
  - DB initialisation and schema
  - generate_posture_recommendations (LLM mock + fallback)
  - analyze_incident (LLM mock + fallback)
  - generate_remediation_plan (LLM mock + fallback)
  - get_threat_briefing (LLM mock + fallback)
  - ask_advisor (LLM mock)
  - list_sessions / get_session
  - list_recommendations with filters
  - update_recommendation_status (happy path + invalid status)
  - get_stats
  - Multi-org isolation
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import patch

import sys
import os

# Ensure suite-core is on path
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _suite in ("suite-core", "suite-api"):
    _p = str(_PROJECT_ROOT / _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.ai_security_advisor_engine import AISecurityAdvisorEngine, FALLBACK_RECOMMENDATIONS

# ---------------------------------------------------------------------------
# Mock LLM payloads
# ---------------------------------------------------------------------------

MOCK_RECS = [
    {
        "priority": "critical",
        "category": "access_control",
        "title": "Enable MFA",
        "description": "Enable multi-factor authentication for all users.",
        "rationale": "Prevents 99.9% of credential attacks.",
        "effort_days": 3,
        "impact_score": 10,
        "implementation_steps": ["Inventory accounts", "Enable MFA", "Enforce policy"],
        "related_controls": ["NIST AC-7", "CIS 6.3"],
    },
    {
        "priority": "high",
        "category": "vulnerability",
        "title": "Patch critical CVEs within 24h",
        "description": "Automate patching of critical severity CVEs.",
        "rationale": "Reduces exploit window to near-zero.",
        "effort_days": 5,
        "impact_score": 9,
        "implementation_steps": ["Audit patch SLA", "Deploy automation", "Alert on failure"],
        "related_controls": ["NIST SI-2", "CIS 7.3"],
    },
]

MOCK_RECS_JSON = json.dumps(MOCK_RECS)

MOCK_ANALYSIS = json.dumps({
    "root_cause": "Unpatched Apache Log4j 2.x",
    "attack_vector": "Remote code execution via JNDI lookup",
    "blast_radius": "Production application servers (3 hosts)",
    "immediate_actions": ["Isolate affected hosts", "Block JNDI outbound"],
    "long_term_fixes": ["Upgrade Log4j to 2.17+", "Deploy WAF rule"],
    "similar_incidents_to_watch": ["Spring4Shell", "Confluence RCE"],
    "severity": "critical",
    "estimated_recovery_hours": 8,
})

MOCK_PLAN = json.dumps({
    "steps": ["Apply patch", "Restart service", "Verify fix"],
    "estimated_effort_hours": 4,
    "technical_prerequisites": ["Admin access", "Approved change ticket"],
    "testing_approach": "Run scanner post-patch",
    "rollback_plan": "Restore from snapshot",
    "verification_criteria": ["Scanner clean", "Service online"],
    "risk_during_remediation": "low",
    "recommended_maintenance_window": "02:00-04:00",
})

MOCK_BRIEFING = json.dumps({
    "executive_summary": "Threat landscape is elevated. Immediate patching is required.",
    "top_threats": [
        {"name": "Ransomware", "description": "Active campaigns", "likelihood": "high"},
        {"name": "Phishing", "description": "Credential harvest", "likelihood": "high"},
        {"name": "Supply chain", "description": "Malicious packages", "likelihood": "medium"},
    ],
    "recommended_actions": ["Patch now", "Enable MFA", "Run backup test"],
    "risk_level": "high",
    "confidence": "high",
    "briefing_date": "2026-04-16",
})

MOCK_ANSWER = "You should enable MFA and patch all critical CVEs within 24 hours."


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def advisor(tmp_path):
    """Fresh engine backed by a temp SQLite DB."""
    db = str(tmp_path / "test_advisor.db")
    return AISecurityAdvisorEngine(db_path=db)


# ---------------------------------------------------------------------------
# 1. DB initialisation
# ---------------------------------------------------------------------------

def test_db_initialised(advisor):
    """Engine creates DB and all four tables."""
    import sqlite3
    conn = sqlite3.connect(advisor._db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "advisor_sessions" in tables
    assert "recommendations" in tables
    assert "advisor_conversations" in tables
    assert "advisor_templates" in tables


def test_db_wal_mode(advisor):
    """DB is opened in WAL journal mode."""
    import sqlite3
    conn = sqlite3.connect(advisor._db_path)
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()
    assert mode == "wal"


# ---------------------------------------------------------------------------
# 2. Posture recommendations — LLM mock
# ---------------------------------------------------------------------------

def test_posture_review_with_mock_llm(advisor):
    ctx = {"risk_score": 0.75, "critical_findings": 5, "top_vulnerabilities": ["Log4Shell", "Heartbleed"]}
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", ctx)
    assert result["session"]["status"] == "completed"
    assert result["session"]["session_type"] == "posture_review"
    assert len(result["recommendations"]) == 2
    assert result["recommendations"][0]["priority"] == "critical"
    assert result["recommendations"][0]["category"] == "access_control"
    assert result["session"]["recommendation_count"] == 2


def test_posture_review_rec_fields(advisor):
    """Each recommendation has all required fields."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", {})
    rec = result["recommendations"][0]
    for field in ("id", "org_id", "session_id", "priority", "category", "title",
                  "description", "rationale", "effort_days", "impact_score",
                  "implementation_steps", "related_controls", "status", "created_at"):
        assert field in rec, f"Missing field: {field}"


def test_posture_review_fallback_on_invalid_json(advisor):
    """Falls back to FALLBACK_RECOMMENDATIONS when LLM returns non-JSON."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value="not valid json at all"):
        result = advisor.generate_posture_recommendations("org1", {"risk_score": 0.5})
    assert result["session"]["status"] == "completed"
    assert len(result["recommendations"]) == len(FALLBACK_RECOMMENDATIONS)


def test_posture_review_fallback_on_empty_llm(advisor):
    """Falls back when LLM returns empty string."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value=""):
        result = advisor.generate_posture_recommendations("org1", {})
    assert len(result["recommendations"]) > 0


def test_posture_review_fallback_on_llm_error(advisor):
    """Falls back when LLM is not configured (returns config message)."""
    with patch("core.ai_security_advisor_engine._call_llm",
               return_value="LLM not configured — set MULEROUTER_API_KEY in .env"):
        result = advisor.generate_posture_recommendations("org1", {})
    assert len(result["recommendations"]) == len(FALLBACK_RECOMMENDATIONS)


def test_posture_review_impact_score_clamped(advisor):
    """Impact scores outside 1-10 are clamped."""
    recs_with_bad_scores = [
        {**MOCK_RECS[0], "impact_score": 999},
        {**MOCK_RECS[1], "impact_score": -5},
    ]
    with patch("core.ai_security_advisor_engine._call_llm", return_value=json.dumps(recs_with_bad_scores)):
        result = advisor.generate_posture_recommendations("org1", {})
    scores = [r["impact_score"] for r in result["recommendations"]]
    for s in scores:
        assert 1.0 <= s <= 10.0


def test_posture_review_effort_days_clamped(advisor):
    """Effort days outside 1-90 are clamped."""
    recs_with_bad_effort = [{**MOCK_RECS[0], "effort_days": 9999}]
    with patch("core.ai_security_advisor_engine._call_llm", return_value=json.dumps(recs_with_bad_effort)):
        result = advisor.generate_posture_recommendations("org1", {})
    assert result["recommendations"][0]["effort_days"] == 90


# ---------------------------------------------------------------------------
# 3. Incident analysis
# ---------------------------------------------------------------------------

def test_analyze_incident_with_mock_llm(advisor):
    incident = {"type": "ransomware", "affected_systems": ["web-01"], "severity": "critical"}
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_ANALYSIS):
        result = advisor.analyze_incident("org1", incident)
    assert result["session"]["status"] == "completed"
    assert result["session"]["session_type"] == "incident_analysis"
    assert "root_cause" in result["analysis"]
    assert "immediate_actions" in result["analysis"]
    assert isinstance(result["analysis"]["immediate_actions"], list)


def test_analyze_incident_fallback(advisor):
    """Falls back to default analysis when LLM returns invalid JSON."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value="bad json"):
        result = advisor.analyze_incident("org1", {"type": "phishing", "severity": "medium"})
    assert result["session"]["status"] == "completed"
    assert "root_cause" in result["analysis"]
    assert len(result["analysis"]["immediate_actions"]) >= 1


def test_analyze_incident_session_persisted(advisor):
    incident = {"type": "data_breach", "severity": "high"}
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_ANALYSIS):
        result = advisor.analyze_incident("org2", incident)
    session_id = result["session"]["id"]
    sessions = advisor.list_sessions("org2", session_type="incident_analysis")
    assert any(s["id"] == session_id for s in sessions)


# ---------------------------------------------------------------------------
# 4. Remediation plan
# ---------------------------------------------------------------------------

def test_generate_remediation_plan_with_mock_llm(advisor):
    vuln = {"cve_id": "CVE-2021-44228", "name": "Log4Shell", "severity": "critical", "cvss_score": 10.0}
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_PLAN):
        result = advisor.generate_remediation_plan("org1", vuln)
    assert result["session"]["status"] == "completed"
    assert result["session"]["session_type"] == "remediation_plan"
    plan = result["plan"]
    assert "steps" in plan
    assert isinstance(plan["steps"], list)
    assert "rollback_plan" in plan
    assert "verification_criteria" in plan


def test_generate_remediation_plan_fallback(advisor):
    """Falls back gracefully when LLM returns garbage."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value="!!!"):
        result = advisor.generate_remediation_plan("org1", {"cve_id": "CVE-2024-0001"})
    assert "steps" in result["plan"]
    assert len(result["plan"]["steps"]) > 0


# ---------------------------------------------------------------------------
# 5. Threat briefing
# ---------------------------------------------------------------------------

def test_get_threat_briefing_with_mock_llm(advisor):
    ctx = {"industry": "finance", "active_campaigns": ["LockBit", "Cl0p"]}
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_BRIEFING):
        result = advisor.get_threat_briefing("org1", ctx)
    assert result["session"]["status"] == "completed"
    assert result["session"]["session_type"] == "threat_briefing"
    briefing = result["briefing"]
    assert "executive_summary" in briefing
    assert "top_threats" in briefing
    assert len(briefing["top_threats"]) == 3
    assert "recommended_actions" in briefing
    assert "risk_level" in briefing


def test_get_threat_briefing_fallback(advisor):
    """Falls back to default briefing when LLM fails."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value="not json"):
        result = advisor.get_threat_briefing("org1", {})
    assert "executive_summary" in result["briefing"]
    assert result["briefing"]["risk_level"] in ("critical", "high", "medium", "low")


# ---------------------------------------------------------------------------
# 6. Ask advisor
# ---------------------------------------------------------------------------

def test_ask_advisor_with_mock_llm(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_ANSWER):
        result = advisor.ask_advisor("org1", "How do I prevent ransomware?")
    assert result["question"] == "How do I prevent ransomware?"
    assert result["answer"] == MOCK_ANSWER
    assert isinstance(result["tokens_used"], int)
    assert result["tokens_used"] > 0


def test_ask_advisor_with_context(advisor):
    ctx = {"risk_score": 0.8, "recent_incident": "ransomware"}
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_ANSWER):
        result = advisor.ask_advisor("org1", "What is my top priority?", context=ctx)
    assert result["answer"] == MOCK_ANSWER


def test_ask_advisor_persists_conversation(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_ANSWER):
        advisor.ask_advisor("org1", "Question 1?")
        advisor.ask_advisor("org1", "Question 2?")
    import sqlite3
    conn = sqlite3.connect(advisor._db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM advisor_conversations WHERE org_id='org1'"
    ).fetchone()[0]
    conn.close()
    # Each ask saves 2 rows (user + assistant)
    assert count == 4


# ---------------------------------------------------------------------------
# 7. Session queries
# ---------------------------------------------------------------------------

def test_list_sessions_empty(advisor):
    assert advisor.list_sessions("new_org") == []


def test_list_sessions_returns_all(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_ANALYSIS):
        advisor.analyze_incident("org1", {})
    sessions = advisor.list_sessions("org1")
    assert len(sessions) == 2


def test_list_sessions_filter_by_type(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_ANALYSIS):
        advisor.analyze_incident("org1", {})
    posture_only = advisor.list_sessions("org1", session_type="posture_review")
    assert len(posture_only) == 1
    assert posture_only[0]["session_type"] == "posture_review"


def test_get_session_with_recommendations(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", {"risk_score": 0.9})
    session_id = result["session"]["id"]
    session = advisor.get_session("org1", session_id)
    assert session is not None
    assert session["id"] == session_id
    assert "recommendations" in session
    assert len(session["recommendations"]) == 2


def test_get_session_not_found(advisor):
    assert advisor.get_session("org1", "nonexistent-id") is None


def test_get_session_wrong_org(advisor):
    """Session for org1 should not be visible to org2."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", {})
    session_id = result["session"]["id"]
    assert advisor.get_session("org2", session_id) is None


# ---------------------------------------------------------------------------
# 8. Recommendation queries
# ---------------------------------------------------------------------------

def test_list_recommendations_all(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    recs = advisor.list_recommendations("org1")
    assert len(recs) == 2


def test_list_recommendations_filter_priority(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    critical = advisor.list_recommendations("org1", priority="critical")
    assert all(r["priority"] == "critical" for r in critical)
    assert len(critical) == 1


def test_list_recommendations_filter_category(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    access = advisor.list_recommendations("org1", category="access_control")
    assert all(r["category"] == "access_control" for r in access)


def test_list_recommendations_filter_status(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    pending = advisor.list_recommendations("org1", status="pending")
    assert len(pending) == 2
    assert all(r["status"] == "pending" for r in pending)


def test_list_recommendations_wrong_org(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    assert advisor.list_recommendations("org2") == []


def test_list_recommendations_steps_parsed_as_list(advisor):
    """implementation_steps must be returned as a list, not a JSON string."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    recs = advisor.list_recommendations("org1")
    for rec in recs:
        assert isinstance(rec["implementation_steps"], list)
        assert isinstance(rec["related_controls"], list)


# ---------------------------------------------------------------------------
# 9. Update recommendation status
# ---------------------------------------------------------------------------

def test_update_recommendation_status_accepted(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", {})
    rec_id = result["recommendations"][0]["id"]
    updated = advisor.update_recommendation_status("org1", rec_id, "accepted")
    assert updated is not None
    assert updated["status"] == "accepted"


def test_update_recommendation_status_implemented(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", {})
    rec_id = result["recommendations"][0]["id"]
    advisor.update_recommendation_status("org1", rec_id, "implemented")
    recs = advisor.list_recommendations("org1", status="implemented")
    assert any(r["id"] == rec_id for r in recs)


def test_update_recommendation_status_invalid(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", {})
    rec_id = result["recommendations"][0]["id"]
    with pytest.raises(ValueError, match="Invalid status"):
        advisor.update_recommendation_status("org1", rec_id, "bad_status")


def test_update_recommendation_status_not_found(advisor):
    result = advisor.update_recommendation_status("org1", "nonexistent", "accepted")
    assert result is None


def test_update_recommendation_status_wrong_org(advisor):
    """org2 cannot update org1's recommendation."""
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", {})
    rec_id = result["recommendations"][0]["id"]
    updated = advisor.update_recommendation_status("org2", rec_id, "accepted")
    assert updated is None


# ---------------------------------------------------------------------------
# 10. Stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(advisor):
    stats = advisor.get_stats("new_org")
    assert stats["session_count"] == 0
    assert stats["implemented_count"] == 0
    assert stats["total_impact_score"] == 0.0
    assert stats["conversation_count"] == 0


def test_get_stats_after_activity(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        result = advisor.generate_posture_recommendations("org1", {})
    rec_id = result["recommendations"][0]["id"]
    advisor.update_recommendation_status("org1", rec_id, "implemented")
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_ANSWER):
        advisor.ask_advisor("org1", "Any advice?")
    stats = advisor.get_stats("org1")
    assert stats["session_count"] == 1
    assert stats["implemented_count"] == 1
    assert stats["total_impact_score"] > 0
    assert stats["conversation_count"] == 2  # user + assistant
    assert stats["sessions_this_week"] == 1


def test_get_stats_recommendations_by_priority(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    stats = advisor.get_stats("org1")
    rbp = stats["recommendations_by_priority"]
    assert "critical" in rbp
    assert rbp["critical"] == 1


def test_get_stats_org_isolation(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org1", {})
    stats_org2 = advisor.get_stats("org2")
    assert stats_org2["session_count"] == 0


# ---------------------------------------------------------------------------
# 11. Multi-org isolation
# ---------------------------------------------------------------------------

def test_multi_org_sessions_isolated(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org_a", {})
        advisor.generate_posture_recommendations("org_b", {})
    assert len(advisor.list_sessions("org_a")) == 1
    assert len(advisor.list_sessions("org_b")) == 1


def test_multi_org_recommendations_isolated(advisor):
    with patch("core.ai_security_advisor_engine._call_llm", return_value=MOCK_RECS_JSON):
        advisor.generate_posture_recommendations("org_a", {})
        advisor.generate_posture_recommendations("org_b", {})
    recs_a = advisor.list_recommendations("org_a")
    recs_b = advisor.list_recommendations("org_b")
    ids_a = {r["id"] for r in recs_a}
    ids_b = {r["id"] for r in recs_b}
    assert ids_a.isdisjoint(ids_b), "Orgs should not share recommendations"


# ---------------------------------------------------------------------------
# 12. Fallback recommendations completeness
# ---------------------------------------------------------------------------

def test_fallback_recommendations_have_required_fields():
    """All fallback recs have the required fields."""
    required = {
        "priority", "category", "title", "description", "rationale",
        "effort_days", "impact_score", "implementation_steps", "related_controls",
    }
    for rec in FALLBACK_RECOMMENDATIONS:
        for field in required:
            assert field in rec, f"Fallback rec missing field: {field}"


def test_fallback_recommendations_priorities_valid():
    valid = {"critical", "high", "medium", "low"}
    for rec in FALLBACK_RECOMMENDATIONS:
        assert rec["priority"] in valid


def test_fallback_recommendations_impact_scores_in_range():
    for rec in FALLBACK_RECOMMENDATIONS:
        assert 1 <= rec["impact_score"] <= 10
