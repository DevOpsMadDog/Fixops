"""Tests for OpenClaw Autonomous Pentest Swarm Engine — 30+ tests.

Covers: campaign CRUD, authorization requirement, start_campaign creates tasks
and findings, phase advance, pause/resume/complete lifecycle, finding status
updates, multi-tenant isolation, stats.
"""

from __future__ import annotations

import os
import tempfile
import uuid
import pytest

from core.openclaw_engine import OpenClawEngine, PHASE_TASKS, FINDING_TEMPLATES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_engine(tmp_path):
    """Return an OpenClawEngine backed by a temp SQLite DB."""
    db = str(tmp_path / "test_openclaw.db")
    return OpenClawEngine(org_id="test_org", db_path=db)


@pytest.fixture
def engine_a(tmp_path):
    db = str(tmp_path / "org_a.db")
    return OpenClawEngine(org_id="org_a", db_path=db)


@pytest.fixture
def engine_b(tmp_path):
    db = str(tmp_path / "org_b.db")
    return OpenClawEngine(org_id="org_b", db_path=db)


def _make_campaign_data(**kwargs):
    defaults = {
        "name": "Test Red Team Op",
        "description": "Full red team assessment",
        "campaign_type": "network_pentest",
        "target_scope": ["192.168.1.0/24", "10.0.0.1"],
        "attack_tactics": ["TA0001", "TA0002"],
        "operators_count": 3,
        "authorization_token": "AUTH-TOKEN-2026-APPROVED-BY-CISO",
        "authorized_by": "CISO John Smith",
        "authorized_until": "2026-12-31",
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# Phase / finding template sanity
# ---------------------------------------------------------------------------


def test_phase_tasks_contains_all_phases():
    required = ["recon", "initial_access", "privilege_escalation", "lateral_movement", "collection"]
    for phase in required:
        assert phase in PHASE_TASKS, f"Missing phase: {phase}"
        assert len(PHASE_TASKS[phase]) >= 2, f"Phase {phase} has too few task templates"


def test_finding_templates_have_required_keys():
    for tech_id, tmpl in FINDING_TEMPLATES.items():
        assert "title" in tmpl, f"{tech_id} missing title"
        assert "severity" in tmpl, f"{tech_id} missing severity"
        assert "category" in tmpl, f"{tech_id} missing category"
        assert "cvss_score" in tmpl, f"{tech_id} missing cvss_score"


# ---------------------------------------------------------------------------
# Campaign creation
# ---------------------------------------------------------------------------


def test_create_campaign_basic(tmp_engine):
    data = _make_campaign_data()
    result = tmp_engine.create_campaign("test_org", data)
    assert result["id"] is not None
    assert result["name"] == "Test Red Team Op"
    assert result["status"] == "staged"
    assert result["phase"] == "recon"
    assert result["campaign_type"] == "network_pentest"
    assert result["operators_count"] == 3


def test_create_campaign_has_operators(tmp_engine):
    data = _make_campaign_data(operators_count=3)
    result = tmp_engine.create_campaign("test_org", data)
    assert len(result["operators"]) == 3
    op_ids = [op["operator_id"] for op in result["operators"]]
    assert sorted(op_ids) == [1, 2, 3]


def test_create_campaign_max_operators(tmp_engine):
    data = _make_campaign_data(operators_count=5)
    result = tmp_engine.create_campaign("test_org", data)
    assert len(result["operators"]) == 5


def test_create_campaign_min_operators(tmp_engine):
    data = _make_campaign_data(operators_count=1)
    result = tmp_engine.create_campaign("test_org", data)
    assert len(result["operators"]) == 1


def test_create_campaign_requires_authorization_token(tmp_engine):
    data = _make_campaign_data()
    data["authorization_token"] = ""
    with pytest.raises(ValueError, match="authorization_token"):
        tmp_engine.create_campaign("test_org", data)


def test_create_campaign_missing_token_key(tmp_engine):
    data = _make_campaign_data()
    del data["authorization_token"]
    with pytest.raises(ValueError, match="authorization_token"):
        tmp_engine.create_campaign("test_org", data)


def test_create_campaign_invalid_type_defaults(tmp_engine):
    data = _make_campaign_data(campaign_type="invalid_type")
    result = tmp_engine.create_campaign("test_org", data)
    assert result["campaign_type"] == "network_pentest"


def test_create_campaign_all_types(tmp_engine):
    types = ["network_pentest", "web_app", "cloud_security",
             "social_engineering", "physical_access", "full_red_team"]
    for ctype in types:
        data = _make_campaign_data(name=f"Test {ctype}", campaign_type=ctype)
        result = tmp_engine.create_campaign("test_org", data)
        assert result["campaign_type"] == ctype


def test_create_campaign_target_scope_stored(tmp_engine):
    data = _make_campaign_data(target_scope=["192.168.1.1", "10.10.0.0/16"])
    result = tmp_engine.create_campaign("test_org", data)
    assert isinstance(result["target_scope"], list)
    assert "192.168.1.1" in result["target_scope"]


# ---------------------------------------------------------------------------
# List / get
# ---------------------------------------------------------------------------


def test_list_campaigns_empty(tmp_engine):
    assert tmp_engine.list_campaigns("test_org") == []


def test_list_campaigns_returns_created(tmp_engine):
    tmp_engine.create_campaign("test_org", _make_campaign_data(name="Camp 1"))
    tmp_engine.create_campaign("test_org", _make_campaign_data(name="Camp 2"))
    results = tmp_engine.list_campaigns("test_org")
    assert len(results) == 2


def test_list_campaigns_filter_by_status(tmp_engine):
    tmp_engine.create_campaign("test_org", _make_campaign_data(name="Staged"))
    results = tmp_engine.list_campaigns("test_org", status="staged")
    assert len(results) == 1
    assert results[0]["status"] == "staged"

    results_running = tmp_engine.list_campaigns("test_org", status="running")
    assert len(results_running) == 0


def test_list_campaigns_filter_by_type(tmp_engine):
    tmp_engine.create_campaign("test_org", _make_campaign_data(name="Web", campaign_type="web_app"))
    tmp_engine.create_campaign("test_org", _make_campaign_data(name="Net", campaign_type="network_pentest"))
    assert len(tmp_engine.list_campaigns("test_org", campaign_type="web_app")) == 1
    assert len(tmp_engine.list_campaigns("test_org", campaign_type="network_pentest")) == 1


def test_get_campaign_not_found(tmp_engine):
    result = tmp_engine.get_campaign("test_org", str(uuid.uuid4()))
    assert result is None


def test_get_campaign_includes_tasks_and_operators(tmp_engine):
    data = _make_campaign_data()
    camp = tmp_engine.create_campaign("test_org", data)
    fetched = tmp_engine.get_campaign("test_org", camp["id"])
    assert "tasks" in fetched
    assert "operators" in fetched
    assert "findings_by_severity" in fetched


# ---------------------------------------------------------------------------
# start_campaign
# ---------------------------------------------------------------------------


def test_start_campaign_transitions_to_running(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    result = tmp_engine.start_campaign("test_org", camp["id"])
    assert result["status"] == "running"
    assert result["phase"] == "recon"


def test_start_campaign_creates_tasks(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    result = tmp_engine.start_campaign("test_org", camp["id"])
    assert result["tasks_queued"] > 0
    tasks = tmp_engine.list_tasks("test_org", camp["id"])
    assert len(tasks) == result["tasks_queued"]


def test_start_campaign_tasks_are_executed(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    tasks = tmp_engine.list_tasks("test_org", camp["id"])
    for task in tasks:
        assert task["status"] in ("succeeded", "failed"), f"Task still in queued: {task}"


def test_start_campaign_may_generate_findings(tmp_engine):
    """Start multiple campaigns to ensure probabilistic finding generation works."""
    found_at_least_one = False
    for _ in range(5):
        camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
        tmp_engine.start_campaign("test_org", camp["id"])
        findings = tmp_engine.list_findings("test_org", campaign_id=camp["id"])
        if len(findings) > 0:
            found_at_least_one = True
            break
    # At 55% success rate on exploit tasks we expect findings in 5 attempts
    assert found_at_least_one, "Expected at least one finding across 5 campaigns"


def test_start_campaign_not_staged_fails(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    with pytest.raises(ValueError, match="staged"):
        tmp_engine.start_campaign("test_org", camp["id"])


def test_start_campaign_nonexistent_fails(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.start_campaign("test_org", str(uuid.uuid4()))


def test_start_campaign_has_estimated_duration(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    result = tmp_engine.start_campaign("test_org", camp["id"])
    assert "estimated_duration_minutes" in result
    assert result["estimated_duration_minutes"] > 0


# ---------------------------------------------------------------------------
# Phase advance
# ---------------------------------------------------------------------------


def test_advance_phase_changes_phase(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    result = tmp_engine.advance_phase("test_org", camp["id"])
    assert result["previous_phase"] == "recon"
    assert result["current_phase"] == "initial_access"


def test_advance_phase_queues_new_tasks(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    tasks_before = len(tmp_engine.list_tasks("test_org", camp["id"]))
    tmp_engine.advance_phase("test_org", camp["id"])
    tasks_after = len(tmp_engine.list_tasks("test_org", camp["id"]))
    assert tasks_after > tasks_before


def test_advance_phase_from_paused(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    tmp_engine.pause_campaign("test_org", camp["id"])
    result = tmp_engine.advance_phase("test_org", camp["id"])
    assert result["current_phase"] is not None


def test_advance_phase_staged_fails(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(ValueError):
        tmp_engine.advance_phase("test_org", camp["id"])


# ---------------------------------------------------------------------------
# Pause / resume
# ---------------------------------------------------------------------------


def test_pause_running_campaign(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    result = tmp_engine.pause_campaign("test_org", camp["id"])
    assert result["status"] == "paused"


def test_resume_paused_campaign(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    tmp_engine.pause_campaign("test_org", camp["id"])
    result = tmp_engine.resume_campaign("test_org", camp["id"])
    assert result["status"] == "running"


def test_pause_non_running_fails(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(ValueError):
        tmp_engine.pause_campaign("test_org", camp["id"])


def test_resume_non_paused_fails(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    with pytest.raises(ValueError):
        tmp_engine.resume_campaign("test_org", camp["id"])


# ---------------------------------------------------------------------------
# Complete
# ---------------------------------------------------------------------------


def test_complete_running_campaign(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    result = tmp_engine.complete_campaign("test_org", camp["id"])
    assert result["status"] == "completed"
    assert "risk_score" in result


def test_complete_staged_campaign_fails(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(ValueError):
        tmp_engine.complete_campaign("test_org", camp["id"])


def test_complete_sets_end_time(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    tmp_engine.complete_campaign("test_org", camp["id"])
    fetched = tmp_engine.get_campaign("test_org", camp["id"])
    assert fetched["end_time"] is not None


def test_complete_risk_score_nonnegative(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    result = tmp_engine.complete_campaign("test_org", camp["id"])
    assert result["risk_score"] >= 0.0


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def test_list_findings_empty(tmp_engine):
    assert tmp_engine.list_findings("test_org") == []


def test_update_finding_status_valid(tmp_engine):
    """Run campaigns until we get a finding to update."""
    finding = None
    for _ in range(10):
        camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
        tmp_engine.start_campaign("test_org", camp["id"])
        findings = tmp_engine.list_findings("test_org", campaign_id=camp["id"])
        if findings:
            finding = findings[0]
            break
    if finding is None:
        pytest.skip("No findings generated (probabilistic) — increase campaign count")

    result = tmp_engine.update_finding_status("test_org", finding["id"], "accepted")
    assert result["status"] == "accepted"

    result2 = tmp_engine.update_finding_status("test_org", finding["id"], "remediated")
    assert result2["status"] == "remediated"


def test_update_finding_invalid_status(tmp_engine):
    with pytest.raises(ValueError, match="Invalid finding status"):
        tmp_engine.update_finding_status("test_org", str(uuid.uuid4()), "invalid_status")


def test_update_finding_not_found(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.update_finding_status("test_org", str(uuid.uuid4()), "accepted")


def test_list_findings_filter_by_severity(tmp_engine):
    """Findings are always either severity from templates; we just verify filter works."""
    # Run campaigns to generate findings
    for _ in range(5):
        camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
        tmp_engine.start_campaign("test_org", camp["id"])

    all_findings = tmp_engine.list_findings("test_org")
    if not all_findings:
        return  # probabilistic — skip if no findings

    first_severity = all_findings[0]["severity"]
    filtered = tmp_engine.list_findings("test_org", severity=first_severity)
    assert all(f["severity"] == first_severity for f in filtered)


# ---------------------------------------------------------------------------
# Multi-tenant isolation
# ---------------------------------------------------------------------------


def test_multitenant_campaigns_isolated(tmp_path):
    db_a = str(tmp_path / "a.db")
    db_b = str(tmp_path / "b.db")
    eng_a = OpenClawEngine(org_id="org_a", db_path=db_a)
    eng_b = OpenClawEngine(org_id="org_b", db_path=db_b)

    camp_a = eng_a.create_campaign("org_a", _make_campaign_data(name="Org A Campaign"))
    camp_b = eng_b.create_campaign("org_b", _make_campaign_data(name="Org B Campaign"))

    # org_a cannot see org_b's campaign
    assert eng_a.get_campaign("org_a", camp_b["id"]) is None
    assert eng_b.get_campaign("org_b", camp_a["id"]) is None

    assert len(eng_a.list_campaigns("org_a")) == 1
    assert len(eng_b.list_campaigns("org_b")) == 1


def test_multitenant_findings_isolated(tmp_path):
    db = str(tmp_path / "shared.db")
    eng = OpenClawEngine(org_id="org_x", db_path=db)

    camp1 = eng.create_campaign("org_x", _make_campaign_data())
    camp2_data = _make_campaign_data()

    # Run org_x's campaign — findings should only appear for org_x
    eng.start_campaign("org_x", camp1["id"])

    # No findings bleed between orgs
    findings_other = eng.list_findings("org_z")
    assert findings_other == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_stats_empty_org(tmp_engine):
    stats = tmp_engine.get_stats("test_org")
    assert stats["campaign_count"] == 0
    assert stats["active_campaigns"] == 0
    assert stats["avg_risk_score"] == 0.0
    assert isinstance(stats["total_findings_by_severity"], dict)
    assert isinstance(stats["techniques_used"], list)


def test_stats_reflect_campaigns(tmp_engine):
    tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.create_campaign("test_org", _make_campaign_data(name="Second"))
    stats = tmp_engine.get_stats("test_org")
    assert stats["campaign_count"] == 2


def test_stats_active_campaigns(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    stats = tmp_engine.get_stats("test_org")
    assert stats["active_campaigns"] == 1


def test_stats_operators_deployed(tmp_engine):
    tmp_engine.create_campaign("test_org", _make_campaign_data(operators_count=3))
    stats = tmp_engine.get_stats("test_org")
    assert stats["operators_deployed"] == 3


def test_stats_techniques_used_after_start(tmp_engine):
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    tmp_engine.start_campaign("test_org", camp["id"])
    stats = tmp_engine.get_stats("test_org")
    # techniques_used lists top-5 succeeded technique IDs — may be empty if all tasks failed
    assert isinstance(stats["techniques_used"], list)
    assert len(stats["techniques_used"]) <= 5
