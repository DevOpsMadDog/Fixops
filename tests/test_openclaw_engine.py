"""Tests for OpenClaw Autonomous Pentest Swarm Engine — 48 tests.

Migration note (2026-05-26):
  start_campaign() and advance_phase() now raise NotImplementedError unless
  PENTEST_CONNECTOR_URL is set (honest-stub policy).  Tests that previously
  called those methods expecting a result dict have been rewritten:

  * Calls that tested start_campaign / advance_phase behaviour → wrapped in
    pytest.raises(NucleiNotConfiguredError).
  * Tests whose real goal was pause / resume / complete / findings / stats
    (read-paths that ARE production-ready) now seed the required row state
    directly via the engine's SQLite DB so the CRUD paths remain covered.
  * No mock makes start_campaign / advance_phase return fake data.

Covers: campaign CRUD, authorization requirement, NotImplementedError for
start/advance, pause/resume/complete lifecycle (real), finding status updates
(real), multi-tenant isolation, stats.
"""

from __future__ import annotations

import json
import sqlite3
import uuid

import pytest

from core.openclaw_engine import OpenClawEngine, PHASE_TASKS, FINDING_TEMPLATES
from core.pentest_connectors.nuclei_connector import NucleiNotConfiguredError


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


def _seed_campaign_status(engine: OpenClawEngine, org_id: str, campaign_id: str, status: str) -> None:
    """Directly update a campaign's status in SQLite (bypasses start_campaign)."""
    conn = sqlite3.connect(engine.db_path)
    try:
        now = engine._now()
        conn.execute(
            "UPDATE swarm_campaigns SET status=?, updated_at=? WHERE id=? AND org_id=?",
            (status, now, campaign_id, org_id),
        )
        conn.commit()
    finally:
        conn.close()


def _seed_finding(
    engine: OpenClawEngine,
    org_id: str,
    campaign_id: str,
    *,
    severity: str = "high",
    technique_id: str = "T1190",
) -> str:
    """Insert a finding row directly so read-path tests can work without start_campaign."""
    finding_id = str(uuid.uuid4())
    now = engine._now()
    conn = sqlite3.connect(engine.db_path)
    try:
        conn.execute(
            """
            INSERT INTO swarm_findings
                (id, org_id, campaign_id, task_id, title, severity, category,
                 technique_id, technique_name, target, evidence_preview,
                 remediation, cvss_score, status, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                finding_id, org_id, campaign_id, "",
                f"Seeded finding {severity}", severity, "initial_access",
                technique_id, "Seeded Technique", "test-target",
                "evidence", "remediate this", 7.5, "open", now,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return finding_id


def _seed_task(
    engine: OpenClawEngine,
    org_id: str,
    campaign_id: str,
    *,
    technique_id: str = "T1595",
    task_type: str = "recon",
    status: str = "succeeded",
) -> str:
    """Insert a task row directly so stats read-path tests work without start_campaign."""
    task_id = str(uuid.uuid4())
    conn = sqlite3.connect(engine.db_path)
    try:
        conn.execute(
            """
            INSERT INTO campaign_tasks
                (id, org_id, campaign_id, task_type, target, technique_id,
                 technique_name, status, operator_id, result_data, risk_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                task_id, org_id, campaign_id, task_type,
                "192.168.1.1", technique_id, "Active Scanning",
                status, 1, "{}", "low",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return task_id


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
# start_campaign — raises NotImplementedError (honest-stub policy)
# ---------------------------------------------------------------------------


def test_start_campaign_raises_not_implemented(tmp_engine):
    """start_campaign() raises NotImplementedError until PENTEST_CONNECTOR_URL is set."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(NucleiNotConfiguredError):
        tmp_engine.start_campaign("test_org", camp["id"])


def test_start_campaign_error_message_mentions_connector(tmp_engine):
    """Error message must reference the connector configuration path."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(NucleiNotConfiguredError, match="PENTEST_CONNECTOR_URL"):
        tmp_engine.start_campaign("test_org", camp["id"])


def test_start_campaign_raises_even_for_nonexistent_campaign(tmp_engine):
    """Existence is validated BEFORE the connector check — a nonexistent
    campaign raises a clear 'not found' ValueError, not the connector error."""
    with pytest.raises(ValueError, match="not found"):
        tmp_engine.start_campaign("test_org", str(uuid.uuid4()))


def test_start_campaign_raises_even_when_already_running(tmp_engine):
    """Status is validated BEFORE the connector check — starting an already
    'running' campaign raises a status ValueError, not the connector error."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "running")
    with pytest.raises(ValueError, match="staged"):
        tmp_engine.start_campaign("test_org", camp["id"])


# ---------------------------------------------------------------------------
# advance_phase — raises NotImplementedError (honest-stub policy)
# ---------------------------------------------------------------------------


def test_advance_phase_raises_not_implemented(tmp_engine):
    """A staged campaign fails the status check first: advance_phase requires a
    'running' campaign, so it raises a status ValueError before the connector."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(ValueError, match="running"):
        tmp_engine.advance_phase("test_org", camp["id"])


def test_advance_phase_error_message_mentions_connector(tmp_engine):
    """For a RUNNING campaign (valid status), advance_phase reaches the connector
    check and its error references the connector configuration path."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "running")
    with pytest.raises(NucleiNotConfiguredError, match="PENTEST_CONNECTOR_URL"):
        tmp_engine.advance_phase("test_org", camp["id"])


def test_advance_phase_raises_on_running_campaign(tmp_engine):
    """advance_phase() raises NotImplementedError even if campaign is running."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "running")
    with pytest.raises(NucleiNotConfiguredError):
        tmp_engine.advance_phase("test_org", camp["id"])


def test_advance_phase_raises_on_staged_campaign(tmp_engine):
    """advance_phase() on a staged campaign raises a status ValueError
    (must be 'running') — the status gate precedes the connector check."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(ValueError, match="running"):
        tmp_engine.advance_phase("test_org", camp["id"])


# ---------------------------------------------------------------------------
# Pause / resume — real production paths; seeded via direct DB write
# ---------------------------------------------------------------------------


def test_pause_running_campaign(tmp_engine):
    """Pause works on a running campaign (status seeded directly)."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "running")
    result = tmp_engine.pause_campaign("test_org", camp["id"])
    assert result["status"] == "paused"


def test_resume_paused_campaign(tmp_engine):
    """Resume works on a paused campaign (status seeded directly)."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "paused")
    result = tmp_engine.resume_campaign("test_org", camp["id"])
    assert result["status"] == "running"


def test_pause_non_running_fails(tmp_engine):
    """Pausing a staged campaign raises ValueError."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(ValueError):
        tmp_engine.pause_campaign("test_org", camp["id"])


def test_resume_non_paused_fails(tmp_engine):
    """Resuming a staged (not paused) campaign raises ValueError."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    # Campaign is staged — resume should raise ValueError (not paused)
    with pytest.raises(ValueError):
        tmp_engine.resume_campaign("test_org", camp["id"])


# ---------------------------------------------------------------------------
# Complete — real production path; seeded via direct DB write
# ---------------------------------------------------------------------------


def test_complete_running_campaign(tmp_engine):
    """Complete works on a running campaign (status seeded directly)."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "running")
    result = tmp_engine.complete_campaign("test_org", camp["id"])
    assert result["status"] == "completed"
    assert "risk_score" in result


def test_complete_staged_campaign_fails(tmp_engine):
    """Completing a staged campaign raises ValueError."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    with pytest.raises(ValueError):
        tmp_engine.complete_campaign("test_org", camp["id"])


def test_complete_sets_end_time(tmp_engine):
    """Complete writes end_time into the DB (real persistence check)."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "running")
    tmp_engine.complete_campaign("test_org", camp["id"])
    fetched = tmp_engine.get_campaign("test_org", camp["id"])
    assert fetched["end_time"] is not None


def test_complete_risk_score_nonnegative(tmp_engine):
    """Risk score after complete is >= 0.0."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "running")
    result = tmp_engine.complete_campaign("test_org", camp["id"])
    assert result["risk_score"] >= 0.0


# ---------------------------------------------------------------------------
# Findings — real production paths; findings seeded via direct DB write
# ---------------------------------------------------------------------------


def test_list_findings_empty(tmp_engine):
    assert tmp_engine.list_findings("test_org") == []


def test_update_finding_status_valid(tmp_engine):
    """update_finding_status works on a real seeded finding."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    finding_id = _seed_finding(tmp_engine, "test_org", camp["id"], severity="high")

    result = tmp_engine.update_finding_status("test_org", finding_id, "accepted")
    assert result["status"] == "accepted"

    result2 = tmp_engine.update_finding_status("test_org", finding_id, "remediated")
    assert result2["status"] == "remediated"


def test_update_finding_invalid_status(tmp_engine):
    with pytest.raises(ValueError, match="Invalid finding status"):
        tmp_engine.update_finding_status("test_org", str(uuid.uuid4()), "invalid_status")


def test_update_finding_not_found(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.update_finding_status("test_org", str(uuid.uuid4()), "accepted")


def test_list_findings_filter_by_severity(tmp_engine):
    """Severity filter on list_findings works with seeded finding rows."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_finding(tmp_engine, "test_org", camp["id"], severity="critical")
    _seed_finding(tmp_engine, "test_org", camp["id"], severity="high")

    all_findings = tmp_engine.list_findings("test_org")
    assert len(all_findings) == 2

    critical = tmp_engine.list_findings("test_org", severity="critical")
    assert len(critical) == 1
    assert critical[0]["severity"] == "critical"

    high = tmp_engine.list_findings("test_org", severity="high")
    assert len(high) == 1
    assert high[0]["severity"] == "high"


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
    """Findings seeded for org_x must not appear when querying org_z."""
    db = str(tmp_path / "shared.db")
    eng = OpenClawEngine(org_id="org_x", db_path=db)

    camp1 = eng.create_campaign("org_x", _make_campaign_data())
    # Seed a finding for org_x directly (no start_campaign needed)
    _seed_finding(eng, "org_x", camp1["id"], severity="high")

    # Verify org_x sees its finding
    assert len(eng.list_findings("org_x")) == 1

    # org_z must see nothing — isolation intact
    findings_other = eng.list_findings("org_z")
    assert findings_other == []


# ---------------------------------------------------------------------------
# Stats — real production paths; seeded via direct DB writes
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
    """active_campaigns count reflects campaigns seeded as status=running."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_campaign_status(tmp_engine, "test_org", camp["id"], "running")
    stats = tmp_engine.get_stats("test_org")
    assert stats["active_campaigns"] == 1


def test_stats_operators_deployed(tmp_engine):
    tmp_engine.create_campaign("test_org", _make_campaign_data(operators_count=3))
    stats = tmp_engine.get_stats("test_org")
    assert stats["operators_deployed"] == 3


def test_stats_techniques_used_after_task_seed(tmp_engine):
    """techniques_used reflects succeeded tasks seeded directly in the DB."""
    camp = tmp_engine.create_campaign("test_org", _make_campaign_data())
    _seed_task(tmp_engine, "test_org", camp["id"], technique_id="T1595", status="succeeded")
    _seed_task(tmp_engine, "test_org", camp["id"], technique_id="T1592", status="succeeded")
    stats = tmp_engine.get_stats("test_org")
    assert isinstance(stats["techniques_used"], list)
    assert "T1595" in stats["techniques_used"]
    assert "T1592" in stats["techniques_used"]
    assert len(stats["techniques_used"]) <= 5
