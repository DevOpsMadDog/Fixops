"""Tests for Bug Bounty / VDP management engine.

Covers:
- BountyProgram CRUD and status transitions
- VulnerabilitySubmission intake, auto-dedup, auto-acknowledge
- Triage workflow (accepted/rejected/duplicate/informational)
- CVSS-to-severity mapping
- Reward creation, approval, payment, bonus
- ResearcherProfile creation, reputation, Hall of Fame
- ALDECI finding generation and linking
- ProgramMetrics computation
- BugBountyRouter HTTP layer (8 endpoints)

Usage:
    pytest tests/test_bug_bounty.py -v --timeout=10
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite-core is on the path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.bug_bounty import (
    BountyProgram,
    BugBountyEngine,
    OWASPCategory,
    ProgramScope,
    ProgramStatus,
    RewardStatus,
    Severity,
    SubmissionStatus,
    _cvss_to_severity,
    get_bug_bounty_engine,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / "bug_bounty_test.db")
    yield db_path


@pytest.fixture
def engine(tmp_db):
    return BugBountyEngine(db_path=tmp_db)


@pytest.fixture
def active_program(engine):
    """Create and return an active program."""
    return engine.create_program(
        name="ALDECI VDP",
        description="Public vulnerability disclosure program",
        monthly_budget=20_000.0,
        org_id="org-test",
    )


@pytest.fixture
def submission(engine, active_program):
    """Create and return a submission against the active program."""
    return engine.submit_vulnerability(
        program_id=active_program.id,
        reporter_email="alice@hunter.io",
        reporter_name="Alice Hunter",
        affected_asset="https://api.aldeci.io",
        vuln_type=OWASPCategory.A03_INJECTION,
        title="SQL Injection in login endpoint",
        description="The /auth/login endpoint is vulnerable to SQL injection.",
        poc_steps="1. Send ' OR 1=1-- as username\n2. Observe error dump",
        impact_assessment="Authentication bypass, data exfiltration",
        org_id="org-test",
    )


# ============================================================================
# _cvss_to_severity (utility)
# ============================================================================


class TestCvssToSeverity:
    def test_critical(self):
        assert _cvss_to_severity(9.5) == Severity.CRITICAL

    def test_critical_boundary(self):
        assert _cvss_to_severity(9.0) == Severity.CRITICAL

    def test_high(self):
        assert _cvss_to_severity(8.0) == Severity.HIGH

    def test_high_boundary(self):
        assert _cvss_to_severity(7.0) == Severity.HIGH

    def test_medium(self):
        assert _cvss_to_severity(5.5) == Severity.MEDIUM

    def test_medium_boundary(self):
        assert _cvss_to_severity(4.0) == Severity.MEDIUM

    def test_low(self):
        assert _cvss_to_severity(2.0) == Severity.LOW

    def test_informational(self):
        assert _cvss_to_severity(0.0) == Severity.INFORMATIONAL


# ============================================================================
# Program Management
# ============================================================================


class TestProgramManagement:
    def test_create_program_defaults(self, engine):
        prog = engine.create_program(name="Test Program", org_id="org-1")
        assert prog.id.startswith("prog-")
        assert prog.name == "Test Program"
        assert prog.status == ProgramStatus.ACTIVE
        assert prog.org_id == "org-1"

    def test_create_program_with_budget(self, engine):
        prog = engine.create_program(name="Paid VDP", monthly_budget=5000.0, org_id="org-1")
        assert prog.monthly_budget == 5000.0

    def test_create_program_has_default_reward_tiers(self, engine):
        prog = engine.create_program(name="Tiered VDP", org_id="org-1")
        assert "critical" in prog.reward_tiers
        assert prog.reward_tiers["critical"].min_reward == 5000
        assert prog.reward_tiers["high"].min_reward == 2000
        assert prog.reward_tiers["medium"].min_reward == 500
        assert prog.reward_tiers["low"].min_reward == 100

    def test_create_program_with_scope(self, engine):
        scope = ProgramScope(
            in_scope=["api.example.com", "*.example.io"],
            out_of_scope=["legacy.example.com"],
        )
        prog = engine.create_program(name="Scoped VDP", scope=scope, org_id="org-1")
        assert "api.example.com" in prog.scope.in_scope
        assert "legacy.example.com" in prog.scope.out_of_scope

    def test_get_program(self, engine, active_program):
        fetched = engine.get_program(active_program.id)
        assert fetched is not None
        assert fetched.id == active_program.id
        assert fetched.name == active_program.name

    def test_get_program_not_found(self, engine):
        assert engine.get_program("nonexistent-id") is None

    def test_list_programs_by_org(self, engine):
        engine.create_program(name="P1", org_id="org-A")
        engine.create_program(name="P2", org_id="org-A")
        engine.create_program(name="P3", org_id="org-B")
        assert len(engine.list_programs("org-A")) == 2
        assert len(engine.list_programs("org-B")) == 1

    def test_list_programs_filter_by_status(self, engine):
        p1 = engine.create_program(name="Active", org_id="org-1")
        p2 = engine.create_program(name="Paused", org_id="org-1")
        engine.update_program_status(p2.id, ProgramStatus.PAUSED)
        active = engine.list_programs("org-1", status=ProgramStatus.ACTIVE)
        paused = engine.list_programs("org-1", status=ProgramStatus.PAUSED)
        assert len(active) == 1
        assert len(paused) == 1

    def test_update_program_status_to_paused(self, engine, active_program):
        updated = engine.update_program_status(active_program.id, ProgramStatus.PAUSED)
        assert updated.status == ProgramStatus.PAUSED

    def test_update_program_status_to_closed(self, engine, active_program):
        updated = engine.update_program_status(active_program.id, ProgramStatus.CLOSED)
        assert updated.status == ProgramStatus.CLOSED

    def test_update_program_status_unknown_program(self, engine):
        with pytest.raises(KeyError):
            engine.update_program_status("bad-id", ProgramStatus.PAUSED)

    def test_update_program_scope(self, engine, active_program):
        new_scope = ProgramScope(in_scope=["new.example.com"], out_of_scope=[])
        updated = engine.update_program_scope(active_program.id, new_scope)
        assert "new.example.com" in updated.scope.in_scope


# ============================================================================
# Submission Portal
# ============================================================================


class TestSubmissionPortal:
    def test_submit_creates_submission(self, engine, active_program):
        sub = engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="bob@sec.io",
            reporter_name="Bob",
            affected_asset="https://app.example.com",
            vuln_type=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
            title="IDOR on user profile",
            description="User can access other users' profiles.",
            org_id="org-test",
        )
        assert sub.id.startswith("sub-")
        assert sub.program_id == active_program.id
        assert sub.reporter_email == "bob@sec.io"
        assert sub.status == SubmissionStatus.NEW

    def test_submit_auto_acknowledges(self, engine, active_program):
        sub = engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="carol@sec.io",
            reporter_name="Carol",
            affected_asset="https://app.example.com",
            vuln_type=OWASPCategory.A03_INJECTION,
            title="XSS in search",
            description="Reflected XSS in search field.",
            org_id="org-test",
        )
        assert sub.acknowledged_at is not None

    def test_submit_sets_sla_deadline(self, engine, active_program):
        sub = engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="dave@sec.io",
            reporter_name="Dave",
            affected_asset="https://admin.example.com",
            vuln_type=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
            title="Admin panel exposed",
            description="Admin panel accessible without auth.",
            org_id="org-test",
        )
        assert sub.sla_deadline is not None

    def test_submit_creates_researcher_profile(self, engine, active_program):
        engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="eve@sec.io",
            reporter_name="Eve",
            affected_asset="https://api.example.com",
            vuln_type=OWASPCategory.A07_AUTH_FAILURES,
            title="Weak password policy",
            description="No password complexity requirements.",
            org_id="org-test",
        )
        researcher = engine.get_researcher_by_email("eve@sec.io", "org-test")
        assert researcher is not None
        assert researcher.total_submissions == 1

    def test_submit_to_paused_program_raises(self, engine, active_program):
        engine.update_program_status(active_program.id, ProgramStatus.PAUSED)
        with pytest.raises(ValueError, match="not accepting submissions"):
            engine.submit_vulnerability(
                program_id=active_program.id,
                reporter_email="frank@sec.io",
                reporter_name="Frank",
                affected_asset="https://api.example.com",
                vuln_type=OWASPCategory.A03_INJECTION,
                title="Test",
                description="Test",
                org_id="org-test",
            )

    def test_submit_duplicate_detected(self, engine, active_program, submission):
        # Second submission for same asset + vuln type
        dup = engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="grace@sec.io",
            reporter_name="Grace",
            affected_asset="https://api.aldeci.io",
            vuln_type=OWASPCategory.A03_INJECTION,
            title="Another SQLi",
            description="Same injection, different parameter.",
            org_id="org-test",
        )
        assert dup.status == SubmissionStatus.DUPLICATE
        assert dup.duplicate_of == submission.id

    def test_submit_increments_program_count(self, engine, active_program):
        engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="hank@sec.io",
            reporter_name="Hank",
            affected_asset="https://other.example.com",
            vuln_type=OWASPCategory.A10_SSRF,
            title="SSRF via redirect",
            description="SSRF via unvalidated redirect parameter.",
            org_id="org-test",
        )
        prog = engine.get_program(active_program.id)
        assert prog.submission_count >= 1


# ============================================================================
# Triage Workflow
# ============================================================================


class TestTriageWorkflow:
    def test_triage_accepted(self, engine, submission):
        triaged = engine.triage_submission(
            submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH
        )
        assert triaged.status == SubmissionStatus.ACCEPTED
        assert triaged.severity == Severity.HIGH
        assert triaged.triaged_at is not None

    def test_triage_rejected(self, engine, submission):
        triaged = engine.triage_submission(
            submission.id, SubmissionStatus.REJECTED, notes="Out of scope"
        )
        assert triaged.status == SubmissionStatus.REJECTED
        assert triaged.triage_notes == "Out of scope"

    def test_triage_informational(self, engine, submission):
        triaged = engine.triage_submission(submission.id, SubmissionStatus.INFORMATIONAL)
        assert triaged.status == SubmissionStatus.INFORMATIONAL

    def test_triage_with_cvss_infers_severity(self, engine, submission):
        triaged = engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, cvss_score=8.5)
        assert triaged.severity == Severity.HIGH
        assert triaged.cvss_score == 8.5

    def test_triage_critical_cvss(self, engine, submission):
        triaged = engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, cvss_score=9.1)
        assert triaged.severity == Severity.CRITICAL

    def test_triage_accepted_creates_reward(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        sub = engine.get_submission(submission.id)
        assert sub.reward_id is not None

    def test_triage_accepted_updates_researcher_reputation(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.MEDIUM)
        researcher = engine.get_researcher_by_email("alice@hunter.io", "org-test")
        assert researcher.accepted_submissions == 1
        assert researcher.reputation_score > 0

    def test_triage_triaging_state(self, engine, submission):
        triaged = engine.triage_submission(submission.id, SubmissionStatus.TRIAGING)
        assert triaged.status == SubmissionStatus.TRIAGING

    def test_triage_updates_sla_by_severity(self, engine, submission):
        original_sla = submission.sla_deadline
        triaged = engine.triage_submission(
            submission.id, SubmissionStatus.ACCEPTED, severity=Severity.CRITICAL
        )
        # CRITICAL has shorter SLA (4h) vs default MEDIUM (72h)
        assert triaged.sla_deadline != original_sla

    def test_resolve_accepted_submission(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        resolved = engine.resolve_submission(submission.id)
        assert resolved.status == SubmissionStatus.FIXED
        assert resolved.resolved_at is not None

    def test_resolve_non_accepted_raises(self, engine, submission):
        with pytest.raises(ValueError, match="Only accepted submissions"):
            engine.resolve_submission(submission.id)


# ============================================================================
# Reward Processing
# ============================================================================


class TestRewardProcessing:
    def test_reward_created_on_acceptance(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        sub = engine.get_submission(submission.id)
        reward = engine.get_reward(sub.reward_id)
        assert reward is not None
        assert reward.status == RewardStatus.PENDING
        assert reward.amount == 2000.0  # HIGH default

    def test_reward_amount_critical(self, engine, active_program):
        sub = engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="ivan@sec.io",
            reporter_name="Ivan",
            affected_asset="https://crit.example.com",
            vuln_type=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            title="RCE via deserialization",
            description="Remote code execution via unsafe deserialization.",
            org_id="org-test",
        )
        engine.triage_submission(sub.id, SubmissionStatus.ACCEPTED, severity=Severity.CRITICAL)
        reward = engine.get_reward(engine.get_submission(sub.id).reward_id)
        assert reward.amount == 5000.0

    def test_approve_reward(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.MEDIUM)
        sub = engine.get_submission(submission.id)
        reward = engine.update_reward_status(sub.reward_id, RewardStatus.APPROVED)
        assert reward.status == RewardStatus.APPROVED
        assert reward.approved_at is not None

    def test_pay_reward_updates_researcher_earnings(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        sub = engine.get_submission(submission.id)
        engine.update_reward_status(sub.reward_id, RewardStatus.PAID)
        researcher = engine.get_researcher_by_email("alice@hunter.io", "org-test")
        assert researcher.total_earnings == 2000.0

    def test_pay_reward_with_bonus(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        sub = engine.get_submission(submission.id)
        engine.update_reward_status(sub.reward_id, RewardStatus.PAID, bonus_amount=500.0)
        researcher = engine.get_researcher_by_email("alice@hunter.io", "org-test")
        assert researcher.total_earnings == 2500.0

    def test_pay_reward_updates_program_total(self, engine, submission, active_program):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        sub = engine.get_submission(submission.id)
        engine.update_reward_status(sub.reward_id, RewardStatus.PAID)
        prog = engine.get_program(active_program.id)
        assert prog.total_rewards_paid == 2000.0

    def test_dispute_reward(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        sub = engine.get_submission(submission.id)
        reward = engine.update_reward_status(sub.reward_id, RewardStatus.DISPUTED, notes="Amount contested")
        assert reward.status == RewardStatus.DISPUTED
        assert "contested" in reward.notes

    def test_list_rewards_by_program(self, engine, active_program, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        rewards = engine.list_rewards("org-test", program_id=active_program.id)
        assert len(rewards) >= 1


# ============================================================================
# Reporter Management
# ============================================================================


class TestReporterManagement:
    def test_researcher_auto_created_on_first_submission(self, engine, active_program):
        engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="judy@research.io",
            reporter_name="Judy",
            affected_asset="https://new.example.com",
            vuln_type=OWASPCategory.A04_INSECURE_DESIGN,
            title="Logic flaw",
            description="Business logic flaw in checkout.",
            org_id="org-test",
        )
        researcher = engine.get_researcher_by_email("judy@research.io", "org-test")
        assert researcher is not None
        assert researcher.name == "Judy"

    def test_update_researcher_profile(self, engine, active_program, submission):
        researcher = engine.get_researcher_by_email("alice@hunter.io", "org-test")
        updated = engine.update_researcher_profile(
            researcher.id, handle="alice_h4x0r", preferred_contact="keybase"
        )
        assert updated.handle == "alice_h4x0r"
        assert updated.preferred_contact == "keybase"

    def test_hall_of_fame_promotion(self, engine, active_program, submission):
        researcher = engine.get_researcher_by_email("alice@hunter.io", "org-test")
        promoted = engine.promote_to_hall_of_fame(researcher.id)
        assert promoted.hall_of_fame is True

    def test_hall_of_fame_auto_on_10k_earnings(self, engine, active_program):
        # Submit and pay enough to cross $10K threshold
        sub = engine.submit_vulnerability(
            program_id=active_program.id,
            reporter_email="kevin@elite.io",
            reporter_name="Kevin",
            affected_asset="https://payments.example.com",
            vuln_type=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
            title="Crypto weakness",
            description="Weak key derivation in payment flow.",
            org_id="org-test",
        )
        engine.triage_submission(sub.id, SubmissionStatus.ACCEPTED, severity=Severity.CRITICAL)
        fetched_sub = engine.get_submission(sub.id)
        engine.update_reward_status(fetched_sub.reward_id, RewardStatus.PAID, bonus_amount=5001.0)
        researcher = engine.get_researcher_by_email("kevin@elite.io", "org-test")
        assert researcher.hall_of_fame is True

    def test_list_researchers(self, engine, active_program, submission):
        researchers = engine.list_researchers("org-test")
        assert len(researchers) >= 1

    def test_list_hall_of_fame_only(self, engine, active_program, submission):
        researcher = engine.get_researcher_by_email("alice@hunter.io", "org-test")
        engine.promote_to_hall_of_fame(researcher.id)
        hof = engine.list_researchers("org-test", hall_of_fame_only=True)
        assert len(hof) == 1

    def test_leaderboard_returns_top_researchers(self, engine, active_program, submission):
        lb = engine.get_leaderboard("org-test", limit=5)
        assert isinstance(lb, list)
        assert len(lb) >= 1
        assert "total_earnings" in lb[0]


# ============================================================================
# ALDECI Finding Integration
# ============================================================================


class TestALDECIIntegration:
    def test_generate_finding_from_accepted_submission(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        finding = engine.create_aldeci_finding_from_submission(submission.id)
        assert finding["source"] == "bug_bounty"
        assert finding["title"] == submission.title
        assert finding["severity"] == "high"
        assert finding["submission_id"] == submission.id

    def test_finding_includes_poc(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        finding = engine.create_aldeci_finding_from_submission(submission.id)
        assert "1. Send" in finding["poc"]

    def test_generate_finding_from_fixed_submission(self, engine, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        engine.resolve_submission(submission.id)
        finding = engine.create_aldeci_finding_from_submission(submission.id)
        assert finding["status"] == "fixed"
        assert finding["resolved_at"] is not None

    def test_generate_finding_from_new_raises(self, engine, submission):
        with pytest.raises(ValueError, match="must be accepted or fixed"):
            engine.create_aldeci_finding_from_submission(submission.id)

    def test_link_aldeci_finding(self, engine, submission):
        linked = engine.link_aldeci_finding(submission.id, "aldeci-finding-001")
        assert linked.aldeci_finding_id == "aldeci-finding-001"


# ============================================================================
# Metrics
# ============================================================================


class TestProgramMetrics:
    def test_metrics_empty_program(self, engine, active_program):
        metrics = engine.get_program_metrics(active_program.id, org_id="org-test")
        assert metrics.program_id == active_program.id
        assert metrics.total_submissions == 0
        assert metrics.acceptance_rate == 0.0

    def test_metrics_after_submissions(self, engine, active_program, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        metrics = engine.get_program_metrics(active_program.id, org_id="org-test")
        assert metrics.total_submissions >= 1
        assert "accepted" in metrics.submissions_by_status

    def test_metrics_acceptance_rate(self, engine, active_program):
        for i in range(3):
            sub = engine.submit_vulnerability(
                program_id=active_program.id,
                reporter_email=f"reporter{i}@sec.io",
                reporter_name=f"Reporter {i}",
                affected_asset=f"https://target{i}.example.com",
                vuln_type=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                title=f"Finding {i}",
                description=f"Description {i}",
                org_id="org-test",
            )
            if i < 2:
                engine.triage_submission(sub.id, SubmissionStatus.ACCEPTED, severity=Severity.LOW)
            else:
                engine.triage_submission(sub.id, SubmissionStatus.REJECTED)
        metrics = engine.get_program_metrics(active_program.id, org_id="org-test")
        assert metrics.acceptance_rate > 0.0

    def test_metrics_roi_estimate(self, engine, active_program, submission):
        engine.triage_submission(submission.id, SubmissionStatus.ACCEPTED, severity=Severity.HIGH)
        metrics = engine.get_program_metrics(active_program.id, org_id="org-test")
        assert "roi_ratio" in metrics.roi_estimate
        assert "estimated_breach_cost_avoided" in metrics.roi_estimate

    def test_metrics_top_reporters(self, engine, active_program, submission):
        metrics = engine.get_program_metrics(active_program.id, org_id="org-test")
        assert isinstance(metrics.top_reporters, list)

    def test_metrics_unknown_program_raises(self, engine):
        with pytest.raises(KeyError):
            engine.get_program_metrics("nonexistent", org_id="org-test")


# ============================================================================
# HTTP Router (FastAPI test client)
# ============================================================================


@pytest.fixture
def client(tmp_db):
    """Return a TestClient wired to a fresh engine instance."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Reset module-level singleton so each test gets a fresh engine
    import core.bug_bounty as bb_module
    bb_module._engine_instance = None

    # Point the singleton to the tmp db
    bb_module._DEFAULT_DB = tmp_db

    # suite-api is on sys.path via sitecustomize.py; import directly
    from apps.api.bug_bounty_router import router  # noqa: PLC0415

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _create_program(client) -> Dict:
    resp = client.post(
        "/api/v1/bounty/programs",
        json={"name": "HTTP Test VDP", "org_id": "org-http", "monthly_budget": 10000},
    )
    assert resp.status_code == 200
    return resp.json()


class TestBugBountyRouter:
    def test_create_program(self, client):
        prog = _create_program(client)
        assert prog["name"] == "HTTP Test VDP"
        assert prog["status"] == "active"

    def test_list_programs(self, client):
        _create_program(client)
        resp = client.get("/api/v1/bounty/programs", params={"org_id": "org-http"})
        assert resp.status_code == 200
        programs = resp.json()
        assert len(programs) >= 1

    def test_update_program_status(self, client):
        prog = _create_program(client)
        resp = client.patch(
            f"/api/v1/bounty/programs/{prog['id']}/status",
            json={"status": "paused"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "paused"

    def test_update_program_status_not_found(self, client):
        resp = client.patch(
            "/api/v1/bounty/programs/no-such/status",
            json={"status": "paused"},
        )
        assert resp.status_code == 404

    def test_submit_vulnerability(self, client):
        prog = _create_program(client)
        resp = client.post(
            "/api/v1/bounty/submissions",
            json={
                "program_id": prog["id"],
                "reporter_email": "test@hunter.io",
                "reporter_name": "Test Hunter",
                "affected_asset": "https://http-test.example.com",
                "vuln_type": "A03:2021-Injection",
                "title": "HTTP SQLi",
                "description": "SQL injection via HTTP test client.",
                "org_id": "org-http",
            },
        )
        assert resp.status_code == 200
        sub = resp.json()
        assert sub["reporter_email"] == "test@hunter.io"
        assert sub["status"] == "new"

    def test_submit_to_paused_program_returns_400(self, client):
        prog = _create_program(client)
        client.patch(
            f"/api/v1/bounty/programs/{prog['id']}/status",
            json={"status": "paused"},
        )
        resp = client.post(
            "/api/v1/bounty/submissions",
            json={
                "program_id": prog["id"],
                "reporter_email": "x@y.io",
                "reporter_name": "X",
                "affected_asset": "https://a.example.com",
                "vuln_type": "Other",
                "title": "X",
                "description": "X",
                "org_id": "org-http",
            },
        )
        assert resp.status_code == 400

    def test_list_submissions(self, client):
        prog = _create_program(client)
        client.post(
            "/api/v1/bounty/submissions",
            json={
                "program_id": prog["id"],
                "reporter_email": "list@test.io",
                "reporter_name": "Lister",
                "affected_asset": "https://list.example.com",
                "vuln_type": "Other",
                "title": "List test",
                "description": "Testing list endpoint.",
                "org_id": "org-http",
            },
        )
        resp = client.get("/api/v1/bounty/submissions", params={"org_id": "org-http"})
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_triage_submission(self, client):
        prog = _create_program(client)
        sub_resp = client.post(
            "/api/v1/bounty/submissions",
            json={
                "program_id": prog["id"],
                "reporter_email": "triage@test.io",
                "reporter_name": "Triager",
                "affected_asset": "https://triage.example.com",
                "vuln_type": "A03:2021-Injection",
                "title": "Triage test",
                "description": "Testing triage endpoint.",
                "org_id": "org-http",
            },
        )
        sub = sub_resp.json()
        resp = client.patch(
            f"/api/v1/bounty/submissions/{sub['id']}/triage",
            json={"decision": "accepted", "severity": "high", "cvss_score": 7.5},
        )
        assert resp.status_code == 200
        triaged = resp.json()
        assert triaged["status"] == "accepted"
        assert triaged["severity"] == "high"

    def test_update_reward(self, client):
        prog = _create_program(client)
        sub_resp = client.post(
            "/api/v1/bounty/submissions",
            json={
                "program_id": prog["id"],
                "reporter_email": "reward@test.io",
                "reporter_name": "Reward Hunter",
                "affected_asset": "https://reward.example.com",
                "vuln_type": "A02:2021-Cryptographic Failures",
                "title": "Crypto issue",
                "description": "Weak cipher used.",
                "org_id": "org-http",
            },
        )
        sub = sub_resp.json()
        triage_resp = client.patch(
            f"/api/v1/bounty/submissions/{sub['id']}/triage",
            json={"decision": "accepted", "severity": "medium"},
        )
        reward_id = triage_resp.json()["reward_id"]
        resp = client.patch(
            f"/api/v1/bounty/rewards/{reward_id}",
            json={"status": "approved", "bonus_amount": 0, "notes": "Approved"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

    def test_get_program_metrics(self, client):
        prog = _create_program(client)
        resp = client.get(
            f"/api/v1/bounty/programs/{prog['id']}/metrics",
            params={"org_id": "org-http"},
        )
        assert resp.status_code == 200
        metrics = resp.json()
        assert "total_submissions" in metrics
        assert "roi_estimate" in metrics

    def test_get_metrics_not_found(self, client):
        resp = client.get(
            "/api/v1/bounty/programs/no-such/metrics",
            params={"org_id": "org-http"},
        )
        assert resp.status_code == 404
