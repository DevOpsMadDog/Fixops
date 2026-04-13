"""
Tests for the Security Training & Awareness Tracker — 47 tests covering:
- Training catalog: built-in modules, categories, custom modules
- Role-based requirements: per-role auto-assignment on registration
- Completion tracking: assignment, start, record, per-user, per-department
- Compliance integration: framework coverage mapping
- Effectiveness metrics: pre/post scores, improvement, phishing click rates
- Gamification: points, badges, leaderboards, streaks
- Certification management: add, status computation, expiry, expiring-soon query

Run with: python -m pytest tests/test_security_training.py -v --timeout=10
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.security_training import (
    BadgeType,
    CertificationStatus,
    CompletionStatus,
    ComplianceFramework,
    ComplianceMapping,
    DepartmentStats,
    ExternalCertification,
    LeaderboardEntry,
    PhishingSimulation,
    SecurityTrainingTracker,
    TrainingCategory,
    TrainingCompletion,
    TrainingModule,
    UserRole,
    UserTrainingProfile,
    _BADGE_POINTS,
    _BUILT_IN_MODULES,
    _ROLE_REQUIREMENTS,
    get_training_tracker,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def tracker(tmp_path):
    """Fresh SecurityTrainingTracker backed by a temp SQLite DB."""
    return SecurityTrainingTracker(db_path=str(tmp_path / "training_test.db"))


@pytest.fixture
def org():
    return f"org-{uuid.uuid4().hex[:8]}"


def _make_profile(
    role: UserRole = UserRole.DEVELOPER,
    department: str = "Engineering",
    org_id: str = "default",
    opt_in: bool = True,
) -> UserTrainingProfile:
    uid = f"u-{uuid.uuid4().hex[:8]}"
    return UserTrainingProfile(
        user_id=uid,
        email=f"{uid}@example.com",
        display_name=f"User {uid}",
        role=role,
        department=department,
        org_id=org_id,
        opt_in_gamification=opt_in,
    )


def _register(tracker: SecurityTrainingTracker, **kwargs) -> UserTrainingProfile:
    profile = _make_profile(**kwargs)
    return tracker.register_user(profile)


# ============================================================================
# TRAINING CATALOG
# ============================================================================


class TestTrainingCatalog:
    def test_catalog_returns_at_least_20_modules(self, tracker):
        modules = tracker.get_catalog()
        assert len(modules) >= 20

    def test_catalog_matches_built_in_count(self, tracker):
        modules = tracker.get_catalog()
        assert len(modules) == len(_BUILT_IN_MODULES)

    def test_get_module_by_id_returns_correct_module(self, tracker):
        mod = tracker.get_module("owasp-top10")
        assert mod is not None
        assert mod.title == "OWASP Top 10 Security Risks"
        assert mod.category == TrainingCategory.SECURE_CODING

    def test_get_unknown_module_returns_none(self, tracker):
        result = tracker.get_module("does-not-exist-xyz")
        assert result is None

    def test_filter_catalog_by_category(self, tracker):
        mods = tracker.get_catalog(category=TrainingCategory.CLOUD_SECURITY.value)
        assert len(mods) >= 1
        assert all(m.category == TrainingCategory.CLOUD_SECURITY for m in mods)

    def test_filter_catalog_by_role_developer(self, tracker):
        mods = tracker.get_catalog(role=UserRole.DEVELOPER.value)
        for m in mods:
            assert (not m.required_roles) or (UserRole.DEVELOPER.value in m.required_roles)

    def test_all_built_in_modules_have_positive_points(self, tracker):
        for mod in tracker.get_catalog():
            assert mod.points > 0, f"{mod.id} has zero points"

    def test_all_built_in_modules_have_valid_duration(self, tracker):
        for mod in tracker.get_catalog():
            assert 5 <= mod.duration_minutes <= 480, f"{mod.id} duration out of range"

    def test_all_built_in_modules_are_active(self, tracker):
        for mod in tracker.get_catalog():
            assert mod.active is True

    def test_add_custom_module_appears_in_catalog(self, tracker):
        custom = TrainingModule(
            id="custom-test-module",
            title="Custom Security 101",
            description="Custom description for testing",
            category=TrainingCategory.COMPLIANCE,
            duration_minutes=30,
            passing_score=70,
            points=90,
        )
        tracker.add_module(custom)
        mod = tracker.get_module("custom-test-module")
        assert mod is not None
        assert mod.title == "Custom Security 101"

    def test_owasp_module_has_soc2_compliance_mapping(self, tracker):
        mod = tracker.get_module("owasp-top10")
        frameworks = [m.framework for m in mod.compliance_mappings]
        assert ComplianceFramework.SOC2 in frameworks

    def test_phishing_awareness_module_has_passing_score_80(self, tracker):
        mod = tracker.get_module("phishing-awareness")
        assert mod is not None
        assert mod.passing_score == 80

    def test_security_champions_program_has_highest_points(self, tracker):
        champion_mod = tracker.get_module("security-champions-program")
        all_mods = tracker.get_catalog()
        max_points = max(m.points for m in all_mods)
        assert champion_mod.points == max_points


# ============================================================================
# ROLE-BASED REQUIREMENTS
# ============================================================================


class TestRoleBasedRequirements:
    def test_developer_gets_owasp_assigned_on_register(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        completions = tracker.get_user_completions(profile.user_id)
        module_ids = {c.module_id for c in completions}
        assert "owasp-top10" in module_ids

    def test_devops_gets_cloud_security_fundamentals_on_register(self, tracker):
        profile = _register(tracker, role=UserRole.DEVOPS)
        completions = tracker.get_user_completions(profile.user_id)
        module_ids = {c.module_id for c in completions}
        assert "cloud-security-fundamentals" in module_ids

    def test_manager_gets_risk_awareness_on_register(self, tracker):
        profile = _register(tracker, role=UserRole.MANAGER)
        completions = tracker.get_user_completions(profile.user_id)
        module_ids = {c.module_id for c in completions}
        assert "risk-awareness-managers" in module_ids

    def test_executive_gets_board_level_risk_on_register(self, tracker):
        profile = _register(tracker, role=UserRole.EXECUTIVE)
        completions = tracker.get_user_completions(profile.user_id)
        module_ids = {c.module_id for c in completions}
        assert "board-level-risk" in module_ids

    def test_security_champion_gets_threat_modeling_on_register(self, tracker):
        profile = _register(tracker, role=UserRole.SECURITY_CHAMPION)
        completions = tracker.get_user_completions(profile.user_id)
        module_ids = {c.module_id for c in completions}
        assert "threat-modeling-stride" in module_ids

    def test_all_staff_gets_phishing_awareness_on_register(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        completions = tracker.get_user_completions(profile.user_id)
        module_ids = {c.module_id for c in completions}
        assert "phishing-awareness" in module_ids

    def test_role_requirements_dict_covers_all_roles(self):
        for role in UserRole:
            assert role in _ROLE_REQUIREMENTS, f"{role} missing from _ROLE_REQUIREMENTS"

    def test_developer_assigned_count_matches_role_requirements(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        completions = tracker.get_user_completions(profile.user_id)
        expected = len(_ROLE_REQUIREMENTS[UserRole.DEVELOPER])
        assert len(completions) == expected


# ============================================================================
# COMPLETION TRACKING
# ============================================================================


class TestCompletionTracking:
    def test_assign_training_returns_not_started_status(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        completion = tracker.assign_training(profile.user_id, "phishing-awareness")
        assert completion.status == CompletionStatus.NOT_STARTED

    def test_assign_training_is_idempotent(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        c1 = tracker.assign_training(profile.user_id, "phishing-awareness")
        c2 = tracker.assign_training(profile.user_id, "phishing-awareness")
        assert c1.id == c2.id

    def test_start_training_sets_in_progress_status(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        tracker.assign_training(profile.user_id, "password-mfa-hygiene")
        completion = tracker.start_training(profile.user_id, "password-mfa-hygiene")
        assert completion is not None
        assert completion.status == CompletionStatus.IN_PROGRESS

    def test_record_completion_with_passing_score_marks_completed(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        tracker.assign_training(profile.user_id, "phishing-awareness")
        completion = tracker.record_completion(profile.user_id, "phishing-awareness", score=85)
        assert completion is not None
        assert completion.status == CompletionStatus.COMPLETED
        assert completion.passed is True

    def test_record_completion_below_passing_score_does_not_complete(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        tracker.assign_training(profile.user_id, "phishing-awareness")
        completion = tracker.record_completion(profile.user_id, "phishing-awareness", score=50)
        assert completion is not None
        assert completion.passed is False
        assert completion.status != CompletionStatus.COMPLETED

    def test_passing_completion_generates_certificate_id(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        tracker.assign_training(profile.user_id, "phishing-awareness")
        completion = tracker.record_completion(profile.user_id, "phishing-awareness", score=90)
        assert completion.certificate_id is not None
        assert completion.certificate_id.startswith("cert-")

    def test_failed_completion_has_no_certificate(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        tracker.assign_training(profile.user_id, "phishing-awareness")
        completion = tracker.record_completion(profile.user_id, "phishing-awareness", score=40)
        assert completion.certificate_id is None

    def test_record_completion_unknown_module_returns_none(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        result = tracker.record_completion(profile.user_id, "nonexistent-module-xyz", score=100)
        assert result is None

    def test_get_user_completions_returns_all_assignments(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        completions = tracker.get_user_completions(profile.user_id)
        expected = len(_ROLE_REQUIREMENTS[UserRole.DEVELOPER])
        assert len(completions) == expected

    def test_get_overdue_users_returns_past_due_assignments(self, tracker, org):
        # Use EXECUTIVE role so auto-assigned modules don't conflict with board-level-risk
        # assignment below. board-level-risk is in EXECUTIVE's required list, but we
        # need a module NOT already auto-assigned.  Use a custom module to avoid the
        # idempotency guard returning the existing record with a future due date.
        custom = TrainingModule(
            id="overdue-test-module",
            title="Overdue Test Module",
            description="Used only in overdue detection test",
            category=TrainingCategory.COMPLIANCE,
            duration_minutes=10,
            passing_score=70,
            points=10,
        )
        tracker.add_module(custom)
        profile = _make_profile(org_id=org)
        tracker.register_user(profile)
        # Assign the custom module with a past due date
        tracker.assign_training(profile.user_id, "overdue-test-module", due_days=-1)
        overdue = tracker.get_overdue_users(org_id=org)
        user_ids = {o["user_id"] for o in overdue}
        assert profile.user_id in user_ids

    def test_get_department_stats_returns_correct_dept(self, tracker, org):
        profile = _make_profile(department="InfoSec", org_id=org)
        tracker.register_user(profile)
        stats = tracker.get_department_stats(org_id=org)
        depts = {s.department for s in stats}
        assert "InfoSec" in depts

    def test_department_stats_completion_rate_zero_before_any_completion(self, tracker, org):
        profile = _make_profile(department="DevOps", org_id=org)
        tracker.register_user(profile)
        stats = tracker.get_department_stats(org_id=org)
        devops_stat = next(s for s in stats if s.department == "DevOps")
        assert devops_stat.completion_rate == 0.0

    def test_department_stats_completion_rate_increases_after_pass(self, tracker, org):
        profile = _make_profile(role=UserRole.ALL_STAFF, department="Sales", org_id=org)
        tracker.register_user(profile)
        # ALL_STAFF gets 4 modules; complete one
        tracker.record_completion(profile.user_id, "phishing-awareness", score=90)
        stats = tracker.get_department_stats(org_id=org)
        sales_stat = next((s for s in stats if s.department == "Sales"), None)
        assert sales_stat is not None
        assert sales_stat.completion_rate > 0.0

    def test_org_summary_reflects_registered_users(self, tracker, org):
        _register(tracker, org_id=org)
        _register(tracker, org_id=org)
        summary = tracker.get_org_summary(org_id=org)
        assert summary["total_users"] == 2

    def test_org_summary_catalog_size_matches_built_ins(self, tracker, org):
        summary = tracker.get_org_summary(org_id=org)
        assert summary["catalog_size"] == len(_BUILT_IN_MODULES)


# ============================================================================
# COMPLIANCE INTEGRATION
# ============================================================================


class TestComplianceIntegration:
    def test_soc2_coverage_returns_non_empty_controls(self, tracker):
        result = tracker.get_compliance_coverage(ComplianceFramework.SOC2.value)
        assert result["framework"] == ComplianceFramework.SOC2.value
        assert len(result["controls"]) > 0

    def test_hipaa_coverage_contains_phishing_module(self, tracker):
        result = tracker.get_compliance_coverage(ComplianceFramework.HIPAA.value)
        module_ids = [c["module_id"] for c in result["controls"]]
        assert "phishing-awareness" in module_ids

    def test_gdpr_coverage_contains_data_handling_module(self, tracker):
        result = tracker.get_compliance_coverage(ComplianceFramework.GDPR.value)
        module_ids = [c["module_id"] for c in result["controls"]]
        assert "data-handling-classification" in module_ids

    def test_coverage_percentage_is_zero_with_no_users(self, tracker):
        org = f"empty-{uuid.uuid4().hex[:6]}"
        result = tracker.get_compliance_coverage(ComplianceFramework.SOC2.value, org_id=org)
        assert result["coverage_percentage"] == 0.0

    def test_unknown_framework_returns_empty_controls(self, tracker):
        result = tracker.get_compliance_coverage("nonexistent-framework-xyz")
        assert result["controls"] == []
        assert result["coverage_percentage"] == 0.0

    def test_pci_dss_coverage_lists_control_ids(self, tracker):
        result = tracker.get_compliance_coverage(ComplianceFramework.PCI_DSS.value)
        for control in result["controls"]:
            assert "control_id" in control
            assert control["control_id"]  # non-empty


# ============================================================================
# EFFECTIVENESS METRICS
# ============================================================================


class TestEffectivenessMetrics:
    def test_effectiveness_no_completions_returns_minimal_dict(self, tracker):
        result = tracker.get_effectiveness_metrics("owasp-top10")
        assert result["module_id"] == "owasp-top10"
        assert result["completions"] == 0

    def test_effectiveness_after_completion_counts_correctly(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        tracker.record_completion(
            profile.user_id, "owasp-top10", score=80,
            time_spent_minutes=60, pre_quiz_score=40,
        )
        result = tracker.get_effectiveness_metrics("owasp-top10")
        assert result["completions"] == 1
        assert result["avg_post_quiz_score"] == 80.0

    def test_effectiveness_score_improvement_computed(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        tracker.record_completion(
            profile.user_id, "owasp-top10", score=85,
            pre_quiz_score=45,
        )
        result = tracker.get_effectiveness_metrics("owasp-top10")
        assert result["score_improvement"] is not None
        assert result["score_improvement"] > 0

    def test_effectiveness_avg_time_computed_when_provided(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        tracker.record_completion(
            profile.user_id, "owasp-top10", score=80,
            time_spent_minutes=45,
        )
        result = tracker.get_effectiveness_metrics("owasp-top10")
        assert result["avg_time_spent_minutes"] == 45.0

    def test_phishing_effectiveness_no_simulations(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        result = tracker.get_phishing_effectiveness(profile.user_id)
        assert result["simulations_sent"] == 0

    def test_phishing_effectiveness_click_rate_computed(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        now = datetime.now(timezone.utc)
        # Record 2 simulations: 1 clicked, 1 not
        tracker.record_phishing_simulation(PhishingSimulation(
            user_id=profile.user_id, campaign_id="camp-1",
            sent_at=now - timedelta(days=10), clicked=True,
            clicked_at=now - timedelta(days=10),
        ))
        tracker.record_phishing_simulation(PhishingSimulation(
            user_id=profile.user_id, campaign_id="camp-2",
            sent_at=now - timedelta(days=5), clicked=False,
        ))
        result = tracker.get_phishing_effectiveness(profile.user_id)
        assert result["simulations_sent"] == 2
        assert result["pre_training_click_rate"] is not None


# ============================================================================
# GAMIFICATION
# ============================================================================


class TestGamification:
    def test_completing_module_awards_module_points(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        mod = tracker.get_module("phishing-awareness")
        tracker.record_completion(profile.user_id, "phishing-awareness", score=90)
        updated = tracker.get_user_profile(profile.user_id)
        assert updated.points >= mod.points

    def test_first_completion_awards_first_completion_badge(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        tracker.record_completion(profile.user_id, "phishing-awareness", score=90)
        updated = tracker.get_user_profile(profile.user_id)
        assert BadgeType.FIRST_COMPLETION.value in updated.badges

    def test_perfect_score_awards_perfect_score_badge(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        tracker.record_completion(profile.user_id, "phishing-awareness", score=100)
        updated = tracker.get_user_profile(profile.user_id)
        assert BadgeType.PERFECT_SCORE.value in updated.badges

    def test_speed_learner_badge_awarded_when_under_half_duration(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        mod = tracker.get_module("phishing-awareness")  # 30 min duration
        tracker.record_completion(
            profile.user_id, "phishing-awareness", score=85,
            time_spent_minutes=mod.duration_minutes // 2 - 1,
        )
        updated = tracker.get_user_profile(profile.user_id)
        assert BadgeType.SPEED_LEARNER.value in updated.badges

    def test_security_champion_badge_on_champions_program_completion(self, tracker):
        profile = _register(tracker, role=UserRole.SECURITY_CHAMPION)
        tracker.record_completion(profile.user_id, "security-champions-program", score=85)
        updated = tracker.get_user_profile(profile.user_id)
        assert BadgeType.SECURITY_CHAMPION.value in updated.badges

    def test_gamification_opt_out_user_receives_no_points(self, tracker):
        profile = _make_profile(opt_in=False)
        tracker.register_user(profile)
        tracker.assign_training(profile.user_id, "phishing-awareness")
        tracker.record_completion(profile.user_id, "phishing-awareness", score=95)
        updated = tracker.get_user_profile(profile.user_id)
        assert updated.points == 0

    def test_badge_points_dict_has_all_badge_types(self):
        for badge in BadgeType:
            assert badge in _BADGE_POINTS, f"{badge} missing from _BADGE_POINTS"

    def test_leaderboard_returns_top_n_entries(self, tracker, org):
        for _ in range(5):
            p = _make_profile(org_id=org)
            tracker.register_user(p)
            tracker.assign_training(p.user_id, "phishing-awareness")
            tracker.record_completion(p.user_id, "phishing-awareness", score=80)
        board = tracker.get_leaderboard(org_id=org, top_n=3)
        assert len(board) <= 3

    def test_leaderboard_entries_sorted_by_points_descending(self, tracker, org):
        for i in range(3):
            p = _make_profile(org_id=org)
            tracker.register_user(p)
            tracker.assign_training(p.user_id, "phishing-awareness")
            tracker.record_completion(p.user_id, "phishing-awareness", score=70 + i * 10)
        board = tracker.get_leaderboard(org_id=org)
        points = [e.points for e in board]
        assert points == sorted(points, reverse=True)

    def test_leaderboard_opt_out_users_excluded(self, tracker, org):
        opt_out = _make_profile(org_id=org, opt_in=False)
        tracker.register_user(opt_out)
        tracker.assign_training(opt_out.user_id, "phishing-awareness")
        tracker.record_completion(opt_out.user_id, "phishing-awareness", score=100)
        board = tracker.get_leaderboard(org_id=org)
        board_ids = {e.user_id for e in board}
        assert opt_out.user_id not in board_ids

    def test_leaderboard_entry_has_correct_fields(self, tracker, org):
        p = _make_profile(org_id=org)
        tracker.register_user(p)
        tracker.assign_training(p.user_id, "phishing-awareness")
        tracker.record_completion(p.user_id, "phishing-awareness", score=80)
        board = tracker.get_leaderboard(org_id=org)
        assert len(board) >= 1
        entry = board[0]
        assert entry.rank == 1
        assert entry.user_id
        assert entry.display_name
        assert entry.completion_rate >= 0.0


# ============================================================================
# CERTIFICATION MANAGEMENT
# ============================================================================


class TestCertificationManagement:
    def test_add_certification_persists_and_is_retrievable(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        cert = ExternalCertification(
            user_id=profile.user_id,
            certification_name="CISSP",
            issuing_body="ISC2",
            obtained_date=datetime.now(timezone.utc) - timedelta(days=30),
            expiry_date=datetime.now(timezone.utc) + timedelta(days=1065),
        )
        tracker.add_certification(cert)
        certs = tracker.get_user_certifications(profile.user_id)
        assert len(certs) == 1
        assert certs[0].certification_name == "CISSP"

    def test_cert_without_expiry_is_active(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        cert = ExternalCertification(
            user_id=profile.user_id,
            certification_name="CompTIA Security+",
            issuing_body="CompTIA",
            obtained_date=datetime.now(timezone.utc),
            expiry_date=None,
        )
        saved = tracker.add_certification(cert)
        assert saved.status == CertificationStatus.ACTIVE

    def test_expired_cert_has_expired_status(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        cert = ExternalCertification(
            user_id=profile.user_id,
            certification_name="CEH",
            issuing_body="EC-Council",
            obtained_date=datetime.now(timezone.utc) - timedelta(days=730),
            expiry_date=datetime.now(timezone.utc) - timedelta(days=1),
        )
        saved = tracker.add_certification(cert)
        assert saved.status == CertificationStatus.EXPIRED

    def test_cert_expiring_within_reminder_days_is_expiring_soon(self, tracker):
        profile = _register(tracker, role=UserRole.DEVELOPER)
        cert = ExternalCertification(
            user_id=profile.user_id,
            certification_name="OSCP",
            issuing_body="Offensive Security",
            obtained_date=datetime.now(timezone.utc) - timedelta(days=300),
            expiry_date=datetime.now(timezone.utc) + timedelta(days=45),
            renewal_reminder_days=90,
        )
        saved = tracker.add_certification(cert)
        assert saved.status == CertificationStatus.EXPIRING_SOON

    def test_get_expiring_certifications_returns_certs_in_window(self, tracker, org):
        profile = _make_profile(org_id=org)
        tracker.register_user(profile)
        cert = ExternalCertification(
            user_id=profile.user_id,
            certification_name="AWS Security Specialty",
            issuing_body="Amazon",
            obtained_date=datetime.now(timezone.utc) - timedelta(days=700),
            expiry_date=datetime.now(timezone.utc) + timedelta(days=60),
        )
        tracker.add_certification(cert)
        expiring = tracker.get_expiring_certifications(days=90, org_id=org)
        assert len(expiring) == 1
        assert expiring[0]["certification_name"] == "AWS Security Specialty"

    def test_get_expiring_certs_excludes_certs_outside_window(self, tracker, org):
        profile = _make_profile(org_id=org)
        tracker.register_user(profile)
        cert = ExternalCertification(
            user_id=profile.user_id,
            certification_name="CISM",
            issuing_body="ISACA",
            obtained_date=datetime.now(timezone.utc) - timedelta(days=100),
            expiry_date=datetime.now(timezone.utc) + timedelta(days=200),
        )
        tracker.add_certification(cert)
        expiring = tracker.get_expiring_certifications(days=90, org_id=org)
        names = [e["certification_name"] for e in expiring]
        assert "CISM" not in names

    def test_expiring_cert_result_includes_days_until_expiry(self, tracker, org):
        profile = _make_profile(org_id=org)
        tracker.register_user(profile)
        cert = ExternalCertification(
            user_id=profile.user_id,
            certification_name="GPEN",
            issuing_body="SANS",
            obtained_date=datetime.now(timezone.utc) - timedelta(days=300),
            expiry_date=datetime.now(timezone.utc) + timedelta(days=30),
        )
        tracker.add_certification(cert)
        expiring = tracker.get_expiring_certifications(days=90, org_id=org)
        assert expiring[0]["days_until_expiry"] is not None
        assert expiring[0]["days_until_expiry"] >= 0


# ============================================================================
# PHISHING SIMULATION
# ============================================================================


class TestPhishingSimulation:
    def test_record_simulation_click_auto_assigns_phishing_training(self, tracker):
        profile = _register(tracker, role=UserRole.ALL_STAFF)
        sim = PhishingSimulation(
            user_id=profile.user_id,
            campaign_id="camp-auto-assign",
            clicked=True,
            clicked_at=datetime.now(timezone.utc),
        )
        tracker.record_phishing_simulation(sim)
        completions = tracker.get_user_completions(profile.user_id)
        module_ids = {c.module_id for c in completions}
        assert "phishing-awareness" in module_ids

    def test_no_click_simulation_does_not_change_phishing_assignment(self, tracker):
        # Start fresh user with NO pre-assigned modules
        profile = UserTrainingProfile(
            user_id=f"u-{uuid.uuid4().hex[:8]}",
            email="fresh@example.com",
            display_name="Fresh User",
            role=UserRole.ALL_STAFF,
            department="Legal",
            org_id="test-phish-no-click",
        )
        tracker.register_user(profile)
        completions_before = {c.module_id for c in tracker.get_user_completions(profile.user_id)}
        sim = PhishingSimulation(
            user_id=profile.user_id,
            campaign_id="camp-no-click",
            clicked=False,
        )
        tracker.record_phishing_simulation(sim)
        completions_after = {c.module_id for c in tracker.get_user_completions(profile.user_id)}
        # Should not change the set of assigned modules
        assert completions_after == completions_before
