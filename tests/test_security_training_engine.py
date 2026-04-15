"""Tests for SecurityTrainingEngine — 40+ tests.

Covers: init, course CRUD, enrollments, assign_training, complete_course (pass/fail),
complete_training alias, certificates, overdue detection, campaigns,
update_campaign_progress, list_certificates, get_department_compliance, stats, org isolation.
"""

from __future__ import annotations

import os
import pytest

from core.security_training_engine import SecurityTrainingEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "test_training.db")
    return SecurityTrainingEngine(db_path=db)


ORG_A = "org-alpha"
ORG_B = "org-beta"


# ---------------------------------------------------------------------------
# 1. Init
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "sub" / "training.db")
    SecurityTrainingEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "training2.db")
    SecurityTrainingEngine(db_path=db)
    SecurityTrainingEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. Course CRUD
# ---------------------------------------------------------------------------


def test_create_course_returns_record(engine):
    c = engine.create_course(ORG_A, {
        "title": "Phishing Awareness 101",
        "description": "Spot phishing emails",
        "category": "phishing",
        "duration_minutes": 45,
        "difficulty": "beginner",
        "format": "video",
        "passing_score": 80,
    })
    assert c["course_id"]
    assert c["title"] == "Phishing Awareness 101"
    assert c["category"] == "phishing"
    assert c["passing_score"] == 80


def test_create_course_invalid_category_defaults(engine):
    c = engine.create_course(ORG_A, {"title": "X", "category": "invalid"})
    assert c["category"] == "compliance"


def test_create_course_invalid_difficulty_defaults(engine):
    c = engine.create_course(ORG_A, {"title": "X", "difficulty": "expert"})
    assert c["difficulty"] == "beginner"


def test_list_courses_empty(engine):
    assert engine.list_courses(ORG_A) == []


def test_list_courses_filter_category(engine):
    engine.create_course(ORG_A, {"title": "A", "category": "phishing"})
    engine.create_course(ORG_A, {"title": "B", "category": "password"})
    engine.create_course(ORG_A, {"title": "C", "category": "phishing"})
    phishing = engine.list_courses(ORG_A, category="phishing")
    assert len(phishing) == 2


def test_list_courses_org_isolation(engine):
    engine.create_course(ORG_A, {"title": "A course"})
    engine.create_course(ORG_B, {"title": "B course"})
    assert len(engine.list_courses(ORG_A)) == 1
    assert len(engine.list_courses(ORG_B)) == 1


# ---------------------------------------------------------------------------
# 3. Enrollments
# ---------------------------------------------------------------------------


def test_enroll_user_returns_record(engine):
    c = engine.create_course(ORG_A, {"title": "Course 1"})
    e = engine.enroll_user(ORG_A, c["course_id"], "user-1", due_date="2026-12-31T00:00:00+00:00")
    assert e["enrollment_id"]
    assert e["user_id"] == "user-1"
    assert e["course_id"] == c["course_id"]
    assert e["status"] in ("enrolled", "assigned")  # spec uses "assigned"
    assert e["due_date"] == "2026-12-31T00:00:00+00:00"


def test_list_enrollments_filter_user(engine):
    c = engine.create_course(ORG_A, {"title": "Course"})
    engine.enroll_user(ORG_A, c["course_id"], "user-1")
    engine.enroll_user(ORG_A, c["course_id"], "user-2")
    u1 = engine.list_enrollments(ORG_A, user_id="user-1")
    assert len(u1) == 1


def test_list_enrollments_filter_course(engine):
    c1 = engine.create_course(ORG_A, {"title": "C1"})
    c2 = engine.create_course(ORG_A, {"title": "C2"})
    engine.enroll_user(ORG_A, c1["course_id"], "user-1")
    engine.enroll_user(ORG_A, c2["course_id"], "user-1")
    by_c1 = engine.list_enrollments(ORG_A, course_id=c1["course_id"])
    assert len(by_c1) == 1


# ---------------------------------------------------------------------------
# 4. Completions — pass / fail
# ---------------------------------------------------------------------------


def test_complete_course_pass(engine):
    c = engine.create_course(ORG_A, {"title": "Course", "passing_score": 70})
    e = engine.enroll_user(ORG_A, c["course_id"], "user-1")
    rec = engine.complete_course(ORG_A, e["enrollment_id"], score=85)
    assert rec["passed"] is True
    assert rec["score"] == 85
    # enrollment should be marked completed
    enrollments = engine.list_enrollments(ORG_A, user_id="user-1")
    assert enrollments[0]["status"] == "completed"


def test_complete_course_fail(engine):
    c = engine.create_course(ORG_A, {"title": "Course", "passing_score": 70})
    e = engine.enroll_user(ORG_A, c["course_id"], "user-1")
    rec = engine.complete_course(ORG_A, e["enrollment_id"], score=50)
    assert rec["passed"] is False


def test_complete_course_invalid_enrollment_raises(engine):
    with pytest.raises(ValueError):
        engine.complete_course(ORG_A, "nonexistent-id", score=90)


# ---------------------------------------------------------------------------
# 5. User Progress
# ---------------------------------------------------------------------------


def test_get_user_progress_empty(engine):
    p = engine.get_user_progress(ORG_A, "user-99")
    assert p["enrolled"] == 0
    assert p["completed"] == 0
    assert p["passed"] == 0
    assert p["failed"] == 0
    assert p["avg_score"] == 0.0
    assert p["compliance_completion_rate"] == 0.0


def test_get_user_progress_after_completion(engine):
    c = engine.create_course(ORG_A, {"title": "Compliance", "category": "compliance", "passing_score": 70})
    e = engine.enroll_user(ORG_A, c["course_id"], "user-1")
    engine.complete_course(ORG_A, e["enrollment_id"], score=90)

    p = engine.get_user_progress(ORG_A, "user-1")
    assert p["enrolled"] == 1
    assert p["completed"] == 1
    assert p["passed"] == 1
    assert p["failed"] == 0
    assert p["avg_score"] == 90.0
    assert p["compliance_completion_rate"] == 100.0


# ---------------------------------------------------------------------------
# 6. Campaigns
# ---------------------------------------------------------------------------


def test_create_campaign_returns_record(engine):
    camp = engine.create_campaign(ORG_A, {
        "name": "Q2 Security Awareness",
        "target_group": "all-employees",
        "course_ids": ["c1", "c2"],
        "due_date": "2026-06-30T00:00:00+00:00",
        "status": "active",
    })
    assert camp["campaign_id"]
    assert camp["name"] == "Q2 Security Awareness"
    assert camp["course_ids"] == ["c1", "c2"]
    assert camp["status"] == "active"


def test_list_campaigns_empty(engine):
    assert engine.list_campaigns(ORG_A) == []


def test_list_campaigns_org_isolation(engine):
    engine.create_campaign(ORG_A, {"name": "A Campaign"})
    engine.create_campaign(ORG_B, {"name": "B Campaign"})
    assert len(engine.list_campaigns(ORG_A)) == 1
    assert len(engine.list_campaigns(ORG_B)) == 1


# ---------------------------------------------------------------------------
# 7. Stats
# ---------------------------------------------------------------------------


def test_get_training_stats_empty(engine):
    stats = engine.get_training_stats(ORG_A)
    assert stats["total_courses"] == 0
    assert stats["enrollments_active"] == 0
    assert stats["completion_rate"] == 0.0
    assert stats["avg_score"] == 0.0
    assert stats["overdue_count"] == 0


def test_get_training_stats_populated(engine):
    c = engine.create_course(ORG_A, {"title": "Course", "category": "phishing", "passing_score": 70})
    e1 = engine.enroll_user(ORG_A, c["course_id"], "user-1")
    e2 = engine.enroll_user(ORG_A, c["course_id"], "user-2")
    engine.complete_course(ORG_A, e1["enrollment_id"], score=80)

    stats = engine.get_training_stats(ORG_A)
    assert stats["total_courses"] == 1
    assert stats["enrollments_active"] == 1  # user-2 still enrolled
    assert stats["completion_rate"] == 50.0
    assert stats["avg_score"] == 80.0
    assert "phishing" in stats["by_category"]


# ---------------------------------------------------------------------------
# 8. assign_training (spec method)
# ---------------------------------------------------------------------------


def test_assign_training_returns_record(engine):
    c = engine.create_course(ORG_A, {"title": "IR Course", "course_type": "incident_response", "frequency": "annual"})
    a = engine.assign_training(ORG_A, {
        "course_id": c["course_id"],
        "user_id": "user-assign-1",
        "user_email": "assign@example.com",
        "department": "engineering",
    })
    assert a["enrollment_id"]
    assert a["user_id"] == "user-assign-1"
    assert a["user_email"] == "assign@example.com"
    assert a["department"] == "engineering"
    assert a["due_date"] is not None  # auto-computed from frequency


def test_assign_training_missing_course_id_raises(engine):
    with pytest.raises(ValueError):
        engine.assign_training(ORG_A, {"user_id": "u1"})


def test_assign_training_missing_user_id_raises(engine):
    with pytest.raises(ValueError):
        engine.assign_training(ORG_A, {"course_id": "some-id"})


def test_assign_training_custom_due_date(engine):
    c = engine.create_course(ORG_A, {"title": "C"})
    a = engine.assign_training(ORG_A, {
        "course_id": c["course_id"],
        "user_id": "u1",
        "due_date": "2027-01-01T00:00:00+00:00",
    })
    assert a["due_date"] == "2027-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# 9. complete_training alias + certificate issuance
# ---------------------------------------------------------------------------


def test_complete_training_alias(engine):
    c = engine.create_course(ORG_A, {"title": "Course", "passing_score": 70})
    a = engine.assign_training(ORG_A, {"course_id": c["course_id"], "user_id": "u-ct"})
    rec = engine.complete_training(ORG_A, a["enrollment_id"], 85)
    assert rec["passed"] is True
    assert rec["score"] == 85


def test_complete_course_issues_certificate_on_pass(engine):
    c = engine.create_course(ORG_A, {"title": "SecCourse", "passing_score": 70, "course_name": "SecCourse"})
    e = engine.enroll_user(ORG_A, c["course_id"], "user-cert", user_email="cert@example.com")
    rec = engine.complete_course(ORG_A, e["enrollment_id"], score=90)
    assert rec.get("certificate_issued") is True
    assert rec.get("certificate_number")


def test_complete_course_no_certificate_on_fail(engine):
    c = engine.create_course(ORG_A, {"title": "Fail Course", "passing_score": 70})
    e = engine.enroll_user(ORG_A, c["course_id"], "user-fail")
    rec = engine.complete_course(ORG_A, e["enrollment_id"], score=40)
    assert rec["passed"] is False
    assert rec.get("certificate_issued") is not True


# ---------------------------------------------------------------------------
# 10. list_assignments (spec alias)
# ---------------------------------------------------------------------------


def test_list_assignments_returns_records(engine):
    c = engine.create_course(ORG_A, {"title": "C"})
    engine.assign_training(ORG_A, {"course_id": c["course_id"], "user_id": "u1", "department": "hr"})
    engine.assign_training(ORG_A, {"course_id": c["course_id"], "user_id": "u2", "department": "eng"})
    assignments = engine.list_assignments(ORG_A)
    assert len(assignments) == 2


def test_list_assignments_filter_department(engine):
    c = engine.create_course(ORG_A, {"title": "C"})
    engine.assign_training(ORG_A, {"course_id": c["course_id"], "user_id": "u1", "department": "hr"})
    engine.assign_training(ORG_A, {"course_id": c["course_id"], "user_id": "u2", "department": "eng"})
    hr = engine.list_assignments(ORG_A, department="hr")
    assert len(hr) == 1
    assert hr[0]["department"] == "hr"


def test_list_assignments_overdue_flag(engine):
    c = engine.create_course(ORG_A, {"title": "C"})
    # Past due date
    e = engine.enroll_user(ORG_A, c["course_id"], "u-overdue", due_date="2020-01-01T00:00:00+00:00")
    assignments = engine.list_assignments(ORG_A)
    overdue = [a for a in assignments if a.get("is_overdue")]
    assert len(overdue) == 1


# ---------------------------------------------------------------------------
# 11. list_certificates
# ---------------------------------------------------------------------------


def test_list_certificates_empty(engine):
    certs = engine.list_certificates(ORG_A)
    assert certs == []


def test_list_certificates_after_completion(engine):
    c = engine.create_course(ORG_A, {"title": "C", "passing_score": 70, "course_name": "C"})
    e = engine.enroll_user(ORG_A, c["course_id"], "user-cert2", user_email="c@x.com")
    engine.complete_course(ORG_A, e["enrollment_id"], score=80)
    certs = engine.list_certificates(ORG_A)
    assert len(certs) >= 1
    assert certs[0]["user_id"] == "user-cert2"
    assert "expired" in certs[0]


def test_list_certificates_filter_by_user(engine):
    c = engine.create_course(ORG_A, {"title": "C", "passing_score": 70, "course_name": "C"})
    e1 = engine.enroll_user(ORG_A, c["course_id"], "cert-user-a", user_email="a@x.com")
    e2 = engine.enroll_user(ORG_A, c["course_id"], "cert-user-b", user_email="b@x.com")
    engine.complete_course(ORG_A, e1["enrollment_id"], score=85)
    engine.complete_course(ORG_A, e2["enrollment_id"], score=90)
    certs_a = engine.list_certificates(ORG_A, user_id="cert-user-a")
    assert len(certs_a) == 1
    assert certs_a[0]["user_id"] == "cert-user-a"


def test_list_certificates_org_isolation(engine):
    for org in (ORG_A, ORG_B):
        c = engine.create_course(org, {"title": "C", "passing_score": 70, "course_name": "C"})
        e = engine.enroll_user(org, c["course_id"], "u1", user_email="u@x.com")
        engine.complete_course(org, e["enrollment_id"], score=80)
    certs_a = engine.list_certificates(ORG_A)
    certs_b = engine.list_certificates(ORG_B)
    assert len(certs_a) == 1
    assert len(certs_b) == 1


# ---------------------------------------------------------------------------
# 12. update_campaign_progress
# ---------------------------------------------------------------------------


def test_update_campaign_progress(engine):
    c = engine.create_course(ORG_A, {"title": "C", "passing_score": 70})
    camp = engine.create_campaign(ORG_A, {
        "name": "Test Campaign",
        "course_id": c["course_id"],
        "course_ids": [c["course_id"]],
        "status": "active",
    })
    e1 = engine.enroll_user(ORG_A, c["course_id"], "u1")
    e2 = engine.enroll_user(ORG_A, c["course_id"], "u2")
    engine.complete_course(ORG_A, e1["enrollment_id"], score=80)
    updated = engine.update_campaign_progress(ORG_A, camp["campaign_id"])
    assert updated["actual_completion_pct"] == 50.0


def test_update_campaign_progress_invalid_id_raises(engine):
    with pytest.raises(ValueError):
        engine.update_campaign_progress(ORG_A, "nonexistent-campaign-id")


# ---------------------------------------------------------------------------
# 13. list_campaigns filter by status
# ---------------------------------------------------------------------------


def test_list_campaigns_filter_status(engine):
    engine.create_campaign(ORG_A, {"name": "Active Camp", "status": "active"})
    engine.create_campaign(ORG_A, {"name": "Draft Camp", "status": "draft"})
    active = engine.list_campaigns(ORG_A, status="active")
    draft = engine.list_campaigns(ORG_A, status="draft")
    assert len(active) == 1
    assert len(draft) == 1
    assert active[0]["name"] == "Active Camp"


# ---------------------------------------------------------------------------
# 14. get_department_compliance
# ---------------------------------------------------------------------------


def test_get_department_compliance_empty(engine):
    result = engine.get_department_compliance(ORG_A)
    assert isinstance(result, dict)


def test_get_department_compliance_with_data(engine):
    c = engine.create_course(ORG_A, {"title": "Mandatory", "passing_score": 70, "mandatory": True})
    a1 = engine.assign_training(ORG_A, {"course_id": c["course_id"], "user_id": "u1", "department": "hr"})
    a2 = engine.assign_training(ORG_A, {"course_id": c["course_id"], "user_id": "u2", "department": "hr"})
    engine.complete_course(ORG_A, a1["enrollment_id"], score=80)
    result = engine.get_department_compliance(ORG_A)
    assert "hr" in result
    assert result["hr"]["total_assigned"] == 2
    assert result["hr"]["completed"] == 1
    assert result["hr"]["completion_rate"] == 50.0


def test_get_department_compliance_non_mandatory_excluded(engine):
    c = engine.create_course(ORG_A, {"title": "Optional", "mandatory": False})
    engine.assign_training(ORG_A, {"course_id": c["course_id"], "user_id": "u1", "department": "sales"})
    result = engine.get_department_compliance(ORG_A)
    # Non-mandatory courses should not appear in compliance report
    assert "sales" not in result


# ---------------------------------------------------------------------------
# 15. Enhanced stats fields
# ---------------------------------------------------------------------------


def test_get_training_stats_has_new_fields(engine):
    stats = engine.get_training_stats(ORG_A)
    assert "total_assignments" in stats
    assert "certificates_issued" in stats
    assert "expiring_soon_count" in stats
    assert "by_department" in stats


def test_get_training_stats_certificates_count(engine):
    c = engine.create_course(ORG_A, {"title": "C", "passing_score": 70, "course_name": "C"})
    e = engine.enroll_user(ORG_A, c["course_id"], "u1", user_email="u@x.com")
    engine.complete_course(ORG_A, e["enrollment_id"], score=80)
    stats = engine.get_training_stats(ORG_A)
    assert stats["certificates_issued"] >= 1


# ---------------------------------------------------------------------------
# 16. list_courses mandatory filter + course_type
# ---------------------------------------------------------------------------


def test_list_courses_filter_mandatory(engine):
    engine.create_course(ORG_A, {"title": "Mandatory", "mandatory": True})
    engine.create_course(ORG_A, {"title": "Optional", "mandatory": False})
    mandatory = engine.list_courses(ORG_A, mandatory=True)
    optional = engine.list_courses(ORG_A, mandatory=False)
    assert len(mandatory) == 1
    assert mandatory[0]["mandatory"] is True
    assert len(optional) == 1


def test_create_course_with_course_type(engine):
    c = engine.create_course(ORG_A, {
        "title": "GDPR Training",
        "course_type": "gdpr",
        "mandatory": True,
        "frequency": "annual",
        "cpe_credits": 2.5,
    })
    assert c["course_type"] == "gdpr"
    assert c["mandatory"] is True
    assert c["cpe_credits"] == 2.5
