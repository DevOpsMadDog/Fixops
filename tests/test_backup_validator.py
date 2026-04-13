"""Tests for Backup & Disaster Recovery Validator.

Covers:
- Backup job CRUD (register, get, list, update, delete)
- RPO/RTO config (set, list, compliance evaluation)
- Backup verification (record, age alerts, checksum)
- DR plan management (register, get, list, update, delete, runbook steps)
- DR test tracking (record, update, remediation status)
- Geographic redundancy (set, list, get)
- Business continuity scoring (weights, grade thresholds, edge cases)

Usage:
    pytest tests/test_backup_validator.py -v --timeout=10
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite-core is on sys.path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.backup_validator import (
    BackupJob,
    BackupStatus,
    BackupType,
    BackupVerification,
    BCScore,
    DataResidencyRegion,
    DRPlan,
    DRTestRecord,
    DRTestResult,
    EncryptionType,
    GeoRedundancyRecord,
    RemediationStatus,
    RPOConfig,
    RunbookStep,
    BackupValidator,
    VerificationStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def validator(tmp_path):
    """Fresh BackupValidator backed by a temp SQLite file."""
    db_file = str(tmp_path / "test_bv.db")
    return BackupValidator(db_path=db_file)


def _make_job(**kwargs) -> BackupJob:
    defaults: Dict[str, Any] = {
        "name": "nightly-db-backup",
        "system_name": "postgres-primary",
        "backup_type": BackupType.FULL,
        "source_path": "/var/lib/postgresql/data",
        "destination": "s3://backups/postgres/",
        "schedule_cron": "0 2 * * *",
        "retention_days": 30,
        "encryption": EncryptionType.AES256,
        "status": BackupStatus.ACTIVE,
        "org_id": "org-test",
    }
    defaults.update(kwargs)
    return BackupJob(**defaults)


def _make_rpo(**kwargs) -> RPOConfig:
    defaults: Dict[str, Any] = {
        "system_name": "postgres-primary",
        "rpo_target_minutes": 240,
        "rto_target_minutes": 480,
        "org_id": "org-test",
    }
    defaults.update(kwargs)
    return RPOConfig(**defaults)


def _make_plan(**kwargs) -> DRPlan:
    defaults: Dict[str, Any] = {
        "name": "DB Failover Plan",
        "system_name": "postgres-primary",
        "priority_order": 1,
        "rto_minutes": 60,
        "rpo_minutes": 30,
        "org_id": "org-test",
    }
    defaults.update(kwargs)
    return DRPlan(**defaults)


def _make_dr_test(plan_id: str, **kwargs) -> DRTestRecord:
    defaults: Dict[str, Any] = {
        "dr_plan_id": plan_id,
        "system_name": "postgres-primary",
        "test_date": datetime.now(timezone.utc).isoformat(),
        "result": DRTestResult.PASSED,
        "tested_by": "ops-team",
        "org_id": "org-test",
    }
    defaults.update(kwargs)
    return DRTestRecord(**defaults)


def _make_geo(**kwargs) -> GeoRedundancyRecord:
    defaults: Dict[str, Any] = {
        "system_name": "postgres-primary",
        "primary_location": "us-east-1",
        "backup_locations": ["us-west-2", "eu-west-1"],
        "distance_km": 3500.0,
        "data_residency_region": DataResidencyRegion.US,
        "residency_compliant": True,
        "org_id": "org-test",
    }
    defaults.update(kwargs)
    return GeoRedundancyRecord(**defaults)


def _make_verification(job_id: str, **kwargs) -> BackupVerification:
    defaults: Dict[str, Any] = {
        "backup_job_id": job_id,
        "backup_artifact_path": "s3://backups/postgres/2026-01-01.tar.gz",
        "sha256_checksum": "abc123def456",
        "checksum_verified": True,
        "restore_tested": True,
        "restore_test_result": VerificationStatus.PASSED,
        "backup_age_hours": 2.0,
        "age_alert_threshold_hours": 48.0,
        "org_id": "org-test",
    }
    defaults.update(kwargs)
    return BackupVerification(**defaults)


# ---------------------------------------------------------------------------
# Backup Job Tests
# ---------------------------------------------------------------------------

class TestBackupJobCRUD:
    def test_register_and_get(self, validator):
        job = _make_job()
        registered = validator.register_backup_job(job)
        assert registered.id == job.id
        fetched = validator.get_backup_job(job.id)
        assert fetched is not None
        assert fetched.name == "nightly-db-backup"

    def test_list_jobs_by_org(self, validator):
        job1 = _make_job(name="job1", system_name="sys-a")
        job2 = _make_job(name="job2", system_name="sys-b")
        validator.register_backup_job(job1)
        validator.register_backup_job(job2)
        jobs = validator.list_backup_jobs("org-test")
        assert len(jobs) == 2

    def test_list_jobs_by_system(self, validator):
        validator.register_backup_job(_make_job(system_name="sys-a"))
        validator.register_backup_job(_make_job(system_name="sys-b"))
        jobs = validator.list_backup_jobs("org-test", system_name="sys-a")
        assert len(jobs) == 1
        assert jobs[0].system_name == "sys-a"

    def test_update_backup_job(self, validator):
        job = validator.register_backup_job(_make_job())
        updated = validator.update_backup_job(job.id, {"status": BackupStatus.FAILED, "retention_days": 60})
        assert updated is not None
        assert updated.status == BackupStatus.FAILED
        assert updated.retention_days == 60

    def test_delete_backup_job(self, validator):
        job = validator.register_backup_job(_make_job())
        assert validator.delete_backup_job(job.id) is True
        assert validator.get_backup_job(job.id) is None

    def test_delete_nonexistent_returns_false(self, validator):
        assert validator.delete_backup_job("nonexistent-id") is False

    def test_get_nonexistent_returns_none(self, validator):
        assert validator.get_backup_job("no-such-id") is None

    def test_job_default_encryption_is_aes256(self, validator):
        job = _make_job()
        assert job.encryption == EncryptionType.AES256

    def test_list_empty_org_returns_empty(self, validator):
        jobs = validator.list_backup_jobs("empty-org")
        assert jobs == []

    def test_update_nonexistent_returns_none(self, validator):
        result = validator.update_backup_job("no-such-id", {"status": BackupStatus.FAILED})
        assert result is None

    def test_register_idempotent(self, validator):
        job = _make_job()
        validator.register_backup_job(job)
        job.name = "updated-name"
        validator.register_backup_job(job)
        fetched = validator.get_backup_job(job.id)
        assert fetched.name == "updated-name"
        assert len(validator.list_backup_jobs("org-test")) == 1


# ---------------------------------------------------------------------------
# RPO/RTO Tests
# ---------------------------------------------------------------------------

class TestRPOConfig:
    def test_set_and_get_rpo(self, validator):
        cfg = _make_rpo()
        saved = validator.set_rpo_config(cfg)
        assert saved.id == cfg.id
        fetched = validator.get_rpo_config(cfg.id)
        assert fetched is not None
        assert fetched.system_name == "postgres-primary"

    def test_rpo_compliance_evaluation_pass(self, validator):
        cfg = _make_rpo(rpo_actual_minutes=120, rto_actual_minutes=300)
        saved = validator.set_rpo_config(cfg)
        assert saved.rpo_compliant is True  # 120 <= 240
        assert saved.rto_compliant is True  # 300 <= 480

    def test_rpo_compliance_evaluation_fail(self, validator):
        cfg = _make_rpo(rpo_actual_minutes=500, rto_actual_minutes=600)
        saved = validator.set_rpo_config(cfg)
        assert saved.rpo_compliant is False  # 500 > 240
        assert saved.rto_compliant is False  # 600 > 480

    def test_rpo_no_actuals_defaults_noncompliant(self, validator):
        cfg = _make_rpo()  # no actuals
        saved = validator.set_rpo_config(cfg)
        assert saved.rpo_compliant is False
        assert saved.rto_compliant is False

    def test_list_rpo_configs(self, validator):
        validator.set_rpo_config(_make_rpo(system_name="sys-a"))
        validator.set_rpo_config(_make_rpo(system_name="sys-b"))
        cfgs = validator.list_rpo_configs("org-test")
        assert len(cfgs) == 2

    def test_get_nonexistent_rpo_returns_none(self, validator):
        assert validator.get_rpo_config("no-such-id") is None

    def test_rpo_exact_target_is_compliant(self, validator):
        cfg = _make_rpo(rpo_actual_minutes=240, rto_actual_minutes=480)
        saved = validator.set_rpo_config(cfg)
        assert saved.rpo_compliant is True
        assert saved.rto_compliant is True


# ---------------------------------------------------------------------------
# Backup Verification Tests
# ---------------------------------------------------------------------------

class TestBackupVerification:
    def test_record_and_get_verification(self, validator):
        job = validator.register_backup_job(_make_job())
        ver = _make_verification(job.id)
        saved = validator.record_verification(ver)
        assert saved.id == ver.id
        fetched = validator.get_verification(ver.id)
        assert fetched is not None
        assert fetched.backup_job_id == job.id

    def test_age_alert_not_triggered_below_threshold(self, validator):
        job = validator.register_backup_job(_make_job())
        ver = _make_verification(job.id, backup_age_hours=10.0, age_alert_threshold_hours=48.0)
        saved = validator.record_verification(ver)
        assert saved.age_alert_triggered is False

    def test_age_alert_triggered_above_threshold(self, validator):
        job = validator.register_backup_job(_make_job())
        ver = _make_verification(job.id, backup_age_hours=72.0, age_alert_threshold_hours=48.0)
        saved = validator.record_verification(ver)
        assert saved.age_alert_triggered is True

    def test_age_alert_no_age_no_trigger(self, validator):
        job = validator.register_backup_job(_make_job())
        ver = _make_verification(job.id, backup_age_hours=None)
        saved = validator.record_verification(ver)
        assert saved.age_alert_triggered is False

    def test_list_verifications_by_org(self, validator):
        job = validator.register_backup_job(_make_job())
        validator.record_verification(_make_verification(job.id))
        validator.record_verification(_make_verification(job.id))
        vers = validator.list_verifications("org-test")
        assert len(vers) == 2

    def test_list_verifications_by_job(self, validator):
        job1 = validator.register_backup_job(_make_job(system_name="sys-a"))
        job2 = validator.register_backup_job(_make_job(system_name="sys-b"))
        validator.record_verification(_make_verification(job1.id))
        validator.record_verification(_make_verification(job2.id))
        vers = validator.list_verifications("org-test", backup_job_id=job1.id)
        assert len(vers) == 1
        assert vers[0].backup_job_id == job1.id

    def test_compute_checksum(self, validator):
        data = b"backup content here"
        checksum = validator.compute_checksum(data)
        assert len(checksum) == 64  # SHA-256 hex digest
        assert checksum == validator.compute_checksum(data)  # deterministic

    def test_get_nonexistent_verification_returns_none(self, validator):
        assert validator.get_verification("no-such-id") is None

    def test_failed_restore_result_recorded(self, validator):
        job = validator.register_backup_job(_make_job())
        ver = _make_verification(job.id, restore_test_result=VerificationStatus.FAILED)
        saved = validator.record_verification(ver)
        assert saved.restore_test_result == VerificationStatus.FAILED


# ---------------------------------------------------------------------------
# DR Plan Tests
# ---------------------------------------------------------------------------

class TestDRPlan:
    def test_register_and_get_plan(self, validator):
        plan = _make_plan()
        saved = validator.register_dr_plan(plan)
        assert saved.id == plan.id
        fetched = validator.get_dr_plan(plan.id)
        assert fetched is not None
        assert fetched.name == "DB Failover Plan"

    def test_plan_with_runbook_steps(self, validator):
        steps = [
            RunbookStep(
                step_number=1,
                title="Notify team",
                description="Send alert to #oncall",
                responsible_party="SRE",
                estimated_duration_minutes=5,
            ),
            RunbookStep(
                step_number=2,
                title="Promote replica",
                description="Promote standby to primary",
                responsible_party="DBA",
                estimated_duration_minutes=10,
                dependencies=[1],
            ),
        ]
        plan = _make_plan(runbook_steps=steps)
        saved = validator.register_dr_plan(plan)
        assert len(saved.runbook_steps) == 2
        assert saved.runbook_steps[1].dependencies == [1]

    def test_list_plans_by_org(self, validator):
        validator.register_dr_plan(_make_plan(system_name="sys-a"))
        validator.register_dr_plan(_make_plan(system_name="sys-b"))
        plans = validator.list_dr_plans("org-test")
        assert len(plans) == 2

    def test_list_plans_by_system(self, validator):
        validator.register_dr_plan(_make_plan(system_name="sys-a"))
        validator.register_dr_plan(_make_plan(system_name="sys-b"))
        plans = validator.list_dr_plans("org-test", system_name="sys-a")
        assert len(plans) == 1

    def test_update_dr_plan(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        updated = validator.update_dr_plan(plan.id, {"priority_order": 2, "version": "1.1"})
        assert updated is not None
        assert updated.priority_order == 2
        assert updated.version == "1.1"

    def test_delete_dr_plan(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        assert validator.delete_dr_plan(plan.id) is True
        assert validator.get_dr_plan(plan.id) is None

    def test_delete_nonexistent_plan_returns_false(self, validator):
        assert validator.delete_dr_plan("no-such-id") is False

    def test_update_nonexistent_plan_returns_none(self, validator):
        assert validator.update_dr_plan("no-such-id", {"version": "2.0"}) is None

    def test_plan_communication_plan_stored(self, validator):
        comm = {
            "channels": ["slack", "email"],
            "escalation": ["cto@example.com"],
            "template": "DR activated for {system}",
        }
        plan = _make_plan(communication_plan=comm)
        saved = validator.register_dr_plan(plan)
        assert saved.communication_plan["channels"] == ["slack", "email"]


# ---------------------------------------------------------------------------
# DR Test Record Tests
# ---------------------------------------------------------------------------

class TestDRTestRecord:
    def test_record_and_get_dr_test(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        record = _make_dr_test(plan.id)
        saved = validator.record_dr_test(record)
        assert saved.id == record.id
        fetched = validator.get_dr_test(record.id)
        assert fetched is not None
        assert fetched.result == DRTestResult.PASSED

    def test_record_dr_test_with_gaps(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        gaps = ["Backup restoration took 2x expected time", "Communication plan email bounced"]
        record = _make_dr_test(
            plan.id,
            result=DRTestResult.PARTIAL,
            gaps_found=gaps,
            remediation_status=RemediationStatus.OPEN,
        )
        saved = validator.record_dr_test(record)
        assert len(saved.gaps_found) == 2
        assert saved.remediation_status == RemediationStatus.OPEN

    def test_update_dr_test_remediation(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        record = validator.record_dr_test(_make_dr_test(plan.id, gaps_found=["gap1"]))
        updated = validator.update_dr_test(
            record.id,
            {"remediation_status": RemediationStatus.RESOLVED, "remediation_notes": "Fixed gap1"}
        )
        assert updated is not None
        assert updated.remediation_status == RemediationStatus.RESOLVED

    def test_list_dr_tests_by_org(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        validator.record_dr_test(_make_dr_test(plan.id))
        validator.record_dr_test(_make_dr_test(plan.id))
        tests = validator.list_dr_tests("org-test")
        assert len(tests) == 2

    def test_list_dr_tests_by_plan(self, validator):
        plan1 = validator.register_dr_plan(_make_plan(system_name="sys-a"))
        plan2 = validator.register_dr_plan(_make_plan(system_name="sys-b"))
        validator.record_dr_test(_make_dr_test(plan1.id))
        validator.record_dr_test(_make_dr_test(plan2.id))
        tests = validator.list_dr_tests("org-test", dr_plan_id=plan1.id)
        assert len(tests) == 1
        assert tests[0].dr_plan_id == plan1.id

    def test_get_nonexistent_dr_test_returns_none(self, validator):
        assert validator.get_dr_test("no-such-id") is None

    def test_update_nonexistent_dr_test_returns_none(self, validator):
        assert validator.update_dr_test("no-such-id", {"result": DRTestResult.FAILED}) is None


# ---------------------------------------------------------------------------
# Geographic Redundancy Tests
# ---------------------------------------------------------------------------

class TestGeoRedundancy:
    def test_set_and_get_geo_record(self, validator):
        rec = _make_geo()
        saved = validator.set_geo_redundancy(rec)
        assert saved.id == rec.id
        fetched = validator.get_geo_record(rec.id)
        assert fetched is not None
        assert fetched.primary_location == "us-east-1"

    def test_list_geo_records(self, validator):
        validator.set_geo_redundancy(_make_geo(system_name="sys-a"))
        validator.set_geo_redundancy(_make_geo(system_name="sys-b"))
        records = validator.list_geo_records("org-test")
        assert len(records) == 2

    def test_geo_record_residency_compliant(self, validator):
        rec = _make_geo(residency_compliant=True, required_residency="US")
        saved = validator.set_geo_redundancy(rec)
        assert saved.residency_compliant is True

    def test_geo_record_noncompliant(self, validator):
        rec = _make_geo(residency_compliant=False, required_residency="EU",
                        data_residency_region=DataResidencyRegion.US)
        saved = validator.set_geo_redundancy(rec)
        assert saved.residency_compliant is False

    def test_get_nonexistent_geo_returns_none(self, validator):
        assert validator.get_geo_record("no-such-id") is None

    def test_geo_record_multiple_backup_locations(self, validator):
        rec = _make_geo(backup_locations=["us-west-2", "eu-west-1", "ap-southeast-1"])
        saved = validator.set_geo_redundancy(rec)
        assert len(saved.backup_locations) == 3

    def test_geo_record_distance_stored(self, validator):
        rec = _make_geo(distance_km=5500.0)
        saved = validator.set_geo_redundancy(rec)
        assert saved.distance_km == 5500.0


# ---------------------------------------------------------------------------
# Business Continuity Score Tests
# ---------------------------------------------------------------------------

class TestBCScore:
    def test_empty_org_returns_zero_score(self, validator):
        score = validator.compute_bc_score("empty-org")
        assert score.score == 0.0
        assert score.grade == "F"

    def test_score_with_all_active_encrypted_jobs(self, validator):
        # Register active encrypted jobs for 2 systems
        validator.register_backup_job(_make_job(system_name="sys-a", encryption=EncryptionType.AES256))
        validator.register_backup_job(_make_job(system_name="sys-b", encryption=EncryptionType.AES256))
        score = validator.compute_bc_score("org-test")
        assert score.backup_coverage_pct == 100.0
        assert score.encryption_coverage_pct == 100.0
        assert score.score > 0

    def test_score_increases_with_rpo_compliance(self, validator):
        validator.register_backup_job(_make_job())
        base = validator.compute_bc_score("org-test").score
        validator.set_rpo_config(_make_rpo(rpo_actual_minutes=60, rto_actual_minutes=120))
        improved = validator.compute_bc_score("org-test").score
        assert improved > base

    def test_score_grade_mapping(self, validator):
        score = validator.compute_bc_score("org-test")
        # empty org = 0 = F
        assert score.grade == "F"

    def test_grade_boundaries(self, validator):
        assert BackupValidator._score_to_grade(90.0) == "A"
        assert BackupValidator._score_to_grade(89.9) == "B"
        assert BackupValidator._score_to_grade(80.0) == "B"
        assert BackupValidator._score_to_grade(79.9) == "C"
        assert BackupValidator._score_to_grade(70.0) == "C"
        assert BackupValidator._score_to_grade(69.9) == "D"
        assert BackupValidator._score_to_grade(60.0) == "D"
        assert BackupValidator._score_to_grade(59.9) == "F"

    def test_score_open_gaps_counted(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        validator.record_dr_test(_make_dr_test(
            plan.id,
            gaps_found=["gap1", "gap2"],
            remediation_status=RemediationStatus.OPEN,
        ))
        score = validator.compute_bc_score("org-test")
        assert score.open_gaps == 1  # one test record with open gaps

    def test_score_resolved_gaps_not_counted(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        validator.record_dr_test(_make_dr_test(
            plan.id,
            gaps_found=["gap1"],
            remediation_status=RemediationStatus.RESOLVED,
        ))
        score = validator.compute_bc_score("org-test")
        assert score.open_gaps == 0

    def test_systems_without_backup_listed(self, validator):
        # Register a DR plan for sys-a but NO backup job
        validator.register_dr_plan(_make_plan(system_name="sys-a"))
        score = validator.compute_bc_score("org-test")
        assert "sys-a" in score.systems_without_backup

    def test_systems_without_dr_plan_listed(self, validator):
        # Backup job for sys-b but no DR plan
        validator.register_backup_job(_make_job(system_name="sys-b"))
        score = validator.compute_bc_score("org-test")
        assert "sys-b" in score.systems_without_dr_plan

    def test_verification_pass_rate_affects_score(self, validator):
        job = validator.register_backup_job(_make_job())
        base = validator.compute_bc_score("org-test").score
        # Add passed verifications
        validator.record_verification(_make_verification(job.id, restore_test_result=VerificationStatus.PASSED))
        validator.record_verification(_make_verification(job.id, restore_test_result=VerificationStatus.PASSED))
        improved = validator.compute_bc_score("org-test").score
        assert improved > base

    def test_geo_redundancy_affects_score(self, validator):
        validator.register_backup_job(_make_job())
        base = validator.compute_bc_score("org-test").score
        validator.set_geo_redundancy(_make_geo(system_name="postgres-primary", residency_compliant=True))
        improved = validator.compute_bc_score("org-test").score
        assert improved > base

    def test_dr_test_frequency_score_recent_tests(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        # Test within last 90 days
        recent = datetime.now(timezone.utc).isoformat()
        validator.record_dr_test(_make_dr_test(plan.id, test_date=recent, result=DRTestResult.PASSED))
        score = validator.compute_bc_score("org-test")
        assert score.test_frequency_score == 100.0  # 1/1 plans tested recently

    def test_dr_test_frequency_score_old_tests_not_counted(self, validator):
        plan = validator.register_dr_plan(_make_plan())
        # Test more than 90 days ago
        old_date = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        validator.record_dr_test(_make_dr_test(plan.id, test_date=old_date, result=DRTestResult.PASSED))
        score = validator.compute_bc_score("org-test")
        assert score.test_frequency_score == 0.0

    def test_unencrypted_jobs_lower_encryption_score(self, validator):
        validator.register_backup_job(_make_job(system_name="sys-a", encryption=EncryptionType.AES256))
        validator.register_backup_job(_make_job(system_name="sys-b", encryption=EncryptionType.NONE))
        score = validator.compute_bc_score("org-test")
        assert score.encryption_coverage_pct == 50.0

    def test_bc_score_model_fields(self, validator):
        score = validator.compute_bc_score("org-test")
        assert isinstance(score, BCScore)
        assert 0.0 <= score.score <= 100.0
        assert score.org_id == "org-test"
        assert score.computed_at is not None

    def test_suspended_jobs_not_counted_as_covered(self, validator):
        validator.register_backup_job(_make_job(system_name="sys-a", status=BackupStatus.SUSPENDED))
        score = validator.compute_bc_score("org-test")
        assert score.backup_coverage_pct == 0.0
        assert "sys-a" in score.systems_without_backup
