"""Tests for core.continuous_validation — validation triggers, statuses, and job lifecycle."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.continuous_validation import (  # noqa: E402
    ValidationJob,
    ValidationStatus,
    ValidationTrigger,
)
from core.mpte_models import PenTestPriority  # noqa: E402


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestValidationTrigger:
    def test_all_triggers(self):
        assert ValidationTrigger.CODE_COMMIT.value == "code_commit"
        assert ValidationTrigger.DEPLOYMENT.value == "deployment"
        assert ValidationTrigger.SCHEDULED.value == "scheduled"
        assert ValidationTrigger.MANUAL.value == "manual"
        assert ValidationTrigger.VULNERABILITY_DISCOVERED.value == "vulnerability_discovered"
        assert ValidationTrigger.SECURITY_INCIDENT.value == "security_incident"
        assert ValidationTrigger.CONFIGURATION_CHANGE.value == "configuration_change"

    def test_trigger_count(self):
        assert len(ValidationTrigger) == 7


class TestValidationStatus:
    def test_all_statuses(self):
        assert ValidationStatus.SCHEDULED.value == "scheduled"
        assert ValidationStatus.IN_PROGRESS.value == "in_progress"
        assert ValidationStatus.COMPLETED.value == "completed"
        assert ValidationStatus.FAILED.value == "failed"
        assert ValidationStatus.SKIPPED.value == "skipped"

    def test_status_count(self):
        assert len(ValidationStatus) == 5


# ---------------------------------------------------------------------------
# ValidationJob
# ---------------------------------------------------------------------------


class TestValidationJob:
    def test_create_job(self):
        job = ValidationJob(
            id="job-001",
            trigger=ValidationTrigger.CODE_COMMIT,
            status=ValidationStatus.SCHEDULED,
            target="https://api.example.com",
            vulnerabilities=[{"cve": "CVE-2024-1234"}],
            priority=PenTestPriority.HIGH,
        )
        assert job.id == "job-001"
        assert job.trigger == ValidationTrigger.CODE_COMMIT
        assert job.status == ValidationStatus.SCHEDULED
        assert job.target == "https://api.example.com"
        assert len(job.vulnerabilities) == 1
        assert job.started_at is None
        assert job.completed_at is None
        assert job.result is None
        assert isinstance(job.metadata, dict)

    def test_to_dict(self):
        job = ValidationJob(
            id="job-002",
            trigger=ValidationTrigger.MANUAL,
            status=ValidationStatus.COMPLETED,
            target="10.0.0.1",
            vulnerabilities=[],
            priority=PenTestPriority.CRITICAL,
            result={"verified": True},
        )
        d = job.to_dict()
        assert d["id"] == "job-002"
        assert d["trigger"] == "manual"
        assert d["status"] == "completed"
        assert d["target"] == "10.0.0.1"

    def test_job_default_metadata(self):
        job = ValidationJob(
            id="j3",
            trigger=ValidationTrigger.SCHEDULED,
            status=ValidationStatus.IN_PROGRESS,
            target="host",
            vulnerabilities=[],
            priority=PenTestPriority.MEDIUM,
        )
        assert job.metadata == {}

    def test_job_with_metadata(self):
        job = ValidationJob(
            id="j4",
            trigger=ValidationTrigger.DEPLOYMENT,
            status=ValidationStatus.SCHEDULED,
            target="host",
            vulnerabilities=[],
            priority=PenTestPriority.LOW,
            metadata={"env": "production", "region": "us-east-1"},
        )
        assert job.metadata["env"] == "production"

    def test_all_trigger_types_valid(self):
        """Each trigger can be used in a ValidationJob."""
        for trigger in ValidationTrigger:
            job = ValidationJob(
                id=f"t-{trigger.value}",
                trigger=trigger,
                status=ValidationStatus.SCHEDULED,
                target="test",
                vulnerabilities=[],
                priority=PenTestPriority.MEDIUM,
            )
            d = job.to_dict()
            assert d["trigger"] == trigger.value

    def test_all_status_types_valid(self):
        """Each status can be used in a ValidationJob."""
        for status in ValidationStatus:
            job = ValidationJob(
                id=f"s-{status.value}",
                trigger=ValidationTrigger.MANUAL,
                status=status,
                target="test",
                vulnerabilities=[],
                priority=PenTestPriority.MEDIUM,
            )
            d = job.to_dict()
            assert d["status"] == status.value
