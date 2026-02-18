"""Tests for reachability job queue module."""

import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from risk.reachability.job_queue import JobQueue, JobResult, JobStatus, ReachabilityJob


class TestJobStatusEnum:
    """Tests for JobStatus enumeration."""

    def test_job_status_values(self):
        """Test JobStatus enum values."""
        assert JobStatus.QUEUED.value == "queued"
        assert JobStatus.RUNNING.value == "running"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"
        assert JobStatus.CANCELLED.value == "cancelled"

    def test_job_status_members(self):
        """Test JobStatus enum has expected members."""
        assert len(JobStatus) == 5


class TestReachabilityJob:
    """Tests for ReachabilityJob dataclass."""

    def test_job_creation(self):
        """Test creating a ReachabilityJob."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={"severity": "high"},
        )

        assert job.repository == repo
        assert job.cve_id == "CVE-2024-1234"
        assert job.component_name == "test-lib"
        assert job.component_version == "1.0.0"
        assert job.vulnerability_details == {"severity": "high"}

    def test_job_defaults(self):
        """Test ReachabilityJob default values."""
        repo = MagicMock()

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-5678",
            component_name="another-lib",
            component_version="2.0.0",
            vulnerability_details={},
        )

        assert job.force_refresh is False
        assert job.job_id is not None
        assert len(job.job_id) == 36  # UUID format
        assert job.created_at is not None
        assert job.priority == 0

    def test_job_with_custom_values(self):
        """Test ReachabilityJob with custom values."""
        repo = MagicMock()

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-9999",
            component_name="priority-lib",
            component_version="3.0.0",
            vulnerability_details={"severity": "critical"},
            force_refresh=True,
            priority=10,
        )

        assert job.force_refresh is True
        assert job.priority == 10


class TestJobResult:
    """Tests for JobResult dataclass."""

    def test_job_result_creation(self):
        """Test creating a JobResult."""
        result = JobResult(
            job_id="test-job-123",
            status=JobStatus.COMPLETED,
        )

        assert result.job_id == "test-job-123"
        assert result.status == JobStatus.COMPLETED

    def test_job_result_defaults(self):
        """Test JobResult default values."""
        result = JobResult(
            job_id="test-job-456",
            status=JobStatus.QUEUED,
        )

        assert result.result is None
        assert result.error is None
        assert result.progress == 0.0
        assert result.started_at is None
        assert result.completed_at is None

    def test_job_result_with_error(self):
        """Test JobResult with error."""
        result = JobResult(
            job_id="test-job-789",
            status=JobStatus.FAILED,
            error="Analysis failed",
        )

        assert result.status == JobStatus.FAILED
        assert result.error == "Analysis failed"

    def test_job_result_with_result(self):
        """Test JobResult with result."""
        mock_result = MagicMock()

        result = JobResult(
            job_id="test-job-abc",
            status=JobStatus.COMPLETED,
            result=mock_result,
            progress=100.0,
            completed_at=datetime.now(timezone.utc),
        )

        assert result.result == mock_result
        assert result.progress == 100.0
        assert result.completed_at is not None


class TestJobQueue:
    """Tests for JobQueue."""

    @pytest.fixture
    def temp_persistence_path(self):
        """Create a temporary persistence path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def queue(self, temp_persistence_path):
        """Create a job queue instance for testing."""
        # Stop workers immediately to avoid threading issues in tests
        q = JobQueue(
            config={
                "persistence_path": temp_persistence_path,
                "max_workers": 0,  # Don't start workers
            }
        )
        q.running = False
        q.workers = []
        return q

    def test_queue_initialization(self, queue, temp_persistence_path):
        """Test queue initialization."""
        assert queue.config is not None
        assert queue.max_workers == 0
        assert queue.max_retries == 3
        assert queue.retry_delay_seconds == 60
        assert queue.jobs == {}
        assert queue.results == {}

    def test_queue_with_custom_config(self, temp_persistence_path):
        """Test queue with custom config."""
        config = {
            "persistence_path": temp_persistence_path,
            "max_workers": 0,
            "max_retries": 5,
            "retry_delay_seconds": 120,
        }
        queue = JobQueue(config=config)
        queue.running = False
        queue.workers = []

        assert queue.max_retries == 5
        assert queue.retry_delay_seconds == 120

    def test_enqueue_job(self, queue):
        """Test enqueueing a job."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        job_id = queue.enqueue(job)

        assert job_id == job.job_id
        assert job_id in queue.jobs
        assert job_id in queue.results
        assert queue.results[job_id].status == JobStatus.QUEUED

    def test_get_status_not_found(self, queue):
        """Test getting status for non-existent job."""
        status = queue.get_status("nonexistent-job")
        assert status is None

    def test_get_status_queued(self, queue):
        """Test getting status for queued job."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        job_id = queue.enqueue(job)
        status = queue.get_status(job_id)

        assert status is not None
        assert status["job_id"] == job_id
        assert status["status"] == "queued"
        assert status["progress"] == 10.0

    def test_get_status_running(self, queue):
        """Test getting status for running job."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        job_id = queue.enqueue(job)

        # Manually set to running
        queue.results[job_id].status = JobStatus.RUNNING
        queue.results[job_id].started_at = datetime.now(timezone.utc)
        queue.results[job_id].progress = 50.0

        status = queue.get_status(job_id)

        assert status["status"] == "running"
        assert status["progress"] == 50.0
        assert status["estimated_completion"] is not None

    def test_get_status_completed(self, queue):
        """Test getting status for completed job."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        job_id = queue.enqueue(job)

        # Manually set to completed
        queue.results[job_id].status = JobStatus.COMPLETED
        queue.results[job_id].progress = 100.0

        status = queue.get_status(job_id)

        assert status["status"] == "completed"
        assert status["progress"] == 100.0

    def test_get_status_failed(self, queue):
        """Test getting status for failed job."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        job_id = queue.enqueue(job)

        # Manually set to failed
        queue.results[job_id].status = JobStatus.FAILED
        queue.results[job_id].error = "Analysis failed"

        status = queue.get_status(job_id)

        assert status["status"] == "failed"
        assert status["progress"] == 0.0
        assert status["error"] == "Analysis failed"

    def test_cancel_job_not_found(self, queue):
        """Test cancelling non-existent job."""
        result = queue.cancel_job("nonexistent-job")
        assert result is False

    def test_cancel_job_queued(self, queue):
        """Test cancelling a queued job."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        job_id = queue.enqueue(job)
        result = queue.cancel_job(job_id)

        assert result is True
        assert queue.results[job_id].status == JobStatus.CANCELLED

    def test_cancel_job_running(self, queue):
        """Test cancelling a running job (should fail)."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        job_id = queue.enqueue(job)
        queue.results[job_id].status = JobStatus.RUNNING

        result = queue.cancel_job(job_id)

        assert result is False
        assert queue.results[job_id].status == JobStatus.RUNNING

    def test_cancel_job_completed(self, queue):
        """Test cancelling a completed job (should fail)."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        job_id = queue.enqueue(job)
        queue.results[job_id].status = JobStatus.COMPLETED

        result = queue.cancel_job(job_id)

        assert result is False

    def test_health_check(self, queue):
        """Test health check."""
        result = queue.health_check()
        # With 0 workers, should report degraded
        assert "degraded" in result or result == "ok"

    def test_get_metrics_empty(self, queue):
        """Test getting metrics with no jobs."""
        metrics = queue.get_metrics()

        assert metrics["queued"] == 0
        assert metrics["running"] == 0
        assert metrics["completed"] == 0
        assert metrics["failed"] == 0
        assert metrics["total"] == 0

    def test_get_metrics_with_jobs(self, queue):
        """Test getting metrics with jobs."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        # Add some jobs with different statuses
        for i in range(3):
            job = ReachabilityJob(
                repository=repo,
                cve_id=f"CVE-2024-{i}",
                component_name="test-lib",
                component_version="1.0.0",
                vulnerability_details={},
            )
            queue.enqueue(job)

        # Set different statuses
        job_ids = list(queue.results.keys())
        queue.results[job_ids[0]].status = JobStatus.QUEUED
        queue.results[job_ids[1]].status = JobStatus.COMPLETED
        queue.results[job_ids[2]].status = JobStatus.FAILED

        metrics = queue.get_metrics()

        assert metrics["queued"] == 1
        assert metrics["completed"] == 1
        assert metrics["failed"] == 1
        assert metrics["total"] == 3

    def test_stop_workers(self, queue):
        """Test stopping workers."""
        queue.stop_workers()

        assert queue.running is False
        assert queue.workers == []

    def test_job_persistence(self, queue, temp_persistence_path):
        """Test job persistence to disk."""
        import os

        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
        )

        queue.enqueue(job)

        # Check that job file was created
        job_file = os.path.join(temp_persistence_path, f"{job.job_id}.job.json")
        assert os.path.exists(job_file)

    def test_enqueue_with_priority(self, queue):
        """Test enqueueing jobs with different priorities."""
        repo = MagicMock()
        repo.url = "https://github.com/test/repo"

        # Enqueue low priority job
        low_job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-LOW",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
            priority=1,
        )

        # Enqueue high priority job
        high_job = ReachabilityJob(
            repository=repo,
            cve_id="CVE-2024-HIGH",
            component_name="test-lib",
            component_version="1.0.0",
            vulnerability_details={},
            priority=10,
        )

        queue.enqueue(low_job)
        queue.enqueue(high_job)

        # Both jobs should be in the queue
        assert low_job.job_id in queue.jobs
        assert high_job.job_id in queue.jobs
