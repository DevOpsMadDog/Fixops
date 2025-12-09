"""Enterprise job queue for async reachability analysis."""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from queue import Queue
from typing import Any, Dict, List, Mapping, Optional

logger = logging.getLogger(__name__)


class JobStatus(Enum):
    """Job status enumeration."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ReachabilityJob:
    """Job for reachability analysis."""

    repository: Any  # GitRepository
    cve_id: str
    component_name: str
    component_version: str
    vulnerability_details: Dict[str, Any]
    force_refresh: bool = False
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    priority: int = 0  # Higher = more priority


@dataclass
class JobResult:
    """Result of a job execution."""

    job_id: str
    status: JobStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    progress: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class JobQueue:
    """Enterprise job queue with priority, retry, and persistence."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize job queue.

        Parameters
        ----------
        config
            Configuration for job queue.
        """
        self.config = config or {}
        self.max_workers = self.config.get("max_workers", 4)
        self.max_retries = self.config.get("max_retries", 3)
        self.retry_delay_seconds = self.config.get("retry_delay_seconds", 60)

        # Job storage
        self.jobs: Dict[str, ReachabilityJob] = {}
        self.results: Dict[str, JobResult] = {}
        self.priority_queue: Queue = Queue()

        # Worker threads
        self.workers: List[threading.Thread] = []
        self.running = False

        # Persistence
        self.persistence_path = Path(
            self.config.get("persistence_path", "data/reachability/jobs")
        )
        self.persistence_path.mkdir(parents=True, exist_ok=True)

        # Start workers
        self.start_workers()

    def enqueue(self, job: ReachabilityJob) -> str:
        """Enqueue a job for processing.

        Parameters
        ----------
        job
            Job to enqueue.

        Returns
        -------
        str
            Job ID.
        """
        self.jobs[job.job_id] = job

        # Store job result with queued status
        self.results[job.job_id] = JobResult(
            job_id=job.job_id,
            status=JobStatus.QUEUED,
        )

        # Add to priority queue
        self.priority_queue.put((-job.priority, job.job_id))

        # Persist job
        self._persist_job(job)

        logger.info(f"Job {job.job_id} queued for analysis")

        return job.job_id

    def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status.

        Parameters
        ----------
        job_id
            Job identifier.

        Returns
        -------
        Optional[Dict[str, Any]]
            Job status information.
        """
        if job_id not in self.results:
            return None

        result = self.results[job_id]

        # Calculate progress
        progress = 0.0
        if result.status == JobStatus.QUEUED:
            progress = 10.0
        elif result.status == JobStatus.RUNNING:
            progress = result.progress
        elif result.status == JobStatus.COMPLETED:
            progress = 100.0
        elif result.status == JobStatus.FAILED:
            progress = 0.0

        # Estimate completion
        estimated_completion = None
        if result.status == JobStatus.RUNNING and result.started_at:
            # Simple estimation: assume 5 minutes average
            estimated = result.started_at.timestamp() + 300
            estimated_completion = datetime.fromtimestamp(
                estimated, tz=timezone.utc
            ).isoformat()

        return {
            "job_id": job_id,
            "status": result.status.value,
            "progress": progress,
            "result": result.result.to_dict() if result.result else None,
            "error": result.error,
            "created_at": self.jobs[job_id].created_at.isoformat(),
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": (
                result.completed_at.isoformat() if result.completed_at else None
            ),
            "estimated_completion": estimated_completion,
        }

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a queued job.

        Parameters
        ----------
        job_id
            Job identifier.

        Returns
        -------
        bool
            True if job was cancelled, False if not found or already running.
        """
        if job_id not in self.results:
            return False

        result = self.results[job_id]

        if result.status == JobStatus.RUNNING:
            return False  # Cannot cancel running job

        if result.status == JobStatus.QUEUED:
            result.status = JobStatus.CANCELLED
            logger.info(f"Job {job_id} cancelled")
            return True

        return False

    def start_workers(self) -> None:
        """Start worker threads."""
        if self.running:
            return

        self.running = True

        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker_loop, name=f"ReachabilityWorker-{i}", daemon=True
            )
            worker.start()
            self.workers.append(worker)

        logger.info(f"Started {self.max_workers} worker threads")

    def stop_workers(self) -> None:
        """Stop worker threads."""
        self.running = False

        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)

        self.workers.clear()
        logger.info("Worker threads stopped")

    def _worker_loop(self) -> None:
        """Worker thread main loop."""
        from core.configuration import load_overlay
        from risk.reachability.analyzer import ReachabilityAnalyzer

        overlay = load_overlay()
        config = overlay.get("reachability_analysis", {})
        analyzer = ReachabilityAnalyzer(config=config)

        while self.running:
            try:
                # Get job from queue (blocking with timeout)
                try:
                    priority, job_id = self.priority_queue.get(timeout=1)
                except Exception:
                    continue

                if job_id not in self.jobs:
                    continue

                job = self.jobs[job_id]
                result = self.results[job_id]

                # Skip if cancelled
                if result.status == JobStatus.CANCELLED:
                    continue

                # Update status to running
                result.status = JobStatus.RUNNING
                result.started_at = datetime.now(timezone.utc)
                result.progress = 20.0

                logger.info(f"Processing job {job_id}")

                try:
                    # Execute analysis
                    analysis_result = analyzer.analyze_vulnerability_from_repo(
                        repository=job.repository,
                        cve_id=job.cve_id,
                        component_name=job.component_name,
                        component_version=job.component_version,
                        vulnerability_details=job.vulnerability_details,
                        force_refresh=job.force_refresh,
                    )

                    # Update progress
                    result.progress = 100.0
                    result.result = analysis_result
                    result.status = JobStatus.COMPLETED
                    result.completed_at = datetime.now(timezone.utc)

                    logger.info(f"Job {job_id} completed successfully")

                except Exception as e:
                    logger.error(f"Job {job_id} failed: {e}", exc_info=True)
                    result.status = JobStatus.FAILED
                    result.error = str(e)
                    result.completed_at = datetime.now(timezone.utc)

                # Persist result
                self._persist_result(result)

            except Exception as e:
                logger.error(f"Worker error: {e}", exc_info=True)

    def _persist_job(self, job: ReachabilityJob) -> None:
        """Persist job to disk."""
        try:
            import json

            job_file = self.persistence_path / f"{job.job_id}.job.json"
            with open(job_file, "w") as f:
                json.dump(
                    {
                        "job_id": job.job_id,
                        "cve_id": job.cve_id,
                        "component_name": job.component_name,
                        "component_version": job.component_version,
                        "repository_url": job.repository.url,
                        "created_at": job.created_at.isoformat(),
                    },
                    f,
                    indent=2,
                )
        except Exception as e:
            logger.warning(f"Failed to persist job {job.job_id}: {e}")

    def _persist_result(self, result: JobResult) -> None:
        """Persist result to disk."""
        try:
            import json

            result_file = self.persistence_path / f"{result.job_id}.result.json"
            with open(result_file, "w") as f:
                json.dump(
                    {
                        "job_id": result.job_id,
                        "status": result.status.value,
                        "error": result.error,
                        "progress": result.progress,
                        "started_at": (
                            result.started_at.isoformat() if result.started_at else None
                        ),
                        "completed_at": (
                            result.completed_at.isoformat()
                            if result.completed_at
                            else None
                        ),
                    },
                    f,
                    indent=2,
                )
        except Exception as e:
            logger.warning(f"Failed to persist result {result.job_id}: {e}")

    def health_check(self) -> str:
        """Health check for job queue."""
        try:
            # Check if workers are running
            active_workers = sum(1 for w in self.workers if w.is_alive())

            if active_workers < self.max_workers:
                return f"degraded ({active_workers}/{self.max_workers} workers)"

            return "ok"
        except Exception as e:
            return f"error: {str(e)}"

    def get_metrics(self) -> Dict[str, Any]:
        """Get job queue metrics."""
        queued = sum(1 for r in self.results.values() if r.status == JobStatus.QUEUED)
        running = sum(1 for r in self.results.values() if r.status == JobStatus.RUNNING)
        completed = sum(
            1 for r in self.results.values() if r.status == JobStatus.COMPLETED
        )
        failed = sum(1 for r in self.results.values() if r.status == JobStatus.FAILED)

        return {
            "queued": queued,
            "running": running,
            "completed": completed,
            "failed": failed,
            "total": len(self.results),
            "active_workers": sum(1 for w in self.workers if w.is_alive()),
        }
