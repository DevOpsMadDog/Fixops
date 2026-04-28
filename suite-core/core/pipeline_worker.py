"""
ALdeci Pipeline Worker — standalone process that consumes pipeline steps from Redis.

Run as a module:
    python -m core.pipeline_worker --queue=default --worker-id=worker-1

Each worker:
  1. Registers itself with a heartbeat key (refreshed every ``HEARTBEAT_INTERVAL`` seconds).
  2. Blocks on ``dequeue_step()`` waiting for work.
  3. Dispatches the step to the appropriate ``BrainPipeline`` method.
  4. Publishes the result back via ``publish_result()``.
  5. Repeats until ``stop()`` is called or a ``SIGTERM`` / ``SIGINT`` arrives.
"""

from __future__ import annotations

import argparse
import logging
import signal
import threading
import time
import uuid
from typing import Any, Dict, Optional

from core.queue_manager import BaseQueueManager, get_queue_manager

logger = logging.getLogger(__name__)

# Steps that should be handled by workers (heavy steps)
REMOTE_STEPS = frozenset(
    ["enrich_threats", "score_risk", "llm_consensus", "llm_council"]
)

# Steps that stay in-process even in queue mode (lightweight)
LOCAL_STEPS = frozenset(
    [
        "connect",
        "normalize",
        "resolve_identity",
        "fp_auto_suppress",
        "deduplicate",
        "build_graph",
        "apply_policy",
        "micro_pentest",
        "run_playbooks",
        "generate_evidence",
    ]
)

_HEARTBEAT_INTERVAL = 10  # seconds
_DEFAULT_QUEUE = "aldeci:pipeline:default"


class PipelineWorker:
    """Standalone pipeline step worker.

    Args:
        worker_id: Unique identifier for this worker process.  Defaults to a
            random UUID.
        queue_name: Redis queue to consume from.
        queue_manager: Optional pre-built ``BaseQueueManager``.  When ``None``
            the global singleton is used (auto-detects Redis / local fallback).
    """

    def __init__(
        self,
        worker_id: Optional[str] = None,
        queue_name: str = _DEFAULT_QUEUE,
        queue_manager: Optional[BaseQueueManager] = None,
    ) -> None:
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.queue_name = queue_name
        self._qm: BaseQueueManager = queue_manager or get_queue_manager()
        self._running = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._pipeline: Optional[Any] = None  # lazy-loaded BrainPipeline

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Register heartbeat and begin the main processing loop (blocking)."""
        self._running = True
        self._qm.register_worker(self.worker_id)
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name=f"hb-{self.worker_id}"
        )
        self._heartbeat_thread.start()
        logger.info("PipelineWorker %s started, queue=%s", self.worker_id, self.queue_name)

        try:
            self._process_loop()
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully shut down the worker."""
        if not self._running:
            return
        self._running = False
        self._qm.deregister_worker(self.worker_id)
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=5)
        logger.info("PipelineWorker %s stopped", self.worker_id)

    # ------------------------------------------------------------------
    # Internal loops
    # ------------------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        """Refresh the worker heartbeat key periodically."""
        while self._running:
            try:
                self._qm.register_worker(self.worker_id)
            except Exception as exc:
                logger.warning("heartbeat refresh failed: %s", exc)
            time.sleep(_HEARTBEAT_INTERVAL)

    def _process_loop(self) -> None:
        """Main dequeue → execute → publish loop."""
        while self._running:
            try:
                task = self._qm.dequeue_step(self.queue_name, timeout=5)
            except Exception as exc:
                logger.warning("dequeue error: %s", exc)
                time.sleep(1)
                continue

            if task is None:
                continue  # timeout with no item — loop again

            run_id = task.get("run_id", "unknown")
            step_name = task.get("step_name", "unknown")
            payload = task.get("payload", {})
            task_id = task.get("task_id", "?")

            logger.info(
                "worker=%s executing task=%s run=%s step=%s",
                self.worker_id,
                task_id,
                run_id,
                step_name,
            )
            try:
                result = self.execute_step(step_name, payload)
                self._qm.publish_result(run_id, step_name, {"status": "ok", "data": result})
                logger.info("step=%s run=%s completed", step_name, run_id)
            except Exception as exc:
                logger.error(
                    "step=%s run=%s failed: %s", step_name, run_id, exc, exc_info=True
                )
                self._qm.publish_result(
                    run_id, step_name, {"status": "error", "error": str(exc)}
                )

    # ------------------------------------------------------------------
    # Step dispatch
    # ------------------------------------------------------------------

    def execute_step(self, step_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch *step_name* to the appropriate BrainPipeline method.

        Args:
            step_name: One of the ``REMOTE_STEPS`` (e.g. ``"enrich_threats"``).
            payload: The step context payload forwarded from the enqueuing side.

        Returns:
            A serialisable result dict (merged back into the pipeline context).

        Raises:
            ValueError: If *step_name* is not a known dispatchable step.
        """
        pipeline = self._get_pipeline()
        ctx = payload.get("ctx", {})
        inp_data = payload.get("inp", {})

        dispatch_map = {
            "enrich_threats": self._run_enrich_threats,
            "score_risk": self._run_score_risk,
            "llm_consensus": self._run_llm_consensus,
            "llm_council": self._run_llm_council,
        }

        handler = dispatch_map.get(step_name)
        if handler is None:
            raise ValueError(f"Unknown remote step: {step_name!r}")

        return handler(pipeline, ctx, inp_data)

    # ------------------------------------------------------------------
    # Per-step handlers (call the real BrainPipeline methods)
    # ------------------------------------------------------------------

    def _get_pipeline(self) -> Any:
        if self._pipeline is None:
            from core.brain_pipeline import BrainPipeline  # lazy import

            self._pipeline = BrainPipeline()
        return self._pipeline

    def _run_enrich_threats(
        self, pipeline: Any, ctx: Dict[str, Any], inp_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        from core.brain_pipeline import PipelineInput

        inp = PipelineInput(**inp_data) if inp_data else PipelineInput(org_id=ctx.get("org_id", "default"))
        updated_ctx = pipeline._step_enrich_threats(ctx, inp)
        return updated_ctx if updated_ctx is not None else ctx

    def _run_score_risk(
        self, pipeline: Any, ctx: Dict[str, Any], inp_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        from core.brain_pipeline import PipelineInput

        inp = PipelineInput(**inp_data) if inp_data else PipelineInput(org_id=ctx.get("org_id", "default"))
        updated_ctx = pipeline._step_score_risk(ctx, inp)
        return updated_ctx if updated_ctx is not None else ctx

    def _run_llm_consensus(
        self, pipeline: Any, ctx: Dict[str, Any], inp_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        from core.brain_pipeline import PipelineInput

        inp = PipelineInput(**inp_data) if inp_data else PipelineInput(org_id=ctx.get("org_id", "default"))
        updated_ctx = pipeline._step_llm_consensus(ctx, inp)
        return updated_ctx if updated_ctx is not None else ctx

    def _run_llm_council(
        self, pipeline: Any, ctx: Dict[str, Any], inp_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        from core.brain_pipeline import PipelineInput

        inp = PipelineInput(**inp_data) if inp_data else PipelineInput(org_id=ctx.get("org_id", "default"))
        updated_ctx = pipeline._step_llm_council(ctx, inp)
        return updated_ctx if updated_ctx is not None else ctx


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _handle_signal(signum: int, frame: Any) -> None:
    """Allow SIGTERM / SIGINT to trigger a clean shutdown."""
    raise KeyboardInterrupt


def main() -> None:
    parser = argparse.ArgumentParser(description="ALdeci Pipeline Worker")
    parser.add_argument(
        "--queue", default=_DEFAULT_QUEUE, help="Queue name to consume from"
    )
    parser.add_argument(
        "--worker-id", default=None, help="Worker identifier (default: random UUID)"
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    signal.signal(signal.SIGTERM, _handle_signal)

    worker = PipelineWorker(worker_id=args.worker_id, queue_name=args.queue)
    try:
        worker.start()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        worker.stop()


if __name__ == "__main__":
    main()
