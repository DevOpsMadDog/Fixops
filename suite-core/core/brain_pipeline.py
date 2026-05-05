"""
ALdeci Brain Pipeline — End-to-End Orchestrator.

Chains all 12 steps of the ALdeci Brain Data Flow:
  1. Connect everything once
  2. Translate into common language (UnifiedFinding)
  3. Fix identity confusion (Fuzzy matching)
  4. Collapse into Exposure Cases
  5. Build the Brain Map (Knowledge Graph)
  6. Add threat reality signals (EPSS, KEV, CVSS)
  7. Run smart algorithms (GNN + attack paths)
  8. Policy decides what must happen
  9. Multi-LLM consensus
 10. MicroPenTest proves reality
 11. Playbooks mobilize remediation
 12. SOC2 Type II evidence pack

Usage:
    pipeline = BrainPipeline()
    result = pipeline.run(PipelineInput(
        org_id="acme",
        findings=[...],
        assets=[...],
    ))
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph integration
# ---------------------------------------------------------------------------
try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus:
            bus.emit(event_type, payload)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Pipeline data types
# ---------------------------------------------------------------------------
class PipelineStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


STEP_NAMES = [
    "connect",  # 1
    "normalize",  # 2
    "resolve_identity",  # 3
    "fp_auto_suppress",  # 3b
    "deduplicate",  # 4
    "build_graph",  # 5
    "enrich_threats",  # 6
    "score_risk",  # 7
    "apply_policy",  # 8
    "llm_consensus",  # 9
    "micro_pentest",  # 10
    "run_playbooks",  # 11
    "generate_evidence",  # 12
]


@dataclass
class StepResult:
    name: str
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_ms: float = 0
    findings_in: int = 0  # Number of findings entering this step
    findings_out: int = 0  # Number of findings leaving this step
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": round(self.duration_ms, 2),
            "findings_in": self.findings_in,
            "findings_out": self.findings_out,
            "output": self.output,
            "error": self.error,
        }


@dataclass
class PipelineInput:
    org_id: str = ""
    # Raw findings from connectors (already ingested)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    # Assets/services inventory
    assets: List[Dict[str, Any]] = field(default_factory=list)
    # Options
    run_pentest: bool = False
    run_playbooks: bool = True
    generate_evidence: bool = True
    evidence_framework: str = "soc2"
    evidence_timeframe_days: int = 90
    # Policy overrides
    policy_rules: List[Dict[str, Any]] = field(default_factory=list)
    # Metadata
    source: str = "api"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineResult:
    run_id: str = ""
    org_id: str = ""
    status: PipelineStatus = PipelineStatus.PENDING
    started_at: str = ""
    finished_at: Optional[str] = None
    total_duration_ms: float = 0
    steps: List[StepResult] = field(default_factory=list)
    # Progress tracking [V3] — enables real-time UI updates
    current_step: str = ""
    current_step_index: int = 0
    total_steps: int = 12
    progress_percent: float = 0.0
    # Summaries
    findings_ingested: int = 0
    clusters_created: int = 0
    exposure_cases_created: int = 0
    graph_nodes: int = 0
    graph_edges: int = 0
    avg_risk_score: float = 0.0
    critical_cases: int = 0
    pentest_validated: int = 0
    playbooks_executed: int = 0
    evidence_generated: bool = False
    evidence_signed: bool = False  # True when crypto signing succeeded
    data_quality: Optional[Dict[str, Any]] = None  # Per-step data quality tracking
    enrichment_stats: Optional[Dict[str, Any]] = None  # Post-pipeline enrichment stats
    error: Optional[str] = None

    def __post_init__(self):
        if not self.run_id:
            self.run_id = f"BR-{uuid.uuid4().hex[:12].upper()}"
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "org_id": self.org_id,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "current_step": self.current_step,
            "current_step_index": self.current_step_index,
            "total_steps": self.total_steps,
            "progress_percent": round(self.progress_percent, 1),
            "steps": [s.to_dict() for s in self.steps],
            "summary": {
                "findings_ingested": self.findings_ingested,
                "clusters_created": self.clusters_created,
                "exposure_cases_created": self.exposure_cases_created,
                "graph_nodes": self.graph_nodes,
                "graph_edges": self.graph_edges,
                "avg_risk_score": round(self.avg_risk_score, 4),
                "critical_cases": self.critical_cases,
                "pentest_validated": self.pentest_validated,
                "playbooks_executed": self.playbooks_executed,
                "evidence_generated": self.evidence_generated,
                "evidence_signed": self.evidence_signed,
            },
            "data_quality": self.data_quality,
            "enrichment_stats": self.enrichment_stats,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Lightweight HTTP OPA client for FIXOPS_OPA_URL integration
# ---------------------------------------------------------------------------

class _HttpOPAEngine:
    """Thin synchronous wrapper around an external OPA server.

    Compatible with the async ``evaluate_policy`` interface expected by
    ``_opa_policy_decisions`` — the async call is just a coroutine wrapper
    around a synchronous ``urllib`` request so there are no extra dependencies.

    Protocol: POST {base_url}/v1/data/{policy_path}
    Body: {"input": <payload>}
    Response: {"result": {"decision": "allow|block|defer", ...}}
    """

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")

    async def evaluate_policy(
        self, policy_path: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate a policy via OPA HTTP API.  Returns OPA result dict."""
        import json as _json
        import urllib.error
        import urllib.request

        url = f"{self._base_url}/v1/data/{policy_path}"
        data = _json.dumps({"input": payload}).encode()
        req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310  # nosemgrep: dynamic-urllib-use-detected  # nosec
                body = _json.loads(resp.read())
                return body.get("result", {})
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"OPA HTTP call failed: {exc}") from exc
        except _json.JSONDecodeError as exc:
            raise RuntimeError(f"OPA response not JSON: {exc}") from exc


class BrainPipeline:
    """End-to-end pipeline orchestrator chaining all 12 ALdeci Brain steps.

    Key scalability features:
    - O(n) asset lookup via pre-built hash map (not O(n²))
    - Pipeline metrics: per-step timing, findings in/out, dedup rate
    - Edge case handling: empty findings, malformed inputs, LLM timeout
    - Batched graph operations for large finding sets (>500)
    """

    # Maximum findings/assets to prevent DoS via pipeline input
    MAX_FINDINGS = 50_000
    MAX_ASSETS = 10_000
    # Batch size for graph operations
    GRAPH_BATCH_SIZE = 500

    # Maximum number of pipeline runs to keep in memory
    MAX_RUNS_HISTORY = 1000

    # Maximum string length for finding fields to prevent memory abuse
    MAX_FIELD_LEN = 10_000
    # Pipeline timeout in seconds (prevent infinite blocking)
    PIPELINE_TIMEOUT_S = 300  # 5 minutes

    # Steps offloaded to workers when FIXOPS_QUEUE_MODE=redis
    _REMOTE_STEPS = frozenset(["enrich_threats", "score_risk", "llm_consensus", "llm_council"])

    def __init__(self) -> None:
        self._runs: Dict[str, PipelineResult] = {}
        self._metrics: List[Dict[str, Any]] = []
        self._lock = threading.Lock()  # Thread-safe access to _runs/_metrics
        self._cancelled: set = set()  # Run IDs that have been cancelled
        # Queue mode: "local" (default) or "redis" (FIXOPS_QUEUE_MODE env var)
        self._queue_mode: str = os.environ.get("FIXOPS_QUEUE_MODE", "local").lower().strip()
        # Persistent single-worker pool reused across all steps — avoids the
        # ~5-10ms OS thread-spawn overhead incurred by per-step context managers.
        self._exec: concurrent.futures.ThreadPoolExecutor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="bp_step")
        )

    def close(self) -> None:
        """Shut down the persistent step executor gracefully."""
        self._exec.shutdown(wait=False, cancel_futures=True)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    # Maximum depth for nested sanitization to prevent stack overflow
    MAX_SANITIZE_DEPTH = 5
    # Step timeout — individual step killed if exceeds this
    STEP_TIMEOUT_S = 60

    # ------------------------------------------------------------------
    # Sanitization helpers
    # ------------------------------------------------------------------
    def _sanitize_finding(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively truncate overly long string fields to prevent memory abuse.

        Handles nested dicts and lists up to MAX_SANITIZE_DEPTH to catch
        deeply nested payloads that could bypass top-level-only truncation.
        """
        return self._deep_sanitize(f, depth=0)

    def _deep_sanitize(self, obj: Any, depth: int) -> Any:
        """Recursively sanitize strings in nested structures."""
        if depth > self.MAX_SANITIZE_DEPTH:
            return obj
        if isinstance(obj, str):
            if len(obj) > self.MAX_FIELD_LEN:
                return obj[: self.MAX_FIELD_LEN] + "...[truncated]"
            return obj
        if isinstance(obj, dict):
            for key, val in obj.items():
                obj[key] = self._deep_sanitize(val, depth + 1)
            return obj
        if isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = self._deep_sanitize(item, depth + 1)
            return obj
        return obj

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self, inp: PipelineInput) -> PipelineResult:
        """Execute the full 12-step pipeline synchronously."""
        # Input validation (P0 — prevent garbage data propagating)
        if inp.org_id is None:
            raise ValueError("org_id is required (may be empty string)")
        if not isinstance(inp.findings, list):
            inp.findings = list(inp.findings) if inp.findings else []
        if not isinstance(inp.assets, list):
            inp.assets = list(inp.assets) if inp.assets else []
        # Ensure findings and assets are dicts (filter non-dicts)
        inp.findings = [f for f in inp.findings if isinstance(f, dict)]
        inp.assets = [a for a in inp.assets if isinstance(a, dict)]

        # Enforce size limits to prevent DoS
        if len(inp.findings) > self.MAX_FINDINGS:
            logger.warning(
                "Truncating findings from %d to %d", len(inp.findings), self.MAX_FINDINGS
            )
            inp.findings = inp.findings[: self.MAX_FINDINGS]
        if len(inp.assets) > self.MAX_ASSETS:
            logger.warning(
                "Truncating assets from %d to %d", len(inp.assets), self.MAX_ASSETS
            )
            inp.assets = inp.assets[: self.MAX_ASSETS]

        # Sanitize string fields to prevent memory abuse
        inp.findings = [self._sanitize_finding(f) for f in inp.findings]

        result = PipelineResult(org_id=inp.org_id)
        result.steps = [StepResult(name=n) for n in STEP_NAMES]
        with self._lock:
            self._runs[result.run_id] = result
            # Evict oldest runs to prevent unbounded memory growth
            if len(self._runs) > self.MAX_RUNS_HISTORY:
                oldest_keys = sorted(
                    self._runs.keys(),
                    key=lambda k: self._runs[k].started_at,
                )[: len(self._runs) - self.MAX_RUNS_HISTORY]
                for k in oldest_keys:
                    del self._runs[k]
        result.status = PipelineStatus.RUNNING
        _tg_emit("brain_pipeline.run_started", {
            "run_id": result.run_id,
            "org_id": inp.org_id,
            "findings_count": len(inp.findings),
            "assets_count": len(inp.assets),
        })

        # Shared context passed between steps
        ctx: Dict[str, Any] = {
            "org_id": inp.org_id,
            "findings": inp.findings,
            "assets": inp.assets,
            "clusters": [],
            "exposure_cases": [],
            "risk_scores": {},
            "policy_decisions": [],
            "llm_results": [],
            "pentest_results": [],
            "playbook_results": [],
            "metrics": {},  # Per-step metrics for observability
        }

        step_funcs = [
            self._step_connect,
            self._step_normalize,
            self._step_resolve_identity,
            self._step_fp_auto_suppress,
            self._step_deduplicate,
            self._step_build_graph,
            self._step_enrich_threats,
            self._step_score_risk,
            self._step_apply_policy,
            # Switch to council if enabled, otherwise use legacy consensus
            self._step_llm_council if os.environ.get("FIXOPS_USE_COUNCIL", "").lower() in ("1", "true", "yes") else self._step_llm_consensus,
            self._step_micro_pentest,
            self._step_run_playbooks,
            self._step_generate_evidence,
        ]

        pipeline_start = time.monotonic()
        pipeline_deadline = pipeline_start + self.PIPELINE_TIMEOUT_S
        failed = False
        findings_count_before = len(inp.findings)

        for idx, func in enumerate(step_funcs):
            step = result.steps[idx]
            # Skip optional steps if not requested
            if step.name == "micro_pentest" and not inp.run_pentest:
                step.status = StepStatus.SKIPPED
                continue
            if step.name == "run_playbooks" and not inp.run_playbooks:
                step.status = StepStatus.SKIPPED
                continue
            if step.name == "generate_evidence" and not inp.generate_evidence:
                step.status = StepStatus.SKIPPED
                continue

            # Cancellation check — allows cooperative cancellation from API/UI
            if result.run_id in self._cancelled:
                step.status = StepStatus.SKIPPED
                step.error = "Pipeline cancelled by user"
                logger.info(
                    "Pipeline %s cancelled at step %s", result.run_id, step.name
                )
                for remaining in result.steps[idx:]:
                    remaining.status = StepStatus.SKIPPED
                result.status = PipelineStatus.FAILED
                result.error = "Pipeline cancelled"
                with self._lock:
                    self._cancelled.discard(result.run_id)
                break

            # Pipeline timeout enforcement
            if time.monotonic() > pipeline_deadline:
                step.status = StepStatus.FAILED
                step.error = "Pipeline timeout exceeded"
                logger.warning(
                    "Pipeline %s timed out at step %s (limit=%ds)",
                    result.run_id, step.name, self.PIPELINE_TIMEOUT_S,
                )
                failed = True
                # Mark remaining steps as skipped
                for remaining in result.steps[idx + 1 :]:
                    remaining.status = StepStatus.SKIPPED
                break

            step.status = StepStatus.RUNNING
            step.started_at = datetime.now(timezone.utc).isoformat()
            t0 = time.monotonic()
            findings_in = len(ctx.get("findings", []))

            # [V3] Progress tracking — update current step for UI polling
            result.current_step = step.name
            result.current_step_index = idx
            result.progress_percent = round((idx / len(step_funcs)) * 100, 1)

            try:
                # In redis queue mode, offload heavy steps to workers
                if self._queue_mode == "redis" and step.name in self._REMOTE_STEPS:
                    step.output = self._dispatch_step_to_queue(step.name, ctx, inp) or {}
                else:
                    step.output = func(ctx, inp) or {}
                step.status = StepStatus.COMPLETED
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
                step.status = StepStatus.FAILED
                # Only expose exception type, not message (may contain secrets/PII)
                step.error = f"{type(e).__name__}: pipeline step failed"
                logger.error("Pipeline step %s failed: %s", step.name, e, exc_info=True)
                failed = True

            step.duration_ms = (time.monotonic() - t0) * 1000
            step.finished_at = datetime.now(timezone.utc).isoformat()

            # Record per-step metrics (both on StepResult and ctx for observability)
            findings_out = len(ctx.get("findings", []))
            step.findings_in = findings_in
            step.findings_out = findings_out
            ctx["metrics"][step.name] = {
                "duration_ms": round(step.duration_ms, 2),
                "findings_in": findings_in,
                "findings_out": findings_out,
                "status": step.status.value,
            }

        result.total_duration_ms = (time.monotonic() - pipeline_start) * 1000
        result.finished_at = datetime.now(timezone.utc).isoformat()
        # [V3] Final progress update
        result.current_step = ""
        result.progress_percent = 100.0

        # Populate summary
        result.findings_ingested = len(inp.findings)
        result.clusters_created = len(ctx.get("clusters", []))
        result.exposure_cases_created = len(ctx.get("exposure_cases", []))
        result.pentest_validated = len(ctx.get("pentest_results", []))
        result.playbooks_executed = len(ctx.get("playbook_results", []))
        result.avg_risk_score = ctx.get("risk_scores", {}).get("avg", 0.0)
        result.critical_cases = ctx.get("risk_scores", {}).get("critical", 0)
        # Reflect evidence generation and signing state from Step 12 output
        evidence_step = next(
            (s for s in result.steps if s.name == "generate_evidence"), None
        )
        if evidence_step and evidence_step.status == StepStatus.COMPLETED:
            result.evidence_generated = True
            result.evidence_signed = bool(
                evidence_step.output.get("signed", False)
            )

        # Compute dedup rate metric
        dedup_rate = 0.0
        if findings_count_before > 0:
            unique_clusters = len(ctx.get("clusters", []))
            if unique_clusters > 0:
                dedup_rate = round(
                    1.0 - (unique_clusters / findings_count_before), 4
                )

        all_completed = all(
            s.status in (StepStatus.COMPLETED, StepStatus.SKIPPED) for s in result.steps
        )
        result.status = (
            PipelineStatus.COMPLETED
            if all_completed
            else (PipelineStatus.FAILED if failed else PipelineStatus.PARTIAL)
        )

        # ── Post-Pipeline Enrichment ─────────────────────────────
        # Add compliance mapping, SLA deadlines, and attack path data
        # to every finding. This NEVER causes pipeline failure.
        enrichment_stats = self._enrich_post_pipeline(ctx)
        result.enrichment_stats = enrichment_stats

        # ── Mirror to SecurityFindingsEngine (customer-facing dashboard) ──
        # Bug surfaced by 15-tenant onboarding 2026-04-24: pipeline reports
        # `completed` but findings never reach /api/v1/security-findings/
        # because brain_pipeline persists to ctx + analytics.db only.
        # This mirror is fire-and-forget — pipeline success not gated on it.
        try:
            mirrored = self._mirror_to_security_findings_engine(ctx)
            result.findings_mirrored_to_dashboard = mirrored
        except Exception as exc:  # noqa: BLE001 — never block pipeline on mirror
            logger.warning("Mirror to SecurityFindingsEngine failed: %s", exc)
            result.findings_mirrored_to_dashboard = 0

        # ── Data Quality Assessment ──────────────────────────────
        # Tell the customer EXACTLY which steps did real work vs fell back.
        data_quality = self._compute_data_quality(ctx, result)
        result.data_quality = data_quality

        # Store pipeline metrics (thread-safe)
        run_metrics = {
            "run_id": result.run_id,
            "total_duration_ms": round(result.total_duration_ms, 2),
            "findings_ingested": result.findings_ingested,
            "clusters_created": result.clusters_created,
            "dedup_rate": dedup_rate,
            "status": result.status.value,
            "step_metrics": ctx.get("metrics", {}),
        }
        with self._lock:
            self._metrics.append(run_metrics)
            # Keep only last 100 metric records
            if len(self._metrics) > 100:
                self._metrics = self._metrics[-100:]

        self._emit_event(result)
        _tg_emit("brain_pipeline.run_completed", {
            "run_id": result.run_id,
            "org_id": inp.org_id,
            "status": result.status,
            "findings_out": len(ctx.get("findings", [])),
            "exposure_cases": len(ctx.get("exposure_cases", [])),
        })

        # ----------------------------------------------------------------
        # Persist PipelineRun to enterprise DatabaseManager (Sprint 2).
        # The sync wrapper is non-blocking on failure — it never raises.
        # All existing sqlite3 behaviour is untouched; this is an additive
        # write only.
        # ----------------------------------------------------------------
        try:
            from core.brain_pipeline_db import (
                persist_pipeline_run_sync,  # noqa: PLC0415
            )
            persist_pipeline_run_sync(result, org_id=inp.org_id or "default")
        except ImportError:
            pass  # DB write failure must never surface to callers

        # ── Analytics Data Bridge ────────────────────────────────
        # Sync findings to analytics.db so dashboards show pipeline results.
        # This bridges the data island between pipeline and analytics.
        synced = self._sync_to_analytics(ctx)
        if synced > 0:
            logger.info("Synced %d findings to analytics.db", synced)

        return result

    def _dispatch_step_to_queue(
        self, step_name: str, ctx: Dict[str, Any], inp: "PipelineInput"
    ) -> Dict[str, Any]:
        """Enqueue a heavy step to a Redis worker and wait for the result.

        Used when ``FIXOPS_QUEUE_MODE=redis``.  Falls back to direct
        in-process execution if the queue manager is unavailable or returns
        an error.

        Args:
            step_name: One of ``_REMOTE_STEPS`` (e.g. ``"enrich_threats"``).
            ctx: Current pipeline context dict.
            inp: Original ``PipelineInput``.

        Returns:
            Updated context dict with the step result merged in.
        """
        try:
            from core.queue_manager import get_queue_manager

            qm = get_queue_manager()
            run_id = ctx.get("org_id", "unknown") + "-" + step_name
            payload = {
                "ctx": {k: v for k, v in ctx.items() if k != "metrics"},
                "inp": {"org_id": inp.org_id},
            }
            qm.enqueue_step(run_id, step_name, payload)
            logger.info(
                "Dispatched step %s to queue (run_id=%s)", step_name, run_id
            )

            # Wait for result via pub/sub (timeout = STEP_TIMEOUT_S)
            sub = qm.subscribe_results(run_id)
            deadline = time.monotonic() + self.STEP_TIMEOUT_S
            try:
                for message in sub:
                    if message.get("step_name") == step_name:
                        result_data = message.get("result", {})
                        if result_data.get("status") == "ok":
                            merged = result_data.get("data", {})
                            # Merge returned context keys back
                            if isinstance(merged, dict):
                                ctx.update(
                                    {k: v for k, v in merged.items() if k != "metrics"}
                                )
                        else:
                            logger.warning(
                                "Queue step %s returned error: %s",
                                step_name,
                                result_data.get("error"),
                            )
                        return ctx
                    if time.monotonic() > deadline:
                        logger.warning(
                            "Queue step %s timed out — running in-process", step_name
                        )
                        break
            finally:
                sub.close()

        except Exception as exc:
            logger.warning(
                "Queue dispatch for step %s failed (%s) — running in-process",
                step_name,
                exc,
            )

        # Fallback: run the step in-process
        step_func_map = {
            "enrich_threats": self._step_enrich_threats,
            "score_risk": self._step_score_risk,
            "llm_consensus": self._step_llm_consensus,
            "llm_council": self._step_llm_council,
        }
        fallback = step_func_map.get(step_name)
        if fallback is not None:
            return fallback(ctx, inp) or ctx
        return ctx

    async def run_async(self, inp: PipelineInput) -> PipelineResult:
        """Execute the pipeline asynchronously (non-blocking).

        Offloads the synchronous pipeline to a thread pool so it doesn't
        block the event loop. Use this from async API handlers.

        [V3] Decision Intelligence — scales past 100 concurrent requests.
        """
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self.run, inp)

        # ----------------------------------------------------------------
        # Async persist — run after the executor returns so we have a
        # running event loop available.  The sync persist in run() will
        # have already fired the fire-and-background path; this await
        # ensures the actual write completes in async contexts (FastAPI).
        # ----------------------------------------------------------------
        try:
            from core.brain_pipeline_db import persist_pipeline_run  # noqa: PLC0415
            await persist_pipeline_run(result, org_id=inp.org_id or "default")
        except ImportError:
            pass  # DB write failure must never surface to callers

        return result

    def cancel(self, run_id: str) -> bool:
        """Cancel a running pipeline by run_id.

        [V3] Decision Intelligence — cooperative cancellation for long-running pipelines.
        The pipeline checks for cancellation before each step and exits gracefully.
        Returns True if the run_id was found and cancellation was requested.
        """
        with self._lock:
            if run_id in self._runs:
                self._cancelled.add(run_id)
                logger.info("Cancellation requested for pipeline %s", run_id)
                return True
        return False

    async def run_async_batch(
        self, inputs: List[PipelineInput], max_concurrent: int = 4
    ) -> List[PipelineResult]:
        """Execute multiple pipeline runs concurrently with bounded parallelism.

        [V3] Decision Intelligence — batch processing for 1000+ finding sets
        from multiple scanners. Uses asyncio.Semaphore to cap concurrency.

        Args:
            inputs: List of PipelineInput objects to process.
            max_concurrent: Maximum number of concurrent pipeline runs (default 4).

        Returns:
            List of PipelineResult objects in the same order as inputs.
        """
        if not inputs:
            return []
        # Clamp concurrency to sane limits
        max_concurrent = max(1, min(max_concurrent, 16))
        sem = asyncio.Semaphore(max_concurrent)

        async def _bounded_run(inp: PipelineInput) -> PipelineResult:
            async with sem:
                return await self.run_async(inp)

        results = await asyncio.gather(
            *[_bounded_run(inp) for inp in inputs],
            return_exceptions=True,
        )
        # Convert exceptions to failed PipelineResult objects
        final: List[PipelineResult] = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                failed_result = PipelineResult(
                    org_id=inputs[i].org_id,
                    status=PipelineStatus.FAILED,
                    error=f"{type(r).__name__}: batch pipeline failed",
                )
                final.append(failed_result)
            else:
                final.append(r)
        return final

    def get_metrics(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent pipeline performance metrics."""
        with self._lock:
            return list(self._metrics[-limit:])

    def get_progress(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Get lightweight progress info for a running pipeline.

        [V3] Decision Intelligence — enables real-time UI progress bars.
        Returns only essential fields to minimize serialization overhead.
        """
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return None
            # For running pipelines, compute elapsed from start time
            if run.status == PipelineStatus.RUNNING:
                try:
                    started = datetime.fromisoformat(run.started_at)
                    elapsed_ms = (
                        datetime.now(timezone.utc) - started
                    ).total_seconds() * 1000
                except (ValueError, TypeError):
                    elapsed_ms = run.total_duration_ms
            else:
                elapsed_ms = run.total_duration_ms
            return {
                "run_id": run.run_id,
                "status": run.status.value,
                "current_step": run.current_step,
                "current_step_index": run.current_step_index,
                "total_steps": run.total_steps,
                "progress_percent": round(run.progress_percent, 1),
                "elapsed_ms": round(elapsed_ms, 2),
            }

    def get_run(self, run_id: str) -> Optional[PipelineResult]:
        with self._lock:
            return self._runs.get(run_id)

    def list_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            runs = sorted(self._runs.values(), key=lambda r: r.started_at, reverse=True)
            return [r.to_dict() for r in runs[:limit]]

    # ------------------------------------------------------------------
    # Post-Pipeline Enrichment (compliance, SLA, attack paths)
    # ------------------------------------------------------------------

    # SLA targets by severity (in hours)
    _SLA_HOURS: Dict[str, int] = {
        "critical": 24,
        "high": 72,
        "medium": 168,
        "low": 720,
        "info": 2160,
        "informational": 2160,
    }

    def _enrich_post_pipeline(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Add compliance mapping, SLA deadlines, and attack path data.

        This runs after all 12 pipeline steps complete. It enriches each
        finding in-place with cross-cutting concerns that span multiple
        steps. It NEVER raises -- all failures are logged as warnings and
        skipped gracefully.

        Returns a stats dict with counts of what was enriched.
        """
        findings: List[Dict[str, Any]] = ctx.get("findings", [])
        stats: Dict[str, Any] = {
            "total_findings": len(findings),
            "compliance_mapped": 0,
            "sla_assigned": 0,
            "attack_paths_enriched": 0,
            "code_to_cloud_enriched": 0,
            "material_change_enriched": 0,
            "frameworks_affected": set(),
        }

        # ---- Load compliance mappings (optional dependency) ----
        cwe_mappings: Dict[str, Any] = {}
        try:
            from compliance.mapping import DEFAULT_CWE_MAPPINGS  # noqa: PLC0415
            cwe_mappings = DEFAULT_CWE_MAPPINGS
        except ImportError:
            logger.warning(
                "Post-pipeline enrichment: compliance.mapping not available, "
                "skipping compliance mapping"
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "Post-pipeline enrichment: failed to load compliance mappings"
            )

        # ---- Load attack path engine (optional dependency) ----
        ap_engine = None
        try:
            from core.attack_path_engine import AttackPathEngine  # noqa: PLC0415

            _ap_instance = AttackPathEngine()

            def _blast_radius_adapter(node_id: str, max_hops: int = 3) -> Dict[str, Any]:  # noqa: ARG001
                """Adapt AttackPathEngine.get_blast_radius to legacy callable shape.

                Brain Pipeline Step 11 expects keys ``total_paths`` and
                ``affected_nodes``. The engine returns ``total_reachable`` and
                ``reachable_nodes`` — map them so downstream enrichment keeps
                working without changing the public engine surface.
                """
                br = _ap_instance.get_blast_radius(node_id)
                if not isinstance(br, dict):
                    return {}
                return {
                    "total_paths": br.get("total_reachable", 0),
                    "affected_nodes": br.get("total_reachable", 0),
                    "max_depth": br.get("max_depth", 0),
                    "crown_jewels_at_risk": br.get("crown_jewels_at_risk", []),
                }

            ap_engine = _blast_radius_adapter
        except ImportError:
            logger.warning(
                "Post-pipeline enrichment: attack_path_engine not available, "
                "skipping attack path enrichment"
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "Post-pipeline enrichment: failed to load attack path engine"
            )

        now = datetime.now(timezone.utc)

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            # ── (a) Compliance mapping ──
            try:
                self._enrich_compliance(finding, cwe_mappings, stats)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Post-pipeline enrichment: compliance mapping failed for "
                    "finding %s", finding.get("id", "unknown")
                )

            # ── (b) SLA deadline assignment ──
            try:
                self._enrich_sla(finding, now, stats)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Post-pipeline enrichment: SLA assignment failed for "
                    "finding %s", finding.get("id", "unknown")
                )

            # ── (c) Attack path enrichment ──
            try:
                self._enrich_attack_paths(finding, ap_engine, stats)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Post-pipeline enrichment: attack path enrichment failed "
                    "for finding %s", finding.get("id", "unknown")
                )

            # ── (d) Code-to-Cloud trace enrichment ──
            try:
                self._enrich_code_to_cloud(finding, stats)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Post-pipeline enrichment: code-to-cloud trace failed "
                    "for finding %s", finding.get("id", "unknown")
                )

            # ── (e) Material change risk amplification ──
            try:
                self._enrich_material_change(finding, stats)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Post-pipeline enrichment: material change enrichment failed "
                    "for finding %s", finding.get("id", "unknown")
                )

        # Convert set to list for JSON serialization
        stats["frameworks_affected"] = sorted(stats["frameworks_affected"])
        ctx["_post_pipeline_enriched"] = True
        return stats

    # Severity → CVSS estimate (used by mirror when CVSS not present)
    _SEVERITY_TO_CVSS = {
        "critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0,
    }

    def _mirror_to_security_findings_engine(self, ctx: Dict[str, Any]) -> int:
        """Write every pipeline-finished finding into SecurityFindingsEngine.

        Required because the customer-facing dashboard at
        ``/api/v1/security-findings/findings`` reads from
        ``SecurityFindingsEngine``, NOT from ctx or analytics.db. Without this
        mirror, a successful pipeline run produces an empty dashboard — the
        bug surfaced by the 15-tenant onboarding 2026-04-24.

        Idempotent: ``SecurityFindingsEngine.record_finding`` dedups on
        ``(org_id, source_tool, title, asset_id)`` when ``correlation_key``
        is provided. Re-running the same scan does not duplicate rows.

        Returns the count of findings successfully mirrored. Errors per
        finding are logged and skipped — one bad finding does not break the
        rest of the mirror.
        """
        findings = ctx.get("findings", []) or []
        if not findings:
            return 0
        org_id = ctx.get("org_id") or "default"
        scan_id = ctx.get("scan_id") or ctx.get("run_id")

        try:
            from core.security_findings_engine import (  # noqa: PLC0415
                SecurityFindingsEngine,
            )
        except ImportError:
            logger.warning("SecurityFindingsEngine unavailable; skipping mirror")
            return 0

        sfe = SecurityFindingsEngine()
        mirrored = 0
        for f in findings:
            try:
                sev = (f.get("severity") or "medium").lower()
                cvss = (
                    float(f.get("cvss_score"))
                    if f.get("cvss_score") is not None
                    else self._SEVERITY_TO_CVSS.get(sev, 5.0)
                )
                asset_id = (
                    f.get("asset_id")
                    or f.get("file_path")
                    or f.get("resource_ref")
                    or "unknown_asset"
                )
                source_tool = f.get("source_tool") or f.get("source") or "brain_pipeline"
                # Stable correlation = source|rule_or_cve|asset → enables lifecycle
                rule_or_cve = (
                    f.get("rule_id") or f.get("cve_id") or f.get("title") or "unknown"
                )
                corr_key = f.get("correlation_key") or f"{source_tool}|{rule_or_cve}|{asset_id}"
                sfe.record_finding(
                    org_id=org_id,
                    title=f.get("title") or rule_or_cve or "Pipeline Finding",
                    finding_type=f.get("finding_type") or f.get("type") or "vulnerability",
                    source_tool=source_tool,
                    severity=sev,
                    cvss_score=cvss,
                    asset_id=asset_id,
                    asset_type=f.get("asset_type") or "unknown",
                    description=f.get("description") or f.get("message") or "",
                    remediation=f.get("remediation") or f.get("fix_suggestion") or "",
                    correlation_key=corr_key,
                    scan_id=scan_id,
                )
                mirrored += 1
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Mirror skipped one finding (id=%s): %s",
                    f.get("id", "?"), exc,
                )
        if mirrored:
            logger.info(
                "Brain pipeline mirrored %d/%d findings to SecurityFindingsEngine "
                "for org_id=%s",
                mirrored, len(findings), org_id,
            )
        return mirrored

    def _enrich_compliance(
        self,
        finding: Dict[str, Any],
        cwe_mappings: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> None:
        """Map CWE to compliance framework controls on a single finding."""
        if not cwe_mappings:
            return

        # Extract CWE ID from finding -- try cwe_id field first, then rule_id
        cwe_id = finding.get("cwe_id") or finding.get("cwe")
        if not cwe_id:
            rule_id = finding.get("rule_id", "") or ""
            match = re.search(r"CWE-(\d+)", str(rule_id), re.IGNORECASE)
            if match:
                cwe_id = f"CWE-{match.group(1)}"

        if not cwe_id:
            return

        # Normalize CWE ID format
        cwe_id = str(cwe_id).upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        mapping = cwe_mappings.get(cwe_id)
        if not mapping:
            return

        # Build compliance_impact dict from the ControlMapping
        frameworks: List[str] = []
        compliance_impact: Dict[str, Any] = {"cwe_id": cwe_id}

        if hasattr(mapping, "nist_800_53") and mapping.nist_800_53:
            compliance_impact["nist_800_53"] = list(mapping.nist_800_53)
            frameworks.append("NIST 800-53")
        if hasattr(mapping, "pci_dss") and mapping.pci_dss:
            compliance_impact["pci_dss"] = list(mapping.pci_dss)
            frameworks.append("PCI DSS")
        if hasattr(mapping, "iso_27001") and mapping.iso_27001:
            compliance_impact["iso_27001"] = list(mapping.iso_27001)
            frameworks.append("ISO 27001")
        if hasattr(mapping, "owasp_category") and mapping.owasp_category:
            compliance_impact["owasp"] = mapping.owasp_category
            frameworks.append("OWASP Top 10")
        if hasattr(mapping, "control_families") and mapping.control_families:
            compliance_impact["control_families"] = list(mapping.control_families)

        compliance_impact["frameworks_affected"] = frameworks
        compliance_impact["frameworks_count"] = len(frameworks)
        finding["compliance_impact"] = compliance_impact

        stats["compliance_mapped"] += 1
        stats["frameworks_affected"].update(frameworks)

    def _enrich_sla(
        self,
        finding: Dict[str, Any],
        now: datetime,
        stats: Dict[str, Any],
    ) -> None:
        """Assign SLA deadline based on severity."""
        severity = str(finding.get("severity", "info")).lower().strip()
        target_hours = self._SLA_HOURS.get(severity, self._SLA_HOURS["info"])

        deadline = now + timedelta(hours=target_hours)

        # SLA urgency: 1.0 = deadline is now, 0.0 = full time remaining
        # For newly assigned SLAs, urgency starts at 0.0
        sla_urgency = 0.0

        # If finding has an existing discovered_at, compute actual urgency
        discovered_at_str = finding.get("discovered_at") or finding.get("created_at")
        if discovered_at_str and isinstance(discovered_at_str, str):
            try:
                discovered_at = datetime.fromisoformat(
                    discovered_at_str.replace("Z", "+00:00")
                )
                elapsed = (now - discovered_at).total_seconds() / 3600.0
                sla_urgency = min(1.0, max(0.0, round(elapsed / target_hours, 4)))
                # Recompute deadline from discovery time, not now
                deadline = discovered_at + timedelta(hours=target_hours)
            except (ValueError, TypeError):
                pass  # Use defaults if timestamp is malformed

        finding["sla_deadline"] = deadline.isoformat()
        finding["sla_target_hours"] = target_hours
        finding["sla_urgency"] = sla_urgency
        stats["sla_assigned"] += 1

    def _enrich_attack_paths(
        self,
        finding: Dict[str, Any],
        ap_engine: Any,
        stats: Dict[str, Any],
    ) -> None:
        """Add attack path count and blast radius from graph engine."""
        if ap_engine is None:
            return

        # Determine node ID for graph lookup -- prefer CVE, then finding ID
        node_id = (
            finding.get("cve_id")
            or finding.get("id")
            or finding.get("finding_id")
        )
        if not node_id or not isinstance(node_id, str):
            return

        br_result = ap_engine(node_id, max_hops=3)
        if not isinstance(br_result, dict):
            return

        finding["attack_paths_count"] = br_result.get("total_paths", 0)
        finding["blast_radius"] = br_result.get("affected_nodes", 0)
        stats["attack_paths_enriched"] += 1

    def _enrich_code_to_cloud(
        self,
        finding: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> None:
        """Add code-to-cloud trace data (risk amplification, cloud exposure).

        Uses the CodeToCloudTracer to determine how a vulnerability's risk
        amplifies as it propagates from source code through build/deploy
        to cloud runtime. This is the key differentiator vs Apiiro/Wiz.
        """
        try:
            from core.code_to_cloud_tracer import get_code_to_cloud_tracer
        except ImportError:
            return

        vuln_id = (
            finding.get("cve_id")
            or finding.get("id")
            or finding.get("finding_id")
        )
        if not vuln_id or not isinstance(vuln_id, str):
            return

        tracer = get_code_to_cloud_tracer()
        result = tracer.trace(
            vulnerability_id=vuln_id,
            source_file=finding.get("file_path", finding.get("source_file", "")),
            source_line=finding.get("line_number", finding.get("source_line", 0)),
            cloud_service=finding.get("cloud_service", ""),
            internet_facing=finding.get("internet_facing", False),
        )

        finding["code_to_cloud"] = {
            "trace_id": result.trace_id,
            "risk_amplification": result.risk_amplification,
            "cloud_exposure": result.cloud_exposure,
            "attack_path_length": result.attack_path_length,
            "remediation_points": len(result.remediation_points),
        }
        stats["code_to_cloud_enriched"] += 1

    def _enrich_material_change(
        self,
        finding: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> None:
        """Boost risk score for findings in files with BREAKING/MATERIAL changes.

        Uses MaterialChangeDetector metadata (if available on the finding's
        file path) to amplify risk for vulnerabilities discovered in code areas
        undergoing security-relevant modifications.  This bridges the material
        change detection engine with the brain pipeline's triage logic.
        """
        file_path = finding.get("file_path") or finding.get("source_file") or ""
        if not file_path:
            return

        # Check if finding already has material_change data attached
        # (e.g., from an earlier PR analysis stored on the finding)
        mc_data = finding.get("material_change")
        if isinstance(mc_data, dict):
            classification = mc_data.get("classification", "COSMETIC")
        else:
            # Attempt to infer from finding metadata
            classification = finding.get("material_classification", "")

        if not classification or classification == "COSMETIC":
            return

        # Apply risk amplification based on classification
        current_risk = finding.get("risk_score", 0.0)
        if isinstance(current_risk, (int, float)):
            if classification == "BREAKING":
                # BREAKING change: significant risk boost (up to +15%)
                boost = min(0.15, 0.15 * (1 - current_risk))
                finding["risk_score"] = round(min(1.0, current_risk + boost), 4)
                finding["material_change_boost"] = round(boost, 4)
            elif classification == "MATERIAL":
                # MATERIAL change: moderate risk boost (up to +8%)
                boost = min(0.08, 0.08 * (1 - current_risk))
                finding["risk_score"] = round(min(1.0, current_risk + boost), 4)
                finding["material_change_boost"] = round(boost, 4)

        finding["material_change_classification"] = classification
        stats["material_change_enriched"] += 1

    # ------------------------------------------------------------------
    # Data Quality Assessment
    # ------------------------------------------------------------------
    def _compute_data_quality(
        self, ctx: Dict[str, Any], result: "PipelineResult"
    ) -> Dict[str, Any]:
        """Compute per-step data quality so customers know what's trustworthy.

        Returns a dict with overall score and per-step status showing whether
        each step did real work, used a fallback, or was skipped entirely.
        """
        steps_quality: Dict[str, Dict[str, str]] = {}
        warnings: List[str] = []
        degraded = 0

        for step in result.steps:
            name = step.name
            output = step.output or {}

            if step.status == StepStatus.SKIPPED:
                steps_quality[name] = {"status": "skipped", "detail": "Step was not requested"}
                continue
            if step.status == StepStatus.FAILED:
                steps_quality[name] = {"status": "failed", "detail": step.error or "Unknown error"}
                degraded += 1
                continue

            # Detect fallback per step
            if name == "connect":
                connectors_val = output.get("connectors_queried", 0)
                n_connectors = len(connectors_val) if isinstance(connectors_val, list) else int(connectors_val or 0)
                if n_connectors > 0:
                    steps_quality[name] = {"status": "real", "detail": f"{n_connectors} connectors queried"}
                else:
                    steps_quality[name] = {"status": "fallback", "detail": "No external scanners configured"}
                    warnings.append("Step 1 (Connect): No external scanners — using only provided findings")
                    degraded += 1

            elif name == "enrich_threats":
                source = ctx.get("_enrich_source", "estimated")
                if source == "live_api":
                    steps_quality[name] = {"status": "real", "detail": "Live EPSS/KEV/NVD API data"}
                elif source == "local_feeds":
                    hits = ctx.get("_enrich_feed_hits", 0)
                    steps_quality[name] = {"status": "real", "detail": f"Local feed DB ({hits} CVE matches)"}
                else:
                    steps_quality[name] = {"status": "fallback", "detail": "Severity-based estimates only"}
                    warnings.append("Step 6 (Enrich): EPSS/CVSS are estimates. Run feed sync for real data.")
                    degraded += 1

            elif name == "score_risk":
                model_ver = output.get("model_version", "")
                if "deterministic" in str(model_ver):
                    steps_quality[name] = {"status": "fallback", "detail": "Deterministic formula"}
                    warnings.append("Step 7 (Score): Deterministic risk formula. Train ML model for accuracy.")
                    degraded += 1
                else:
                    steps_quality[name] = {"status": "real", "detail": f"ML model {model_ver}"}

            elif name == "multi_llm_consensus":
                mode = output.get("mode", "")
                if mode == "deterministic" or output.get("skipped"):
                    steps_quality[name] = {"status": "fallback", "detail": "Rule-based — no LLM keys"}
                    warnings.append("Step 9 (AI Consensus): No LLM providers. Set OPENAI_API_KEY.")
                    degraded += 1
                else:
                    steps_quality[name] = {"status": "real", "detail": "LLM consensus completed"}

            else:
                if output.get("skipped"):
                    steps_quality[name] = {"status": "fallback", "detail": output.get("reason", "Dependency unavailable")}
                    degraded += 1
                else:
                    steps_quality[name] = {"status": "real", "detail": "OK"}

        total_active = sum(1 for s in result.steps if s.status != StepStatus.SKIPPED)
        real_count = sum(1 for v in steps_quality.values() if v["status"] == "real")
        score = round(real_count / max(total_active, 1), 2)

        # Post-pipeline enrichment quality
        enrichment_quality: Dict[str, Any] = {"status": "skipped", "detail": "Not run"}
        if ctx.get("_post_pipeline_enriched"):
            e_stats = result.enrichment_stats or {}
            total = e_stats.get("total_findings", 0)
            mapped = e_stats.get("compliance_mapped", 0)
            sla = e_stats.get("sla_assigned", 0)
            ap = e_stats.get("attack_paths_enriched", 0)
            if total > 0 and (mapped > 0 or sla > 0):
                enrichment_quality = {
                    "status": "real",
                    "detail": (
                        f"compliance={mapped}/{total}, "
                        f"sla={sla}/{total}, "
                        f"attack_paths={ap}/{total}"
                    ),
                }
            elif total > 0:
                enrichment_quality = {
                    "status": "fallback",
                    "detail": "No enrichment dependencies available",
                }
                warnings.append(
                    "Post-pipeline enrichment: no compliance mappings or "
                    "graph engine available"
                )
            else:
                enrichment_quality = {
                    "status": "skipped",
                    "detail": "No findings to enrich",
                }
        steps_quality["post_pipeline_enrichment"] = enrichment_quality

        return {
            "overall_score": score,
            "overall_grade": "A" if score >= 0.9 else "B" if score >= 0.7 else "C" if score >= 0.5 else "D",
            "steps": steps_quality,
            "warnings": warnings,
            "degraded_steps": degraded,
            "real_steps": real_count,
            "total_active_steps": total_active,
        }

    # ------------------------------------------------------------------
    # Analytics Data Bridge
    # ------------------------------------------------------------------
    def _sync_to_analytics(self, ctx: Dict[str, Any]) -> int:
        """Sync pipeline findings to analytics.db so dashboards show results.

        This bridges the data island between pipeline and analytics. Never raises.
        """
        try:
            import sqlite3 as _sqlite3
            from pathlib import Path as _Path

            db_path = _Path("data/analytics.db")
            if not db_path.exists():
                return 0

            conn = _sqlite3.connect(str(db_path), timeout=5)
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    severity TEXT,
                    status TEXT DEFAULT 'open',
                    source TEXT,
                    asset_name TEXT,
                    cve_id TEXT,
                    cvss_score REAL,
                    epss_score REAL,
                    risk_score REAL,
                    in_kev INTEGER DEFAULT 0,
                    org_id TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)

            # Perf fix #3: build all row tuples first, then flush with a
            # single executemany() call instead of one round-trip per finding.
            now = datetime.now(timezone.utc).isoformat()
            org_id_val = ctx.get("org_id", "default")
            rows = []
            for f in ctx.get("findings", []):
                title = str(f.get("title", ""))[:500]
                severity = str(f.get("severity", "medium"))[:20]
                source = str(f.get("source", "pipeline"))[:100]
                asset = str(f.get("asset_name", ""))[:200]
                cve = str(f.get("cve_id", ""))[:30]

                finding_id = f.get("finding_id") or f.get("id")
                if not finding_id:
                    finding_id = hashlib.sha256(
                        f"{title}|{asset}|{severity}".encode()
                    ).hexdigest()[:16]

                rows.append((
                    finding_id, title, severity, str(f.get("status", "open")),
                    source, asset, cve, f.get("cvss_score"), f.get("epss_score"),
                    f.get("risk_score"), 1 if f.get("in_kev") else 0,
                    org_id_val, now, now,
                ))

            synced = 0
            if rows:
                try:
                    cursor.executemany(
                        """INSERT INTO findings (id, title, severity, status, source,
                           asset_name, cve_id, cvss_score, epss_score, risk_score,
                           in_kev, org_id, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(id) DO UPDATE SET
                             cvss_score=excluded.cvss_score, epss_score=excluded.epss_score,
                             risk_score=excluded.risk_score, in_kev=excluded.in_kev,
                             updated_at=excluded.updated_at
                        """,
                        rows,
                    )
                    synced = cursor.rowcount if cursor.rowcount >= 0 else len(rows)
                except _sqlite3.Error:
                    pass

            conn.commit()
            conn.close()
            return synced
        except ImportError as e:
            logger.warning("Analytics sync failed (non-fatal): %s", type(e).__name__)
            return 0
        except Exception as e:  # noqa: BLE001 - sqlite3 may raise beyond sqlite3.Error (e.g. OperationalError subclasses); never break the pipeline
            logger.warning("Analytics sync failed (non-fatal): %s", type(e).__name__)
            return 0

    # ------------------------------------------------------------------
    # Step 1: Connect everything once
    # ------------------------------------------------------------------
    def _step_connect(self, ctx: Dict[str, Any], inp: PipelineInput) -> Dict[str, Any]:
        """Attempt to pull findings from configured connectors, then tally.

        Connector configuration is resolved in priority order:
        1. ``inp.metadata["connector_config"]`` — caller-supplied dict
        2. Environment variables (FIXOPS_SNYK_TOKEN, FIXOPS_GITHUB_TOKEN, etc.)

        Each connector is invoked independently — a failure in one NEVER
        blocks the others or halts the pipeline.  All connector-fetched
        findings are appended to ctx["findings"] with a ``connector_source``
        tag so downstream steps can distinguish them from caller-supplied data.
        """
        connectors_queried: List[str] = []
        connector_errors: List[str] = []
        fetched_count = 0

        # ------------------------------------------------------------------
        # Wave 2D Integration 3 — auto-collect via ConnectorIngestionScheduler
        # When pipeline is invoked with no findings, attempt to self-pull from
        # configured connectors. Wave 2F may add the scheduler module — if it
        # is missing, we silently fall through to env-var connectors below.
        # ------------------------------------------------------------------
        if not ctx["findings"]:
            try:
                from core.connector_ingestion_scheduler import (
                    ConnectorIngestionScheduler,
                )
                scheduler = ConnectorIngestionScheduler(ctx["org_id"])
                collected = scheduler.collect_all_findings()
                ctx["findings"].extend(collected)
                logger.info("_step_connect: auto-collected %d findings", len(collected))
            except ImportError:
                logger.debug("ConnectorIngestionScheduler not available — skipping auto-collect")
            except Exception as e:
                logger.warning("_step_connect auto-collect failed: %s", e)

        # ------------------------------------------------------------------
        # Resolve connector configuration
        # ------------------------------------------------------------------
        caller_cfg: Dict[str, Any] = {}
        if isinstance(inp.metadata.get("connector_config"), dict):
            caller_cfg = inp.metadata["connector_config"]

        def _cfg(name: str) -> Dict[str, Any]:
            """Merge caller config with env-var defaults for a named connector."""
            base = caller_cfg.get(name, {}) if caller_cfg else {}
            return base  # env-var fallbacks applied per connector below

        # ------------------------------------------------------------------
        # Helper: normalise a raw finding from an external source
        # ------------------------------------------------------------------
        def _normalise(raw: Any, source_tag: str) -> Optional[Dict[str, Any]]:
            if not isinstance(raw, dict):
                return None
            f: Dict[str, Any] = dict(raw)
            f.setdefault("connector_source", source_tag)
            f.setdefault("org_id", ctx["org_id"])
            f.setdefault("source", source_tag)
            # Coerce severity to lowercase
            if "severity" in f and isinstance(f["severity"], str):
                f["severity"] = f["severity"].lower()
            return f

        # ------------------------------------------------------------------
        # 1a. Snyk — FIXOPS_SNYK_TOKEN + FIXOPS_SNYK_ORG_ID
        # ------------------------------------------------------------------
        snyk_token = os.environ.get("FIXOPS_SNYK_TOKEN") or _cfg("snyk").get("token")
        snyk_org = os.environ.get("FIXOPS_SNYK_ORG_ID") or _cfg("snyk").get("org_id")
        if snyk_token and snyk_org:
            try:
                from core.security_connectors import SnykConnector

                snyk = SnykConnector(
                    {"token": snyk_token, "org_id": snyk_org}
                )
                connectors_queried.append("snyk")
                projects_result = snyk.list_projects()
                if projects_result.status == "fetched":
                    projects = projects_result.details.get("projects", [])
                    for proj in projects[:20]:  # cap at 20 projects to avoid blocking
                        pid = proj.get("id") or proj.get("projectId")
                        if not pid:
                            continue
                        issues_result = snyk.get_issues(str(pid))
                        if issues_result.status == "fetched":
                            for issue in issues_result.details.get("issues", []):
                                vuln = issue.get("issueData") or issue
                                norm = _normalise(
                                    {
                                        "id": issue.get("id", ""),
                                        "title": vuln.get("title", ""),
                                        "severity": vuln.get("severity", "medium"),
                                        "cve_id": (
                                            vuln.get("identifiers", {})
                                            .get("CVE", [None])[0]
                                        ),
                                        "cvss_score": vuln.get("cvssScore"),
                                        "description": vuln.get("description", ""),
                                        "component": proj.get("name", ""),
                                        "fix_available": issue.get(
                                            "isUpgradable", False
                                        ),
                                    },
                                    "snyk",
                                )
                                if norm:
                                    ctx["findings"].append(norm)
                                    fetched_count += 1
                elif projects_result.status == "failed":
                    connector_errors.append(
                        f"snyk:list_projects:{projects_result.details.get('error', 'unknown')}"
                    )
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                connector_errors.append(f"snyk:{type(exc).__name__}")
                logger.debug("Snyk connector error in Step 1: %s", type(exc).__name__)

        # ------------------------------------------------------------------
        # 1b. SonarQube — FIXOPS_SONARQUBE_URL + FIXOPS_SONARQUBE_TOKEN
        # ------------------------------------------------------------------
        sonar_url = os.environ.get("FIXOPS_SONARQUBE_URL") or _cfg("sonarqube").get("url")
        sonar_token = (
            os.environ.get("FIXOPS_SONARQUBE_TOKEN") or _cfg("sonarqube").get("token")
        )
        if sonar_url and sonar_token:
            try:
                from core.security_connectors import SonarQubeConnector

                sonar = SonarQubeConnector(
                    {
                        "base_url": sonar_url,
                        "token": sonar_token,
                        "project_key": _cfg("sonarqube").get("project_key"),
                    }
                )
                connectors_queried.append("sonarqube")
                issues_result = sonar.get_issues()
                if issues_result.status == "fetched":
                    for issue in issues_result.details.get("issues", []):
                        sev_map = {
                            "BLOCKER": "critical",
                            "CRITICAL": "high",
                            "MAJOR": "medium",
                            "MINOR": "low",
                            "INFO": "info",
                        }
                        norm = _normalise(
                            {
                                "id": issue.get("key", ""),
                                "title": issue.get("message", ""),
                                "severity": sev_map.get(
                                    str(issue.get("severity", "")).upper(), "medium"
                                ),
                                "rule_id": issue.get("rule"),
                                "component": issue.get("component", ""),
                                "file_path": issue.get("component", ""),
                                "line": issue.get("line"),
                                "description": issue.get("message", ""),
                            },
                            "sonarqube",
                        )
                        if norm:
                            ctx["findings"].append(norm)
                            fetched_count += 1
                elif issues_result.status == "failed":
                    connector_errors.append(
                        f"sonarqube:get_issues:{issues_result.details.get('error', 'unknown')}"
                    )
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                connector_errors.append(f"sonarqube:{type(exc).__name__}")
                logger.debug("SonarQube connector error in Step 1: %s", type(exc).__name__)

        # ------------------------------------------------------------------
        # 1c. GitHub Dependabot / Code Scanning Alerts
        #     FIXOPS_GITHUB_TOKEN + FIXOPS_GITHUB_OWNER + FIXOPS_GITHUB_REPO
        # ------------------------------------------------------------------
        gh_token = (
            os.environ.get("FIXOPS_GITHUB_TOKEN") or _cfg("github").get("token")
        )
        gh_owner = (
            os.environ.get("FIXOPS_GITHUB_OWNER") or _cfg("github").get("owner")
        )
        gh_repo = (
            os.environ.get("FIXOPS_GITHUB_REPO") or _cfg("github").get("repo")
        )
        if gh_token and gh_owner and gh_repo:
            try:
                from core.connectors import GitHubConnector as _GHConnector

                gh = _GHConnector(
                    {
                        "token": gh_token,
                        "owner": gh_owner,
                        "repo": gh_repo,
                    }
                )
                connectors_queried.append("github")

                # Fetch Dependabot vulnerability alerts via GitHub REST API
                dep_endpoint = (
                    f"https://api.github.com/repos/{gh_owner}/{gh_repo}"
                    "/dependabot/alerts?state=open&per_page=100"
                )
                try:
                    dep_resp = gh._request(
                        "GET",
                        dep_endpoint,
                        headers={
                            "Authorization": f"Bearer {gh_token}",
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    if dep_resp.status_code == 200:
                        alerts = dep_resp.json() if dep_resp.content else []
                        for alert in alerts if isinstance(alerts, list) else []:
                            adv = alert.get("security_advisory") or {}
                            vuln = alert.get("security_vulnerability") or {}
                            sev_map = {
                                "critical": "critical",
                                "high": "high",
                                "moderate": "medium",
                                "low": "low",
                            }
                            cves = [
                                i["value"]
                                for i in adv.get("identifiers", [])
                                if i.get("type") == "CVE"
                            ]
                            norm = _normalise(
                                {
                                    "id": f"dependabot-{alert.get('number', '')}",
                                    "title": adv.get("summary", ""),
                                    "severity": sev_map.get(
                                        str(adv.get("severity", "")).lower(), "medium"
                                    ),
                                    "cve_id": cves[0] if cves else None,
                                    "cvss_score": adv.get("cvss", {}).get("score"),
                                    "component": vuln.get("package", {}).get("name"),
                                    "description": adv.get("description", ""),
                                    "fix_available": bool(
                                        vuln.get("first_patched_version")
                                    ),
                                },
                                "github_dependabot",
                            )
                            if norm:
                                ctx["findings"].append(norm)
                                fetched_count += 1
                except (OSError, ValueError, KeyError, RuntimeError) as dep_exc:  # narrowed from bare Exception
                    logger.debug(
                        "GitHub Dependabot fetch error: %s", type(dep_exc).__name__
                    )
                    connector_errors.append(f"github_dependabot:{type(dep_exc).__name__}")

                # Fetch Code Scanning alerts
                cs_endpoint = (
                    f"https://api.github.com/repos/{gh_owner}/{gh_repo}"
                    "/code-scanning/alerts?state=open&per_page=100"
                )
                try:
                    cs_resp = gh._request(
                        "GET",
                        cs_endpoint,
                        headers={
                            "Authorization": f"Bearer {gh_token}",
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    if cs_resp.status_code == 200:
                        cs_alerts = cs_resp.json() if cs_resp.content else []
                        for alert in cs_alerts if isinstance(cs_alerts, list) else []:
                            rule = alert.get("rule") or {}
                            sev_map = {
                                "critical": "critical",
                                "high": "high",
                                "medium": "medium",
                                "warning": "medium",
                                "low": "low",
                                "note": "info",
                            }
                            location = alert.get("most_recent_instance", {}).get(
                                "location", {}
                            )
                            norm = _normalise(
                                {
                                    "id": f"code-scan-{alert.get('number', '')}",
                                    "title": rule.get("name", rule.get("id", "")),
                                    "severity": sev_map.get(
                                        str(rule.get("severity", "")).lower(), "medium"
                                    ),
                                    "rule_id": rule.get("id"),
                                    "description": rule.get("description", ""),
                                    "file_path": location.get("path"),
                                    "line": location.get("start_line"),
                                    "cwe_id": (
                                        rule.get("tags", [None])[0]
                                        if rule.get("tags")
                                        else None
                                    ),
                                },
                                "github_code_scanning",
                            )
                            if norm:
                                ctx["findings"].append(norm)
                                fetched_count += 1
                except (OSError, ValueError, KeyError, RuntimeError) as cs_exc:  # narrowed from bare Exception
                    logger.debug(
                        "GitHub code-scanning fetch error: %s", type(cs_exc).__name__
                    )
                    connector_errors.append(
                        f"github_code_scanning:{type(cs_exc).__name__}"
                    )

            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                connector_errors.append(f"github:{type(exc).__name__}")
                logger.debug("GitHub connector error in Step 1: %s", type(exc).__name__)

        # ------------------------------------------------------------------
        # 1d. Jira — pull existing security tickets tagged as findings
        #     FIXOPS_JIRA_URL + FIXOPS_JIRA_USER + FIXOPS_JIRA_TOKEN
        # ------------------------------------------------------------------
        jira_url = os.environ.get("FIXOPS_JIRA_URL") or _cfg("jira").get("url")
        jira_user = os.environ.get("FIXOPS_JIRA_USER") or _cfg("jira").get("user_email")
        jira_token = os.environ.get("FIXOPS_JIRA_TOKEN") or _cfg("jira").get("token")
        jira_project = (
            os.environ.get("FIXOPS_JIRA_PROJECT") or _cfg("jira").get("project_key")
        )
        jira_jql = (
            os.environ.get("FIXOPS_JIRA_FINDINGS_JQL")
            or _cfg("jira").get("findings_jql")
        )
        if jira_url and jira_user and jira_token and (jira_project or jira_jql):
            try:
                from core.connectors import JiraConnector as _JiraConnector

                jira = _JiraConnector(
                    {
                        "url": jira_url,
                        "user_email": jira_user,
                        "token": jira_token,
                        "project_key": jira_project or "SEC",
                    }
                )
                connectors_queried.append("jira")
                jql = jira_jql or (
                    f"project = {jira_project} AND labels = security-finding"
                    " AND statusCategory != Done ORDER BY created DESC"
                )
                result = jira.search_issues(jql, max_results=200)
                if result.status == "fetched":
                    for issue in result.details.get("issues", []):
                        fields = issue.get("fields", {})
                        pri = (fields.get("priority") or {}).get("name", "Medium")
                        sev_map = {
                            "Highest": "critical",
                            "High": "high",
                            "Medium": "medium",
                            "Low": "low",
                            "Lowest": "info",
                        }
                        norm = _normalise(
                            {
                                "id": issue.get("key", ""),
                                "title": fields.get("summary", ""),
                                "severity": sev_map.get(pri, "medium"),
                                "description": str(
                                    fields.get("description") or ""
                                )[:500],
                                "asset_name": fields.get("components", [{}])[0].get(
                                    "name", ""
                                )
                                if fields.get("components")
                                else "",
                                "jira_key": issue.get("key"),
                            },
                            "jira",
                        )
                        if norm:
                            ctx["findings"].append(norm)
                            fetched_count += 1
                elif result.status == "failed":
                    connector_errors.append(
                        f"jira:search:{result.details.get('reason', 'unknown')}"
                    )
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                connector_errors.append(f"jira:{type(exc).__name__}")
                logger.debug("Jira connector error in Step 1: %s", type(exc).__name__)

        # ------------------------------------------------------------------
        # Tally and return
        # ------------------------------------------------------------------
        result_out: Dict[str, Any] = {
            "findings_count": len(ctx.get("findings", [])),
            "assets_count": len(ctx.get("assets", [])),
            "source": inp.source,
            "connector_fetched": fetched_count,
            "connectors_queried": connectors_queried,
        }
        if connector_errors:
            result_out["connector_errors"] = connector_errors
        if not connectors_queried:
            result_out["connector_note"] = (
                "No connectors configured. Set FIXOPS_SNYK_TOKEN, "
                "FIXOPS_SONARQUBE_TOKEN, FIXOPS_GITHUB_TOKEN, or "
                "FIXOPS_JIRA_TOKEN to enable live ingestion."
            )
        return result_out

    # ------------------------------------------------------------------
    # Step 2: Translate into common language
    # ------------------------------------------------------------------
    def _step_normalize(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Ensure every finding has a canonical shape and validate parser quality.

        [V7] MCP-Native Platform — validates parser output quality.
        [V3] Decision Intelligence — garbage-in-garbage-out protection.

        After normalization, runs ParserQualityValidator to check:
        - Required fields present
        - Severity values valid
        - Severity distributions within expected bounds
        - CVE/CWE format correctness
        - Deduplication readiness

        Quality validation runs defensively — failures do NOT block the pipeline,
        but quality metrics are attached to the step output for observability.
        """
        normalized = 0
        for f in ctx["findings"]:
            f.setdefault("severity", "medium")
            f.setdefault("source", inp.source)
            f.setdefault("org_id", ctx["org_id"])
            f.setdefault("title", f.get("message", f.get("rule_id", "unknown")))
            f.setdefault("cve_id", None)
            f.setdefault("asset_name", f.get("asset", f.get("component", "unknown")))
            normalized += 1

        # [V7] Parser quality validation — validate normalized findings
        quality_result = None
        try:
            from core.ml.parser_quality import ParserQualityValidator
            validator = ParserQualityValidator()

            # Determine scanner type from input metadata or first finding
            scanner_type = inp.metadata.get("scanner_type", "")
            if not scanner_type and ctx["findings"]:
                scanner_type = ctx["findings"][0].get(
                    "scanner_source",
                    ctx["findings"][0].get("source", inp.source),
                )

            quality_result = validator.validate_findings(
                ctx["findings"], scanner_type=scanner_type or "unknown"
            )

            # Attach quality metrics to context for downstream steps
            ctx["parser_quality"] = quality_result.to_dict()

            # Log quality issues if any
            if quality_result.issues:
                logger.info(
                    "Parser quality: score=%.1f, errors=%d, warnings=%d for scanner=%s",
                    quality_result.quality_score,
                    quality_result.error_count,
                    quality_result.warning_count,
                    scanner_type,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Parser quality validation skipped: %s", type(e).__name__)

        result = {"normalized_count": normalized}
        if quality_result is not None:
            result["parser_quality_score"] = round(quality_result.quality_score, 2)
            result["parser_quality_passes"] = quality_result.passes
            result["parser_quality_errors"] = quality_result.error_count
            result["parser_quality_warnings"] = quality_result.warning_count
        return result

    # ------------------------------------------------------------------
    # Step 3: Fix identity confusion (Fuzzy matching)
    # ------------------------------------------------------------------
    def _step_resolve_identity(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Use FuzzyIdentityResolver to map asset names → canonical IDs."""
        try:
            from core.services.fuzzy_identity import get_fuzzy_resolver

            resolver = get_fuzzy_resolver()
        except ImportError:
            return {
                "resolved": 0,
                "skipped": True,
                "reason": "fuzzy_identity unavailable",
            }

        # Register known assets first
        for asset in ctx["assets"]:
            name = asset.get("name", asset.get("id", ""))
            canonical_id = asset.get("id", name)
            if name:
                resolver.register_canonical(
                    canonical_id=canonical_id,
                    org_id=ctx["org_id"],
                    properties=asset,
                )
                # Also add the asset name as an alias for matching
                if name != canonical_id:
                    resolver.add_alias(canonical_id, name, source="pipeline")

        resolved = 0
        for f in ctx["findings"]:
            asset_name = f.get("asset_name", "")
            if not asset_name:
                continue
            match = resolver.resolve(asset_name, org_id=ctx["org_id"])
            if match:
                f["canonical_asset_id"] = match.canonical_id
                f["identity_confidence"] = match.confidence
                f["identity_strategy"] = (
                    match.strategy.value
                    if hasattr(match.strategy, "value")
                    else str(match.strategy)
                )
                resolved += 1
        return {"resolved": resolved, "total": len(ctx["findings"])}

    # ------------------------------------------------------------------
    # Step 3b: Auto-suppress known false positives
    # ------------------------------------------------------------------
    def _step_fp_auto_suppress(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Auto-suppress findings matching FP patterns reported 3+ times.

        [V8] Self-Learning — Integrates with the FalsePositiveLoop from
        the self-learning engine to leverage historical FP feedback data.
        """
        suppressed = 0
        suppression_source = "none"

        # Try FP feedback store first (legacy)
        try:
            store = get_fp_feedback_store()
            kept: List[Dict[str, Any]] = []
            for f in ctx["findings"]:
                scanner = f.get("scanner", f.get("source", ""))
                cwe_id = f.get("cwe_id", f.get("cwe", ""))
                rule_id = f.get("rule_id", "")
                if store.should_auto_suppress(
                    scanner=scanner, cwe_id=cwe_id, rule_id=rule_id
                ):
                    f["auto_suppressed"] = True
                    f["suppression_reason"] = "fp_feedback_pattern"
                    suppressed += 1
                kept.append(f)
            ctx["findings"] = kept
            suppression_source = "fp_store"
        except (OSError, ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            pass

        # Also integrate with self-learning FalsePositiveLoop
        try:
            from core.self_learning import SelfLearningEngine
            learning = SelfLearningEngine.get_instance()
            fp_loop = learning.fp_loop
            if fp_loop:
                suppressed_rules = fp_loop.get_suppressed_rules()
                if suppressed_rules:
                    for f in ctx["findings"]:
                        scanner = f.get("scanner", f.get("source", ""))
                        rule_id = f.get("rule_id", "")
                        rule_key = f"{scanner}:{rule_id}"
                        if rule_key in suppressed_rules and not f.get("auto_suppressed"):
                            f["auto_suppressed"] = True
                            f["suppression_reason"] = "self_learning_fp_loop"
                            suppressed += 1
                    suppression_source = "fp_store+self_learning" if suppression_source == "fp_store" else "self_learning"
        except (ImportError, OSError, ValueError, RuntimeError):
            pass  # Self-learning not available

        return {"suppressed": suppressed, "total": len(ctx.get("findings", [])), "source": suppression_source}

    # ------------------------------------------------------------------
    # Step 4: Collapse duplicates into Exposure Cases
    # ------------------------------------------------------------------
    def _local_dedup_findings(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fast O(n) local deduplication using dict-keyed lookup.

        Groups findings by (title, asset_name, severity) tuple. This is
        a lightweight fallback when DeduplicationService is unavailable or
        times out. Avoids O(n^2) pairwise comparison.

        Returns:
            Dict mapping cluster_key -> list of findings in that cluster.
        """
        clusters: Dict[tuple, List[Dict[str, Any]]] = {}
        for f in findings:
            key = (
                f.get("title", f.get("message", f.get("rule_id", "unknown"))),
                f.get("asset_name", f.get("asset", f.get("component", "unknown"))),
                str(f.get("severity", "medium")).lower(),
            )
            if key not in clusters:
                clusters[key] = []
            clusters[key].append(f)
        return clusters

    def _step_deduplicate(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Deduplicate findings and create Exposure Cases.

        Uses a thread-based timeout to prevent hanging on very large
        finding sets (50K+ findings can cause O(n^2) in dedup service).
        Falls back to fast O(n) local dedup when service is unavailable.
        """
        from pathlib import Path

        batch = None
        use_local_fallback = False

        try:
            from core.services.deduplication import DeduplicationService

            dedup = DeduplicationService(db_path=Path("fixops_dedup.db"))
        except ImportError:
            use_local_fallback = True
            dedup = None

        if not use_local_fallback:
            run_id = uuid.uuid4().hex[:12]

            # Run dedup with timeout to prevent hanging on large datasets
            def _do_dedup():
                return dedup.process_findings_batch(
                    ctx["findings"], run_id=run_id, org_id=ctx["org_id"], source=inp.source
                )

            try:
                future = self._exec.submit(_do_dedup)
                batch = future.result(timeout=self.STEP_TIMEOUT_S)
            except concurrent.futures.TimeoutError:
                logger.warning(
                    "Dedup step timed out after %ds for %d findings, using local fallback",
                    self.STEP_TIMEOUT_S,
                    len(ctx["findings"]),
                )
                use_local_fallback = True
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.warning("Dedup step failed (%s), using local fallback", type(e).__name__)
                use_local_fallback = True

        # Fast O(n) local fallback dedup
        if use_local_fallback:
            local_clusters = self._local_dedup_findings(ctx["findings"])
            total_findings = len(ctx["findings"])
            unique_count = len(local_clusters)
            noise_pct = round(
                (1.0 - unique_count / total_findings) * 100, 2
            ) if total_findings > 0 else 0.0

            # Generate cluster IDs for local dedup
            cluster_ids = []
            for key_tuple in local_clusters:
                # Stable cluster ID from dedup key
                key_str = "|".join(str(k) for k in key_tuple)
                cid = "LC-" + hashlib.sha256(key_str.encode()).hexdigest()[:12]
                cluster_ids.append(cid)
            ctx["clusters"] = cluster_ids

            # Wave 2D Integration 2 — also run correlator on fallback path
            self._correlate_and_emit(ctx)
            return {
                "total_findings": total_findings,
                "unique_clusters": unique_count,
                "noise_reduction_pct": noise_pct,
                "exposure_cases_created": 0,
                "exposure_cases_updated": 0,
                "method": "local_fallback",
                "correlator_cases": len(ctx.get("correlator_exposure_cases", [])),
            }

        # Service-based dedup succeeded — process results
        cluster_ids = list(
            set(
                r.get("cluster_id")
                for r in batch.get("results", batch.get("clusters", []))
                if isinstance(r, dict) and r.get("cluster_id")
            )
        )
        ctx["clusters"] = cluster_ids

        # Create Exposure Cases from clusters (idempotent — upsert, not blind insert)
        try:
            from core.exposure_case import (
                ExposureCase,
                get_case_manager,
                severity_to_priority,
            )

            mgr = get_case_manager()
            cases_created = []
            cases_updated = []

            # Build a lookup: cluster_id → dedup result row
            cluster_results = {}
            for r in batch.get("results", batch.get("clusters", [])):
                if isinstance(r, dict):
                    cluster_results[r["cluster_id"]] = r

            for cid in cluster_ids:
                cr = cluster_results.get(cid, {})

                # --- Idempotency: check if a case already owns this cluster ---
                existing_case = mgr.find_case_by_cluster(cid)
                if existing_case is not None:
                    # Bump finding count by occurrence delta and update
                    occ = cr.get("occurrence_count", 1)
                    if occ > existing_case.finding_count:
                        mgr.update_case(
                            existing_case.case_id,
                            {"finding_count": occ},
                        )
                    cases_updated.append(existing_case.case_id)
                    continue

                # --- Enrich from dedup cluster metadata ---
                # Fetch full cluster row from dedup DB for CVE/CWE/severity/title
                cluster_detail = None
                try:
                    cluster_detail = dedup.get_cluster(cid)
                except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                    pass

                severity = (cluster_detail or {}).get("severity", "medium")
                title_raw = (cluster_detail or {}).get(
                    "title", cr.get("correlation_key", cid[:8])
                )
                cve_id = (cluster_detail or {}).get("cve_id")
                component_id = (cluster_detail or {}).get("component_id")
                category = (cluster_detail or {}).get("category", "")
                occ_count = cr.get(
                    "occurrence_count",
                    (cluster_detail or {}).get("occurrence_count", 1),
                )

                # Derive risk score from severity
                sev_risk = {
                    "critical": 9.5,
                    "high": 7.5,
                    "medium": 5.0,
                    "low": 2.5,
                    "info": 0.5,
                }.get(str(severity or "medium").lower(), 5.0)

                case = ExposureCase(
                    case_id=f"EC-{uuid.uuid4().hex[:12]}",
                    title=title_raw[:120] if title_raw else f"Exposure-{cid[:8]}",
                    description=(
                        f"Auto-generated from dedup cluster {cid}. "
                        f"Category: {category}. Occurrences: {occ_count}."
                    ),
                    org_id=ctx["org_id"],
                    cluster_ids=[cid],
                    finding_count=occ_count,
                    root_cve=cve_id if cve_id else None,
                    root_component=component_id
                    if component_id and component_id != "unknown"
                    else None,
                    priority=severity_to_priority(severity),
                    risk_score=sev_risk,
                    blast_radius=occ_count,
                    tags=[category] if category and category != "sarif" else [],
                    metadata={
                        "source_cluster": cid,
                        "correlation_key": cr.get("correlation_key", ""),
                        "first_seen": cr.get("first_seen", ""),
                    },
                )
                created = mgr.create_case(case)
                cases_created.append(created.case_id)
            ctx["exposure_cases"] = cases_created
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
            # Only expose exception type — str(e) may leak DB paths or credentials
            logger.warning(
                "Could not create exposure cases: %s", type(e).__name__
            )
            cases_updated = []

        # ------------------------------------------------------------------
        # Wave 2D Integration 2 — FindingCorrelator union-find clustering
        # Writes to ctx["correlator_exposure_cases"] so it does not clobber
        # the dedup-service case_id list already in ctx["exposure_cases"].
        # ------------------------------------------------------------------
        self._correlate_and_emit(ctx)

        return {
            "total_findings": batch.get("total_findings", len(ctx["findings"])),
            "unique_clusters": len(cluster_ids),
            "noise_reduction_pct": batch.get("noise_reduction_percent", 0),
            "exposure_cases_created": len(ctx.get("exposure_cases", [])),
            "exposure_cases_updated": len(cases_updated),
            "correlator_cases": len(ctx.get("correlator_exposure_cases", [])),
        }

    def _correlate_and_emit(self, ctx: Dict[str, Any]) -> None:
        """Run FindingCorrelator union-find and emit case events.

        Wave 2D Integration 2 — pipeline never fails when correlator
        or event bus unavailable. Async emit handled via asyncio.run
        in a try/except since this method is sync.
        """
        try:
            from core.finding_correlator import FindingCorrelator
            correlator = FindingCorrelator()
            cases = correlator.build_exposure_cases(
                ctx["findings"], org_id=ctx["org_id"]
            )
            ctx["correlator_exposure_cases"] = [c.model_dump() for c in cases]

            # Best-effort event emission — async bus called from sync context
            try:
                import asyncio as _asyncio

                from core.trustgraph_event_bus import get_event_bus
                bus = get_event_bus()

                async def _emit_all():
                    for case in ctx["correlator_exposure_cases"]:
                        await bus.emit("finding.created", {
                            "org_id": ctx["org_id"],
                            "engine": "correlator",
                            "id": case.get("id") or case.get("case_id") or case.get("title", ""),
                            "title": case.get("title", ""),
                            "severity": case.get("severity", "medium"),
                            "entity_type": "exposure_case",
                            "risk_score": case.get("risk_score"),
                            "finding_count": len(case.get("findings", [])),
                        })

                try:
                    _asyncio.get_running_loop()
                    # Inside running loop — schedule as task
                    _asyncio.ensure_future(_emit_all())
                except RuntimeError:
                    # No running loop — create a private loop to avoid
                    # thread-pool teardown race from asyncio.run()
                    _loop = _asyncio.new_event_loop()
                    try:
                        _loop.run_until_complete(_emit_all())
                    finally:
                        _loop.close()
            except Exception as bus_e:
                logger.warning("correlator event emission skipped: %s", bus_e)
        except Exception as e:
            logger.warning("correlator skipped: %s", e)

    # ------------------------------------------------------------------
    # Step 5: Build the Brain Map (Knowledge Graph)
    # ------------------------------------------------------------------
    def _step_build_graph(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Upsert nodes/edges to Knowledge Graph Brain.

        Performance optimizations for 1000+ findings:
        1. Pre-computes all node IDs, edge pairs, and CVE set BEFORE any upserts
        2. Deduplicates CVE nodes upfront via set comprehension (O(n))
        3. Batches upserts with pre-computed data to minimize per-item overhead
        4. Records detailed timing metrics for each phase (prep/nodes/edges)
        5. Per-finding error isolation prevents one bad finding from crashing step
        """
        try:
            from core.knowledge_brain import (
                EdgeType,
                EntityType,
                GraphEdge,
                GraphNode,
                get_brain,
            )

            brain = get_brain()
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            return {"nodes": 0, "edges": 0, "skipped": True}

        t_prep_start = time.monotonic()

        # ---------------------------------------------------------------
        # Phase 1: Pre-compute all graph data (pure Python, no I/O)
        # ---------------------------------------------------------------
        findings = ctx["findings"]
        org_id = ctx["org_id"]

        # Pre-compute asset node data
        asset_nodes: List[Dict[str, Any]] = []
        for asset in ctx["assets"]:
            node_id = asset.get("id", asset.get("name", ""))
            if node_id:
                asset_nodes.append({"node_id": node_id, "properties": asset})

        # Pre-compute all finding node data, edges, and unique CVEs in one pass
        finding_nodes: List[Dict[str, Any]] = []
        finding_asset_edges: List[tuple] = []  # (source_id, target_id)
        finding_cve_edges: List[tuple] = []  # (source_id, cve_id)
        # Deduplicate CVE nodes upfront via set comprehension
        unique_cves: set = {
            f["cve_id"] for f in findings
            if f.get("cve_id")
        }

        for f in findings:
            fid = f.get("id", f.get("rule_id", uuid.uuid4().hex[:12]))
            finding_nodes.append({
                "fid": fid,
                "title": f.get("title"),
                "severity": f.get("severity"),
            })

            # Pre-compute finding->asset edge
            asset_id = f.get("canonical_asset_id", f.get("asset_name"))
            if asset_id:
                finding_asset_edges.append((fid, asset_id))

            # Pre-compute finding->CVE edge
            cve = f.get("cve_id")
            if cve:
                finding_cve_edges.append((fid, cve))

        # Pre-compute exposure case nodes
        exposure_case_ids = ctx.get("exposure_cases", [])

        t_prep_end = time.monotonic()
        prep_ms = (t_prep_end - t_prep_start) * 1000

        # ---------------------------------------------------------------
        # Phase 2: Batch upsert all nodes (asset, finding, CVE, case)
        # ---------------------------------------------------------------
        t_upsert_start = time.monotonic()
        nodes_added = 0
        edges_added = 0
        graph_errors = 0

        # Upsert asset nodes
        for an in asset_nodes:
            brain.upsert_node(
                GraphNode(
                    node_id=an["node_id"],
                    node_type=EntityType.ASSET,
                    org_id=org_id,
                    properties=an["properties"],
                )
            )
            nodes_added += 1

        # Upsert finding nodes in batches for memory efficiency
        for batch_start in range(0, len(finding_nodes), self.GRAPH_BATCH_SIZE):
            batch = finding_nodes[batch_start: batch_start + self.GRAPH_BATCH_SIZE]
            for fn in batch:
                try:
                    brain.upsert_node(
                        GraphNode(
                            node_id=fn["fid"],
                            node_type=EntityType.FINDING,
                            org_id=org_id,
                            properties={
                                "title": fn["title"],
                                "severity": fn["severity"],
                            },
                        )
                    )
                    nodes_added += 1
                except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as graph_err:
                    graph_errors += 1
                    if graph_errors <= 5:
                        logger.warning(
                            "Graph upsert error for finding %s: %s",
                            fn["fid"],
                            type(graph_err).__name__,
                        )

        # Upsert unique CVE nodes (deduplicated — each CVE only once)
        for cve_id in unique_cves:
            try:
                brain.upsert_node(
                    GraphNode(
                        node_id=cve_id,
                        node_type=EntityType.CVE,
                        org_id=org_id,
                    )
                )
                nodes_added += 1
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as graph_err:
                graph_errors += 1
                if graph_errors <= 5:
                    logger.warning(
                        "Graph upsert error for CVE %s: %s",
                        cve_id,
                        type(graph_err).__name__,
                    )

        # Upsert exposure case nodes
        for case_id in exposure_case_ids:
            brain.upsert_node(
                GraphNode(
                    node_id=case_id,
                    node_type=EntityType.EXPOSURE_CASE,
                    org_id=org_id,
                )
            )
            nodes_added += 1

        t_upsert_end = time.monotonic()
        upsert_ms = (t_upsert_end - t_upsert_start) * 1000

        # ---------------------------------------------------------------
        # Phase 3: Batch add all edges (pre-computed, no per-item logic)
        # ---------------------------------------------------------------
        t_edges_start = time.monotonic()

        # Finding -> Asset edges
        for src, tgt in finding_asset_edges:
            try:
                brain.add_edge(
                    GraphEdge(
                        source_id=src,
                        target_id=tgt,
                        edge_type=EdgeType.AFFECTS,
                    )
                )
                edges_added += 1
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as graph_err:
                graph_errors += 1
                if graph_errors <= 5:
                    logger.warning(
                        "Graph edge error %s->%s: %s",
                        src, tgt,
                        type(graph_err).__name__,
                    )

        # Finding -> CVE edges
        for src, cve_id in finding_cve_edges:
            try:
                brain.add_edge(
                    GraphEdge(
                        source_id=src,
                        target_id=cve_id,
                        edge_type=EdgeType.REFERENCES,
                    )
                )
                edges_added += 1
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as graph_err:
                graph_errors += 1
                if graph_errors <= 5:
                    logger.warning(
                        "Graph edge error %s->%s: %s",
                        src, cve_id,
                        type(graph_err).__name__,
                    )

        t_edges_end = time.monotonic()
        edges_ms = (t_edges_end - t_edges_start) * 1000

        stats = brain.stats()
        ctx["graph_stats"] = stats
        result = {
            "nodes_added": nodes_added,
            "edges_added": edges_added,
            "unique_cves": len(unique_cves),
            "total_nodes": stats.get("total_nodes", 0),
            "total_edges": stats.get("total_edges", 0),
            "timing": {
                "prep_ms": round(prep_ms, 2),
                "upsert_ms": round(upsert_ms, 2),
                "edges_ms": round(edges_ms, 2),
            },
        }
        if graph_errors > 0:
            result["graph_errors"] = graph_errors
            logger.warning("Graph step completed with %d errors", graph_errors)

        # [V3] GNN attack-path analysis on the built graph
        try:
            from core.ml.attack_path_gnn import build_gnn_from_knowledge_graph

            gnn = build_gnn_from_knowledge_graph(brain)
            if gnn.is_fitted and gnn.metrics:
                ctx["gnn_model"] = gnn
                result["gnn_fitted"] = True
                result["gnn_coverage"] = round(gnn.metrics.coverage, 4)
                result["gnn_attention_entropy"] = round(gnn.metrics.attention_entropy, 4)
                result["gnn_fit_ms"] = round(gnn.metrics.fit_time_ms, 2)

                # Find top risk hotspots
                hotspots = gnn.get_attention_hotspots(top_k=5)
                if hotspots:
                    result["gnn_hotspots"] = [h["node_id"] for h in hotspots[:3]]
        except (OSError, ValueError, KeyError, RuntimeError) as gnn_err:  # narrowed from bare Exception
            logger.debug("GNN analysis skipped: %s", type(gnn_err).__name__)

        return result

    # ------------------------------------------------------------------
    # Step 6: Add threat reality signals (EPSS, KEV, CVSS)
    # ------------------------------------------------------------------
    def _step_enrich_threats(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Enrich findings with real EPSS scores, KEV status, and CVSS data.

        [V3] Decision Intelligence — Real threat feed enrichment.

        Priority chain:
        1. ThreatEnricher service (live API data from FIRST.org, CISA, NVD)
        2. Local feed databases (data/feeds/feeds.db — 317K EPSS + 1.5K KEV)
        3. Severity-based estimates (last resort, marked as estimated)
        """
        cve_ids = [f["cve_id"] for f in ctx["findings"] if f.get("cve_id")]
        if not cve_ids:
            return {"enriched": 0, "reason": "no CVE IDs to enrich"}

        # Try ML-powered threat enrichment with real API data
        try:
            from core.ml.threat_enricher import get_threat_enricher

            enricher = get_threat_enricher()
            result = enricher.enrich_findings(ctx["findings"])
            ctx["_enrich_source"] = "live_api"
            self._fuse_vuln_intel(ctx)
            self._apply_reachability_verdicts(ctx)
            return result
        except (ImportError, Exception) as e:
            logger.warning(
                "ThreatEnricher unavailable (%s), trying local feed databases",
                type(e).__name__,
            )

        # Try local feed databases — real data, not hardcoded
        epss_lookup, kev_lookup, nvd_lookup = self._load_local_feeds()
        feed_source = "local_feeds" if (epss_lookup or kev_lookup) else "estimated"

        enriched = 0
        feed_hits = 0
        for f in ctx["findings"]:
            cve = f.get("cve_id")
            if not cve:
                continue

            # EPSS: real data from local feed DB, else estimate
            if cve in epss_lookup:
                f["epss_score"] = epss_lookup[cve]["epss"]
                f["epss_percentile"] = epss_lookup[cve].get("percentile", 0.0)
                f["epss_source"] = "feeds_db"
                feed_hits += 1
            else:
                sev = f.get("severity", "medium").lower()
                epss_est = {"critical": 0.25, "high": 0.10, "medium": 0.03,
                            "low": 0.01, "info": 0.001}.get(sev, 0.03)
                if f.get("exploit_available"):
                    epss_est = min(epss_est * 3.0, 0.95)
                f["epss_score"] = round(epss_est, 6)
                f["epss_source"] = "estimated"

            # KEV: real lookup from local feed DB
            if cve in kev_lookup:
                f["in_kev"] = True
                f["kev_source"] = "feeds_db"
                f["kev_date_added"] = kev_lookup[cve].get("date_added", "")
                f["kev_due_date"] = kev_lookup[cve].get("due_date", "")
                f["kev_ransomware"] = kev_lookup[cve].get("ransomware", "Unknown")
                feed_hits += 1
            else:
                f["in_kev"] = False
                f["kev_source"] = "feeds_db" if kev_lookup else "unavailable"

            # CVSS: real data from NVD cache, else estimate from severity
            if cve in nvd_lookup:
                f["cvss_score"] = nvd_lookup[cve]
                f["cvss_source"] = "feeds_db"
            else:
                sev = f.get("severity", "medium").lower()
                f["cvss_score"] = {"critical": 9.5, "high": 7.5, "medium": 5.0,
                                   "low": 2.5, "info": 0.5}.get(sev, 5.0)
                f["cvss_source"] = "estimated"

            enriched += 1

        ctx["_enrich_source"] = feed_source
        ctx["_enrich_feed_hits"] = feed_hits
        self._fuse_vuln_intel(ctx)
        self._apply_reachability_verdicts(ctx)
        return {
            "enriched": enriched,
            "unique_cves": len(set(cve_ids)),
            "source": feed_source,
            "feed_hits": feed_hits,
            "feed_misses": enriched - feed_hits,
        }

    def _fuse_vuln_intel(self, ctx: Dict[str, Any]) -> None:
        """Wire findings through VulnIntelFusionEngine for multi-source consensus.

        Wave 2D Integration 1 — adds fusion_score, consensus_severity,
        consensus_priority to every finding that has a CVE id. Pipeline
        never fails if fusion is unavailable.

        Perf fix #2: build the feed-record list in one pass, then call
        ingest_source_feed once per record rather than rebuilding intermediate
        dicts inside a property-access-heavy loop.
        """
        try:
            from core.vuln_intel_fusion_engine import VulnIntelFusionEngine

            # Short-circuit: no CVE findings means nothing to fuse
            cve_findings = [f for f in ctx["findings"] if f.get("cve_id")]
            if not cve_findings:
                return

            fusion = VulnIntelFusionEngine()
            org_id = ctx["org_id"]

            # Build all feed records in a single list comprehension (avoids
            # repeated .get() attribute lookups inside the ingest call itself)
            # Pre-extract all fields in one list comprehension then call
            # ingest_from_source once per record (avoids repeated .get()
            # inside the call and uses the correct positional-arg signature)
            feed_records = [
                (
                    f["cve_id"],
                    f.get("engine", "pipeline"),
                    f.get("severity", "unknown"),
                    float(f.get("cvss") or f.get("cvss_score") or 0.0),
                    float(f.get("epss") or f.get("epss_score") or 0.0),
                    1 if (f.get("in_kev") or f.get("kev_listed")) else 0,
                )
                for f in cve_findings
            ]
            for cve_id, src_name, src_sev, cvss, epss, kev in feed_records:
                fusion.ingest_from_source(
                    org_id, cve_id, src_name, src_sev, cvss, epss, kev
                )

            pq = fusion.get_priority_queue(org_id)
            lookup = {x["cve_id"]: x for x in pq if x.get("cve_id")}
            for f in ctx["findings"]:
                fused = lookup.get(f.get("cve_id"))
                if fused:
                    f["fusion_score"] = fused.get("fusion_score", 0.0)
                    f["consensus_severity"] = fused.get("consensus_severity", f.get("severity"))
                    f["consensus_priority"] = fused.get("consensus_priority", 3)
                    f["epss_score"] = fused.get("epss_score", f.get("epss_score", 0.0))
                    f["kev_listed"] = bool(fused.get("kev_listed", 0))
            ctx["fused_vulns"] = pq
        except Exception as e:
            logger.warning("fusion enrichment skipped: %s", e)

    def _apply_reachability_verdicts(self, ctx: Dict[str, Any]) -> None:
        """Wave 3A — apply FunctionReachabilityEngine verdicts to findings.

        For every finding with a CVE id, query the reachability engine and
        annotate the finding with ``reachable``, ``reachable_callers``, and
        ``reachability_verdict``. Persists verdict to per-finding store when
        a finding id is present. Downgrades ``consensus_priority`` for
        unreachable findings (Apiiro-style noise reduction).

        Pipeline never fails when the engine is unavailable.
        """
        try:
            from core.function_reachability_engine import get_engine as get_reach_engine
            reach_engine = get_reach_engine()
            for f in ctx["findings"]:
                if not f.get("cve_id"):
                    continue
                pattern = f.get("dependency_fqn_pattern") or (
                    f"{f.get('package_name', '')}.%" if f.get("package_name") else ""
                )
                if not pattern.replace(".%", ""):
                    continue
                try:
                    callers = reach_engine.vulnerable_reachability(
                        ctx["org_id"], f["cve_id"], pattern
                    )
                except Exception as q_exc:  # noqa: BLE001 - per-finding isolation
                    logger.debug("reachability query skipped for %s: %s", f.get("cve_id"), q_exc)
                    continue
                f["reachable"] = bool(callers)
                f["reachable_callers"] = callers[:5]
                f["reachability_verdict"] = "reachable" if callers else "unreachable"
                if f.get("id"):
                    try:
                        reach_engine.record_finding_verdict(
                            ctx["org_id"], f["id"], f["cve_id"], pattern,
                            f["reachability_verdict"], callers,
                        )
                    except Exception:  # noqa: BLE001 - persistence is best-effort
                        pass
                # Downgrade priority (higher number = lower priority) for unreachable
                if not callers and "consensus_priority" in f:
                    try:
                        f["consensus_priority"] = min(4, int(f["consensus_priority"]) + 1)
                    except (ValueError, TypeError):
                        pass
        except Exception as exc:  # noqa: BLE001 - reachability is optional
            logger.warning("reachability verdicts skipped: %s", exc)

    def _run_attack_graph_gnn(self, ctx: Dict[str, Any]) -> None:
        """Wave 3B — build SecurityGraph and run GraphNeuralPredictor.

        Builds a SERVICE+VULNERABILITY graph from current ctx findings and
        assets, propagates risk via GNN, computes attack paths, and emits
        ``threat.detected`` events for the top 3 attack paths.

        Pipeline never fails when the GNN module is unavailable.
        """
        try:
            import uuid as _uuid

            from core.attack_graph_gnn import (
                EdgeType,
                GraphNeuralPredictor,
                NodeType,
                SecurityGraph,
            )
            graph = SecurityGraph()
            entry_points: List[str] = []
            vuln_ids: List[str] = []
            for asset in ctx.get("assets", []):
                aid = str(asset.get("id") or _uuid.uuid4())
                graph.add_node(
                    aid, NodeType.SERVICE,
                    properties=asset,
                    risk_score=float(asset.get("criticality_score", 0.5)),
                )
                entry_points.append(aid)
            for f in ctx.get("findings", []):
                vuln_id = str(f.get("id") or _uuid.uuid4())
                try:
                    cvss_val = float(f.get("cvss") or f.get("cvss_score") or 5.0)
                except (TypeError, ValueError):
                    cvss_val = 5.0
                graph.add_node(
                    vuln_id, NodeType.VULNERABILITY,
                    properties=f,
                    risk_score=cvss_val / 10.0,
                )
                vuln_ids.append(vuln_id)
                if f.get("asset_id") and f["asset_id"] in graph.nodes:
                    try:
                        graph.add_edge(f["asset_id"], vuln_id, EdgeType.AFFECTS)
                    except Exception:
                        pass
            predictor = GraphNeuralPredictor()
            try:
                predictor.propagate_risk(graph, iterations=3)
            except Exception:  # noqa: BLE001 - propagation is best-effort
                pass
            paths: List[Any] = []
            try:
                paths = predictor.find_attack_paths(
                    graph,
                    entry_points=entry_points or list(graph.nodes.keys())[:5],
                    targets=vuln_ids or list(graph.nodes.keys())[-5:],
                    max_paths=10,
                )
            except Exception:  # noqa: BLE001 - path finding is best-effort
                paths = []
            ctx["attack_paths"] = [
                p.to_dict() if hasattr(p, "to_dict") else p for p in paths
            ]
            ctx["graph_nodes"] = len(graph.nodes)
            ctx["graph_edges"] = len(graph.edges)

            # Emit threat.detected events for top 3 paths (async-safe)
            try:
                import asyncio as _asyncio

                from core.trustgraph_event_bus import get_event_bus
                bus = get_event_bus()

                async def _emit_paths():
                    for path in ctx["attack_paths"][:3]:
                        await bus.emit("threat.detected", {
                            "org_id": ctx["org_id"],
                            "engine": "attack_graph_gnn",
                            "id": str(_uuid.uuid4()),
                            "title": f"Attack path: {path.get('summary', path.get('entry', 'unknown'))}",
                            "severity": "high",
                            "entity_type": "attack_path",
                            "path": path.get("path", []),
                            "score": path.get("probability", 0.0) * path.get("impact_score", 0.0),
                        })

                try:
                    _asyncio.get_running_loop()
                    _asyncio.ensure_future(_emit_paths())
                except RuntimeError:
                    # No running loop — create an isolated one to avoid
                    # thread-pool teardown race from asyncio.run()
                    _loop = _asyncio.new_event_loop()
                    try:
                        _loop.run_until_complete(_emit_paths())
                    finally:
                        _loop.close()
            except Exception as bus_e:  # noqa: BLE001 - event emission is best-effort
                logger.warning("attack graph event emission skipped: %s", bus_e)
        except Exception as exc:  # noqa: BLE001 - GNN is optional
            logger.warning("attack graph GNN skipped: %s", exc)

    # ------------------------------------------------------------------
    # Module-level TTL cache for local feed data (Fix 1: avoid reloading
    # 317K EPSS + 1.5K KEV rows on every pipeline run).
    # Cache is invalidated after _FEEDS_CACHE_TTL_S seconds so long-running
    # processes pick up daily feed refreshes without restarting.
    # ------------------------------------------------------------------
    _feeds_cache: Optional[tuple] = None
    _feeds_cache_ts: float = 0.0
    _FEEDS_CACHE_TTL_S: float = 300.0  # 5-minute TTL

    @classmethod
    def _load_local_feeds(cls) -> tuple:
        """Load EPSS, KEV, and NVD data from local feed databases.

        Returns (epss_dict, kev_dict, nvd_dict) — each keyed by CVE ID.
        Returns empty dicts if databases are unavailable.

        Results are cached for _FEEDS_CACHE_TTL_S seconds to avoid
        re-reading 317K rows from SQLite on every pipeline run.
        """
        import sqlite3
        from pathlib import Path

        # Return cached data if still fresh (perf fix #1)
        now_mono = time.monotonic()
        if cls._feeds_cache is not None and (now_mono - cls._feeds_cache_ts) < cls._FEEDS_CACHE_TTL_S:
            return cls._feeds_cache

        epss: Dict[str, Any] = {}
        kev: Dict[str, Any] = {}
        nvd: Dict[str, float] = {}

        # Search for feeds.db in common locations
        candidates = [
            Path("data/feeds/feeds.db"),
            Path(".fixops_data/feeds/feeds.db"),
        ]
        db_path = None
        for p in candidates:
            if p.exists():
                db_path = p
                break

        if not db_path:
            logger.info("No local feed database found — enrichment will use estimates")
            result = (epss, kev, nvd)
            cls._feeds_cache = result
            cls._feeds_cache_ts = now_mono
            return result

        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            conn.row_factory = sqlite3.Row

            # Load EPSS scores
            try:
                cursor = conn.execute("SELECT cve_id, epss, percentile FROM epss_scores")
                for row in cursor:
                    epss[row["cve_id"]] = {
                        "epss": round(float(row["epss"]), 6),
                        "percentile": round(float(row["percentile"]), 4),
                    }
            except sqlite3.OperationalError:
                pass

            # Load KEV entries
            try:
                cursor = conn.execute(
                    "SELECT cve_id, date_added, due_date, known_ransomware_campaign_use "
                    "FROM kev_entries"
                )
                for row in cursor:
                    kev[row["cve_id"]] = {
                        "date_added": row["date_added"] or "",
                        "due_date": row["due_date"] or "",
                        "ransomware": row["known_ransomware_campaign_use"] or "Unknown",
                    }
            except sqlite3.OperationalError:
                pass

            # Load NVD CVSS scores
            try:
                cursor = conn.execute("SELECT cve_id, cvss_v3_score FROM nvd_cves WHERE cvss_v3_score IS NOT NULL")
                for row in cursor:
                    score = row["cvss_v3_score"]
                    if score is not None:
                        nvd[row["cve_id"]] = round(float(score), 1)
            except sqlite3.OperationalError:
                pass

            conn.close()
            logger.info(
                "Loaded local feeds: %d EPSS, %d KEV, %d NVD CVSS",
                len(epss), len(kev), len(nvd),
            )
        except (sqlite3.Error, OSError) as e:
            logger.warning("Failed to load local feeds: %s", type(e).__name__)

        result = (epss, kev, nvd)
        cls._feeds_cache = result
        cls._feeds_cache_ts = now_mono
        return result

    # ------------------------------------------------------------------
    # Step 7: Run smart algorithms (GNN + attack paths)
    # ------------------------------------------------------------------
    def _step_score_risk(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Score risk using ML model with fallback to deterministic formula.

        [V3] Decision Intelligence — ML-powered risk scoring.

        Uses a Gradient Boosted Trees model trained on the golden regression
        dataset (50 real CVE cases). The model considers 9 features:
        CVSS, EPSS, KEV, asset criticality, network exposure, exploit
        availability/maturity, reachability, and chain exploits.

        Falls back to a weighted linear formula if ML model is unavailable.
        """
        # Try to use ML risk scorer
        ml_available = False
        risk_model = None
        ML_MODEL_VERSION = "unknown"
        try:
            from core.ml.risk_scorer import MODEL_VERSION as _ml_ver
            from core.ml.risk_scorer import get_risk_model
            ML_MODEL_VERSION = _ml_ver
            risk_model = get_risk_model()
            ml_available = risk_model.is_trained
        except ImportError as e:
            logger.debug("ML risk scorer unavailable: %s", type(e).__name__)

        # ── Reachability analysis ──
        # [V5] Populate the "reachable" field on each finding using real
        # call-graph + data-flow analysis rather than assuming True.
        reachability_stats = {"analyzed": 0, "reachable": 0, "unreachable": 0, "skipped": 0}
        repo_path_str = (inp.metadata or {}).get("repo_path", "")
        if repo_path_str and ctx.get("findings"):
            try:
                from pathlib import Path as _Path

                from risk.reachability.call_graph import CallGraphBuilder
                _repo = _Path(repo_path_str)
                if _repo.is_dir():
                    _cg_builder = CallGraphBuilder()
                    _call_graph = _cg_builder.build_call_graph(_repo)
                    for _f in ctx.get("findings", []):
                        if "reachable" in _f:
                            reachability_stats["skipped"] += 1
                            continue  # already set (e.g. by external scanner)
                        func_name = _f.get("function", _f.get("symbol", ""))
                        if not func_name:
                            reachability_stats["skipped"] += 1
                            continue
                        _reached_result = CallGraphBuilder.is_reachable_from_entry(_call_graph, func_name)
                        _reached = _reached_result[0] if isinstance(_reached_result, tuple) else _reached_result
                        _f["reachable"] = _reached
                        reachability_stats["analyzed"] += 1
                        if _reached:
                            reachability_stats["reachable"] += 1
                        else:
                            reachability_stats["unreachable"] += 1
                    logger.info("Reachability: %s", reachability_stats)
            except Exception as _reach_err:  # noqa: BLE001 - reachability is optional; ImportError, OSError, or library errors must never halt the pipeline
                logger.warning("Reachability analysis skipped: %s", _reach_err)

        scores = []
        predictions_meta = []
        # Pre-build asset lookup to avoid O(n²) scan (P1 performance fix)
        asset_lookup: Dict[str, Dict[str, Any]] = {
            a.get("id", ""): a for a in ctx.get("assets", []) if a.get("id")
        }
        findings_list = ctx.get("findings", [])

        # Build per-finding context (asset criticality / exposure) once so
        # both the ML batch path and the fallback path can reuse it without
        # re-resolving the asset lookup.
        finding_ctxs: List[Dict[str, Any]] = []
        for f in findings_list:
            asset_info = asset_lookup.get(f.get("canonical_asset_id", ""), {})
            finding_ctxs.append({
                "asset_criticality": asset_info.get("criticality", 0.5),
                "network_exposure": asset_info.get(
                    "exposure", asset_info.get("network_exposure", "unknown")
                ),
            })

        # Batch ML predictions: one sklearn predict() over an (N, F) matrix
        # instead of N individual calls (perf fix #2 — risk_scorer.py:507).
        ml_preds: List[Any] = []
        ml_vuln_data: List[Dict[str, Any]] = []
        if ml_available and risk_model is not None and findings_list:
            for f, fctx in zip(findings_list, finding_ctxs):
                ml_vuln_data.append({
                    "cvss_score": f.get("cvss_score", 5.0),
                    "epss_score": f.get("epss_score", 0.1),
                    "in_kev": f.get("in_kev", False),
                    "asset_criticality": fctx["asset_criticality"],
                    "network_exposure": fctx["network_exposure"],
                    "exploit_available": f.get("exploit_available", False),
                    "exploit_maturity": f.get("exploit_maturity", "none"),
                    "reachable": f.get("reachable", True),
                    "chain_cves": f.get("chain_cves"),
                })
            try:
                ml_preds = risk_model.predict_batch(ml_vuln_data)
            except (OSError, ValueError, KeyError, RuntimeError) as batch_err:
                logger.warning(
                    "Batched risk prediction failed (%s); falling back to per-finding",
                    type(batch_err).__name__,
                )
                ml_preds = []

        for idx, f in enumerate(findings_list):
            fctx = finding_ctxs[idx]
            asset_criticality = fctx["asset_criticality"]
            fctx["network_exposure"]

            if ml_available and risk_model is not None and idx < len(ml_preds):
                vuln_data = ml_vuln_data[idx]
                pred = ml_preds[idx]
                risk = round(pred.risk_score / 100.0, 4)  # Normalize to 0-1
                f["risk_score"] = risk
                f["risk_priority"] = pred.priority
                f["risk_confidence_interval"] = [
                    round(pred.confidence_interval[0] / 100.0, 4),
                    round(pred.confidence_interval[1] / 100.0, 4),
                ]
                f["risk_model_version"] = pred.model_version
                # [V3] SHAP-like feature explanations — explain WHY this score
                f["risk_feature_contributions"] = pred.feature_contributions
                try:
                    explanation = risk_model.explain_prediction(vuln_data)
                    f["risk_explanation"] = {
                        "top_drivers": explanation.top_drivers[:3],
                        "narrative": explanation.risk_narrative,
                        "base_value": round(explanation.base_value / 100.0, 4),
                    }
                except (OSError, ValueError, KeyError, RuntimeError) as expl_err:  # narrowed from bare Exception
                    logger.debug("SHAP explanation failed: %s", type(expl_err).__name__)
                predictions_meta.append({
                    "model": pred.model_version,
                    "ci_width": pred.confidence_width,
                })
            else:
                # Fallback: deterministic weighted formula
                cvss = f.get("cvss_score", 5.0)
                epss = f.get("epss_score", 0.1)
                kev_boost = 1.5 if f.get("in_kev") else 1.0
                # [V5] Unreachable findings get 40% risk reduction
                reach_mult = 1.0 if f.get("reachable", True) else 0.6
                risk = round(
                    min(
                        (cvss / 10 * 0.4 + epss * 0.3 + 0.3)
                        * kev_boost
                        * asset_criticality
                        * reach_mult,
                        1.0,
                    ),
                    4,
                )
                f["risk_score"] = risk
                f["risk_model_version"] = "deterministic-1.0"

            scores.append(risk)

        avg = round(sum(scores) / len(scores), 4) if scores else 0.0
        critical_count = sum(1 for s in scores if s >= 0.75)
        ctx["risk_scores"] = {"avg": avg, "critical": critical_count, "scores": scores}

        result = {
            "avg_risk_score": avg,
            "critical_count": critical_count,
            "scored": len(scores),
            "model": f"ml-gbt-v{ML_MODEL_VERSION}" if ml_available else "deterministic-v1.0",
        }
        if reachability_stats["analyzed"]:
            result["reachability"] = reachability_stats
        if predictions_meta:
            avg_ci = sum(p["ci_width"] for p in predictions_meta) / len(predictions_meta)
            result["avg_confidence_width"] = round(avg_ci, 2)

        # ------------------------------------------------------------------
        # SBOM-to-Runtime Correlation (ALdeci differentiator)
        # If SBOM data is provided in pipeline metadata, correlate components
        # against runtime findings and apply risk adjustments.
        # ------------------------------------------------------------------
        sbom_data = inp.metadata.get("sbom") if inp.metadata else None
        if sbom_data and isinstance(sbom_data, dict):
            try:
                from core.sbom_runtime_correlator import SBOMRuntimeCorrelator

                correlator = SBOMRuntimeCorrelator()
                correlation = correlator.correlate(
                    sbom=sbom_data,
                    findings=ctx.get("findings", []),
                    org_id=inp.org_id or "",
                )
                # Apply risk adjustments to findings in-place
                findings = ctx.get("findings", [])
                adjustments_applied = 0
                for finding in findings:
                    fid = finding.get("id", finding.get("finding_id", ""))
                    delta = correlation.risk_adjustments.get(fid)
                    if delta is not None:
                        old_score = finding.get("risk_score", 0.5)
                        finding["risk_score"] = round(
                            min(max(old_score + delta, 0.0), 1.0), 4
                        )
                        finding["sbom_correlated"] = True
                        finding["sbom_risk_delta"] = round(delta, 4)
                        adjustments_applied += 1

                # Store correlation result in context for downstream steps
                ctx["sbom_correlation"] = correlation.to_dict()

                # Recalculate aggregate scores after SBOM adjustments
                adj_scores = [f.get("risk_score", 0.5) for f in findings]
                if adj_scores:
                    result["avg_risk_score"] = round(sum(adj_scores) / len(adj_scores), 4)
                    result["critical_count"] = sum(1 for s in adj_scores if s >= 0.75)
                    ctx["risk_scores"]["avg"] = result["avg_risk_score"]
                    ctx["risk_scores"]["critical"] = result["critical_count"]

                result["sbom_correlation"] = {
                    "components_in_sbom": correlation.stats.get("components_in_sbom", 0),
                    "matched": correlation.stats.get("matched_components", 0),
                    "sbom_only": correlation.stats.get("sbom_only_components", 0),
                    "shadow_dependencies": correlation.stats.get("shadow_count", 0),
                    "shadow_alert": correlation.shadow_dependency_alert,
                    "adjustments_applied": adjustments_applied,
                }
                logger.info(
                    "SBOM correlation applied: org=%s matched=%d shadows=%d adj=%d",
                    inp.org_id or "?",
                    correlation.stats.get("matched_components", 0),
                    correlation.stats.get("shadow_count", 0),
                    adjustments_applied,
                )
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as sbom_exc:
                # SBOM correlation is additive — never fail the pipeline
                logger.warning(
                    "SBOM correlation failed (non-fatal): %s", type(sbom_exc).__name__
                )
                result["sbom_correlation"] = {"error": type(sbom_exc).__name__}

        # Wave 3B — Attack graph GNN (after risk scoring + SBOM correlation)
        self._run_attack_graph_gnn(ctx)
        if ctx.get("attack_paths") is not None:
            result["attack_paths_count"] = len(ctx["attack_paths"])
            result["graph_nodes"] = ctx.get("graph_nodes", 0)
            result["graph_edges"] = ctx.get("graph_edges", 0)

        return result

    # ------------------------------------------------------------------
    # Step 8: Policy decides what must happen
    # ------------------------------------------------------------------

    # OPA engine singleton — lazily initialised once per process.
    # None = untried; False = unavailable; OPAEngine instance = ready.
    _opa_engine: Any = None
    _opa_available: Optional[bool] = None

    def _get_opa_engine(self) -> Any:
        """Return a live OPA engine, or None if unavailable.

        Resolution order (first that works wins):
        1. FIXOPS_OPA_URL env var → HTTP OPA client (air-gap + cloud compatible)
        2. real_opa_engine.OPAEngineFactory (enterprise install)
        3. None — falls back to expression evaluator in ``_opa_policy_decisions``

        Cached on the class so all BrainPipeline instances share one instance.
        Import / connection errors are caught and logged at DEBUG level so they
        never surface as pipeline failures.
        """
        if BrainPipeline._opa_available is not None:
            return BrainPipeline._opa_engine if BrainPipeline._opa_available else None

        # --- Path 1: FIXOPS_OPA_URL → lightweight HTTP OPA client -----------
        opa_url = os.environ.get("FIXOPS_OPA_URL", "").strip()
        if opa_url:
            try:
                engine = _HttpOPAEngine(base_url=opa_url)
                BrainPipeline._opa_engine = engine
                BrainPipeline._opa_available = True
                logger.info("OPA engine (HTTP) initialised at %s", opa_url)
                return engine
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                logger.debug("HTTP OPA engine init failed: %s", exc)
                # fall through to enterprise path

        # --- Path 2: Enterprise real_opa_engine import -----------------------
        try:
            from core.services.enterprise.real_opa_engine import (
                OPAEngineFactory,  # type: ignore[import]
            )

            engine = OPAEngineFactory.create()
            BrainPipeline._opa_engine = engine
            BrainPipeline._opa_available = True
            logger.info("OPA engine initialised for Step 8: %s", type(engine).__name__)
            return engine
        except ImportError as exc:
            BrainPipeline._opa_available = False
            BrainPipeline._opa_engine = None
            logger.debug("OPA engine unavailable, using expression evaluator: %s", exc)
            return None

    @staticmethod
    def _run_async_in_thread(coro: Any) -> Any:
        """Run an async coroutine from a synchronous context via a worker thread."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=5)

    # Canonical field aliases for policy expressions — maps human-readable
    # names to the actual keys stored in finding dicts.
    _POLICY_FIELD_ALIASES: Dict[str, str] = {
        # Risk / scoring fields
        "risk_score": "risk_score",
        "risk": "risk_score",
        "cvss_score": "cvss_score",
        "cvss": "cvss_score",
        "epss_score": "epss_score",
        "epss": "epss_score",
        # Severity
        "severity": "severity",
        # Threat-intel booleans
        "in_kev": "in_kev",
        "kev": "in_kev",
        "fix_available": "fix_available",
        "has_fix": "fix_available",
        "autofix_available": "fix_available",
        # Asset
        "asset_criticality": "asset_criticality",
        "criticality": "asset_criticality",
    }

    @staticmethod
    def _evaluate_condition(condition: str, finding: Dict[str, Any]) -> bool:
        """Evaluate a policy condition expression against a finding dict.

        Supports:
        - Numeric comparisons:  ``risk_score >= 0.85``, ``cvss_score > 7``
        - Boolean equality:     ``in_kev == true``, ``fix_available == false``
        - String equality:      ``severity == CRITICAL``
        - Inequality:           ``severity != low``
        - Membership:           ``severity in [critical, high]``
        - Non-membership:       ``severity not in [low, info]``
        - Compound:             ``risk_score >= 0.6 and in_kev == true``
        - OR:                   ``risk_score >= 0.9 or severity == CRITICAL``

        AND is evaluated before OR (standard precedence).
        Parentheses are not supported.
        Unrecognised clauses return False (conservative default).

        Supported fields: risk_score, cvss_score, epss_score, severity,
        in_kev, fix_available, asset_criticality (plus common aliases).
        """
        import operator as op_module
        import re as _re

        # Operator table for numeric/equality comparisons
        _OPS = {
            ">=": op_module.ge,
            "<=": op_module.le,
            ">": op_module.gt,
            "<": op_module.lt,
            "==": op_module.eq,
            "!=": op_module.ne,
        }

        # Field alias resolution (instance-independent)
        _ALIASES = BrainPipeline._POLICY_FIELD_ALIASES

        def _resolve_field(name: str) -> Any:
            """Resolve a field name (with aliases) from the finding."""
            canonical = _ALIASES.get(name, name)
            return finding.get(canonical)

        def _eval_single_clause(clause: str) -> bool:
            clause = clause.strip()
            if not clause:
                return False

            # --- membership: ``severity in [critical, high]`` ----------------
            m_in = _re.match(
                r"^(\w+)\s+in\s+\[([^\]]*)\]$", clause, flags=_re.IGNORECASE
            )
            if m_in:
                field_name = m_in.group(1).strip()
                values = [v.strip().strip("\"'") for v in m_in.group(2).split(",")]
                finding_val = _resolve_field(field_name)
                if finding_val is None:
                    return False
                return str(finding_val).lower() in [v.lower() for v in values]

            # --- non-membership: ``severity not in [low, info]`` ---------------
            m_not_in = _re.match(
                r"^(\w+)\s+not\s+in\s+\[([^\]]*)\]$", clause, flags=_re.IGNORECASE
            )
            if m_not_in:
                field_name = m_not_in.group(1).strip()
                values = [v.strip().strip("\"'") for v in m_not_in.group(2).split(",")]
                finding_val = _resolve_field(field_name)
                if finding_val is None:
                    return True  # not in the list if missing
                return str(finding_val).lower() not in [v.lower() for v in values]

            # --- comparison operators: >=, <=, >, <, ==, != -------------------
            for sym, func in _OPS.items():
                m = _re.match(rf"^(\w+)\s*{_re.escape(sym)}\s*(.+)$", clause)
                if m:
                    field_name = m.group(1).strip()
                    raw_val = m.group(2).strip()
                    finding_val = _resolve_field(field_name)
                    # Parse RHS value
                    if raw_val.lower() in ("true", "false"):
                        rhs: Any = raw_val.lower() == "true"
                    else:
                        try:
                            rhs = float(raw_val)
                        except ValueError:
                            rhs = raw_val.strip("\"'")
                    # Coerce LHS for numeric comparisons
                    if isinstance(rhs, float) and finding_val is not None:
                        try:
                            finding_val = float(finding_val)
                        except (TypeError, ValueError):
                            finding_val = 0.0
                    # String comparisons are case-insensitive
                    if isinstance(rhs, str) and isinstance(finding_val, str):
                        finding_val = finding_val.lower()
                        rhs = rhs.lower()
                    try:
                        return bool(func(finding_val, rhs))
                    except TypeError:
                        return False

            logger.debug("Policy clause not parsed: %r", clause)
            return False  # No operator matched

        # OR splits (lowest precedence); AND within each OR clause
        for or_part in _re.split(r"\s+or\s+", condition, flags=_re.IGNORECASE):
            and_parts = _re.split(r"\s+and\s+", or_part, flags=_re.IGNORECASE)
            if all(_eval_single_clause(c) for c in and_parts):
                return True
        return False

    def _opa_policy_decisions(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Run findings through the OPA vulnerability policy in batch.

        Returns ``{finding_id: decision}`` where decision is 'allow', 'block',
        or 'defer'.  Returns an empty dict on any failure so the caller always
        continues with the expression evaluator.
        """
        engine = self._get_opa_engine()
        if engine is None:
            return {}
        try:
            vuln_list = [
                {
                    "cve_id": f.get("cve_id", f.get("id", "")),
                    "severity": str(f.get("severity", "LOW")).upper(),
                    "fix_available": bool(
                        f.get("fix_available")
                        or f.get("has_fix")
                        or f.get("autofix_available")
                    ),
                }
                for f in findings
            ]
            coro = engine.evaluate_policy("vulnerability", {"vulnerabilities": vuln_list})
            opa_result = self._run_async_in_thread(coro)
            decision = opa_result.get("decision", "allow")
            # OPA returns a single batch verdict; broadcast to all findings
            return {f.get("id", ""): decision for f in findings}
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.warning("OPA batch evaluation failed, continuing without OPA: %s", exc)
            return {}

    def _step_apply_policy(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Evaluate policy rules and determine required actions.

        Evaluation order (highest priority first):
        1. Policy rules (built-in defaults or caller-supplied) evaluated via a
           proper expression parser — handles numeric comparisons, boolean
           equality, string equality, and AND/OR logic.
        2. OPA engine (if available) acts as a secondary gate: if OPA says
           'block' and the expression evaluator only said 'allow', OPA wins.
        3. Default fallback: 'allow'.
        """
        decisions = []
        rules = inp.policy_rules or [
            {
                "name": "critical_block",
                "condition": "risk_score >= 0.85",
                "action": "block",
            },
            {
                "name": "high_review",
                "condition": "risk_score >= 0.6",
                "action": "review",
            },
            {
                "name": "kev_escalate",
                "condition": "in_kev == true",
                "action": "escalate",
            },
        ]

        # Attempt OPA batch evaluation (best-effort — never blocks on failure)
        opa_decisions = self._opa_policy_decisions(ctx["findings"])
        opa_used = bool(opa_decisions)

        for f in ctx["findings"]:
            finding_id = f.get("id", "")
            action = "allow"
            triggered_rule = None

            # Evaluate policy rules via expression parser
            for rule in rules:
                cond = rule.get("condition", "")
                if not cond:
                    continue
                try:
                    if self._evaluate_condition(cond, f):
                        action = rule["action"]
                        triggered_rule = rule["name"]
                        break
                except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                    logger.debug(
                        "Policy condition error rule=%s: %s", rule.get("name"), exc
                    )

            # OPA veto: if OPA says 'block' and rules only said 'allow',
            # honour OPA as the stricter authority.
            opa_verdict = opa_decisions.get(finding_id, "allow")
            if opa_verdict == "block" and action == "allow":
                action = "block"
                triggered_rule = "opa_vulnerability_policy"

            decisions.append(
                {
                    "finding_id": finding_id,
                    "action": action,
                    "rule": triggered_rule,
                    "opa_verdict": opa_verdict if opa_used else None,
                }
            )
            f["policy_action"] = action

        ctx["policy_decisions"] = decisions
        action_counts: Dict[str, int] = {}
        for d in decisions:
            action_counts[d["action"]] = action_counts.get(d["action"], 0) + 1
        return {
            "decisions": len(decisions),
            "action_breakdown": action_counts,
            "opa_engine_used": opa_used,
        }

    # ------------------------------------------------------------------
    # Step 9: Multi-LLM consensus
    # ------------------------------------------------------------------
    # Batch size for LLM consensus calls
    LLM_BATCH_SIZE = 25
    MAX_LLM_FINDINGS = 100

    def _step_llm_consensus(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Get multi-LLM consensus on critical findings.

        [V3] Decision Intelligence — Real multi-provider LLM consensus.

        Architecture:
        1. Groups findings by severity for coherent prompts
        2. Sends to 3+ LLM providers (OpenAI, Anthropic, Gemini, vLLM/Ollama)
        3. Aggregates responses with configurable 85% consensus threshold
        4. Falls back to deterministic when all LLMs unavailable (air-gapped)
        5. Records decision outcomes for self-learning Loop 1

        Supports air-gapped mode: If FIXOPS_VLLM_URL or FIXOPS_OLLAMA_URL
        is configured, uses self-hosted models with zero external API calls.
        """
        critical = [f for f in ctx["findings"] if f.get("risk_score", 0) >= 0.6]
        if not critical:
            return {"analyzed": 0, "reason": "no critical findings"}

        # Sort by risk (highest first) and cap
        critical = sorted(
            critical, key=lambda f: f.get("risk_score", 0), reverse=True
        )[: self.MAX_LLM_FINDINGS]
        was_capped = len(critical) == self.MAX_LLM_FINDINGS

        try:
            import concurrent.futures

            from core.llm_providers import LLMProviderManager

            manager = LLMProviderManager()

            # Group findings into severity batches
            severity_buckets: Dict[str, List[Dict[str, Any]]] = {
                "critical": [],
                "high": [],
                "medium": [],
            }
            for f in critical:
                sev = str(f.get("severity", "medium")).lower()
                bucket = severity_buckets.get(sev, severity_buckets["medium"])
                bucket.append(f)

            severity_overview = {
                sev: len(findings) for sev, findings in severity_buckets.items()
            }

            # Build analysis prompt with findings context
            prompt = (
                f"Analyze {len(critical)} security findings for risk decision.\n"
                f"Severity distribution: {severity_overview}\n"
                f"Average risk score: {sum(f.get('risk_score', 0) for f in critical) / len(critical):.2f}\n"
                f"Top findings:\n"
            )
            for f in critical[:10]:
                prompt += (
                    f"- {f.get('title', 'Unknown')}: severity={f.get('severity', 'medium')}, "
                    f"risk={f.get('risk_score', 0):.2f}, cve={f.get('cve_id', 'N/A')}\n"
                )
            prompt += (
                "\nDecide: should this release be BLOCKED, require REVIEW, or ALLOWED? "
                "Consider exploitability, blast radius, and remediation complexity."
            )

            # Determine which providers to use (prefer air-gapped if configured)
            provider_order = []
            if os.environ.get("FIXOPS_VLLM_URL") or os.environ.get("FIXOPS_OLLAMA_URL"):
                # Air-gapped mode: use self-hosted first
                provider_order = ["vllm", "ollama"]
            # Always try cloud providers as fallback (will no-op if no API keys)
            provider_order.extend(["anthropic", "openai", "gemini"])

            # Collect responses from multiple providers
            responses = []
            consensus_threshold = float(os.environ.get("FIXOPS_CONSENSUS_THRESHOLD", "0.85"))

            mitigation_hints = {
                "mitre_candidates": list({
                    t for f in critical[:20]
                    for t in f.get("mitre_techniques", [])
                }),
                "compliance": list({
                    c for f in critical[:20]
                    for c in f.get("compliance_concerns", [])
                }),
            }

            def _query_provider(provider_name: str):
                return manager.analyse(
                    provider_name,
                    prompt=prompt,
                    context={"severity_overview": severity_overview, "finding_count": len(critical)},
                    default_action="review",
                    default_confidence=0.5,
                    default_reasoning="Deterministic fallback — LLM unavailable",
                    mitigation_hints=mitigation_hints,
                )

            # Query providers with timeout
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(provider_order)) as pool:
                future_map = {
                    pool.submit(_query_provider, p): p for p in provider_order
                }
                for future in concurrent.futures.as_completed(future_map, timeout=self.STEP_TIMEOUT_S):
                    provider_name = future_map[future]
                    try:
                        resp = future.result(timeout=5)
                        responses.append({
                            "provider": provider_name,
                            "action": resp.recommended_action,
                            "confidence": resp.confidence,
                            "reasoning": resp.reasoning,
                            "mode": resp.metadata.get("mode", "unknown"),
                            "mitre": list(resp.mitre_techniques),
                            "compliance": list(resp.compliance_concerns),
                        })
                    except (TimeoutError, concurrent.futures.TimeoutError):
                        logger.warning("LLM provider %s timed out", provider_name)
                    except (OSError, ValueError, RuntimeError) as e:
                        logger.warning("LLM provider %s failed: %s", provider_name, type(e).__name__)

            # Compute consensus from responses
            if not responses:
                return self._deterministic_consensus(critical, ctx)

            # Count votes by action
            action_votes: Dict[str, float] = {}
            for resp in responses:
                action = resp["action"].lower()
                weight = resp["confidence"]
                action_votes[action] = action_votes.get(action, 0) + weight

            total_weight = sum(action_votes.values())
            best_action = max(action_votes, key=action_votes.get)
            best_weight = action_votes[best_action]
            consensus_pct = best_weight / total_weight if total_weight > 0 else 0

            # Determine final decision
            if consensus_pct >= consensus_threshold:
                final_decision = best_action
                method = "multi_llm_consensus"
            else:
                # No consensus — use most conservative action
                if "block" in action_votes:
                    final_decision = "block"
                elif "review" in action_votes:
                    final_decision = "review"
                else:
                    final_decision = "allow"
                method = "multi_llm_no_consensus"

            # Aggregate MITRE and compliance from all providers
            all_mitre = list({t for r in responses for t in r.get("mitre", [])})
            all_compliance = list({c for r in responses for c in r.get("compliance", [])})

            result = {
                "final_decision": final_decision,
                "method": method,
                "consensus_pct": round(consensus_pct, 4),
                "threshold": consensus_threshold,
                "providers_queried": len(provider_order),
                "providers_responded": len(responses),
                "provider_details": responses,
                "mitre_techniques": all_mitre[:20],
                "compliance_concerns": all_compliance[:10],
                "air_gapped": any(r.get("mode") == "self-hosted" for r in responses),
            }

            ctx["llm_results"] = [result]
            return {
                "analyzed": len(critical),
                "decision": final_decision,
                "method": method,
                "consensus_pct": round(consensus_pct, 4),
                "capped": was_capped,
                "providers_responded": len(responses),
                "air_gapped": result["air_gapped"],
            }
        except (TimeoutError, concurrent.futures.TimeoutError):
            logger.warning("LLM consensus timed out — using deterministic fallback")
            return self._deterministic_consensus(critical, ctx)
        except (OSError, ValueError, KeyError, RuntimeError) as e:
            logger.warning("LLM consensus skipped: %s", type(e).__name__)
            return self._deterministic_consensus(critical, ctx)

    def _deterministic_consensus(
        self, critical: List[Dict[str, Any]], ctx: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fallback consensus when LLM is unavailable.

        Uses risk score distribution to determine overall decision.
        """
        if not critical:
            return {"analyzed": 0, "skipped": True, "reason": "no findings"}

        avg_risk = sum(f.get("risk_score", 0) for f in critical) / len(critical)
        high_pct = sum(1 for f in critical if f.get("risk_score", 0) >= 0.75) / len(
            critical
        )

        if high_pct > 0.5:
            decision = "block"
        elif avg_risk >= 0.7:
            decision = "review"
        else:
            decision = "allow"

        result = {
            "final_decision": decision,
            "method": "deterministic",
            "avg_risk": round(avg_risk, 4),
            "high_risk_pct": round(high_pct, 4),
        }
        ctx["llm_results"] = [result]
        return {
            "analyzed": len(critical),
            "decision": decision,
            "skipped": True,
            "reason": "deterministic fallback",
        }

    # ------------------------------------------------------------------
    # Step 9B: LLM Council (3-stage Karpathy pattern)
    # Replaces legacy consensus when FIXOPS_USE_COUNCIL=1
    # ------------------------------------------------------------------

    # Singleton council adapter — reuse across pipeline runs for session history
    _council_adapter = None
    _council_adapter_lock = __import__('threading').Lock()

    @classmethod
    def _get_council_adapter(cls):
        """Get or create the singleton CouncilPipelineAdapter."""
        if cls._council_adapter is None:
            with cls._council_adapter_lock:
                if cls._council_adapter is None:
                    from core.council_pipeline_adapter import (
                        create_consensus_engine_replacement,
                    )
                    cls._council_adapter = create_consensus_engine_replacement()
                    logger.info("CouncilPipelineAdapter singleton initialized")
        return cls._council_adapter

    def _step_llm_council(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Get LLM Council verdict on critical findings.

        [V4] Council Architecture — Karpathy 3-stage pattern via CouncilPipelineAdapter:
        Stage 1: Independent Analysis (each member analyzes without seeing others)
        Stage 2: Anonymous Peer Review (members can update position based on peers)
        Stage 3: Chairman Synthesis (strongest model synthesizes into final verdict)
        Optional: Escalate to Opus CTO if confidence < 0.7 or disagreement > 2 members

        Integrated features (via CouncilPipelineAdapter):
        - Decision memory: learns from past decisions and analyst overrides
        - Analyst feedback loop: continuous improvement from SOC team
        - Opus CTO escalation: cost-guarded (max 10/hour) for high-uncertainty cases
        - Session history: full audit trail for compliance

        Composition: Qwen, DeepSeek, Gemma, Llama (via OpenRouter/Ollama/vLLM)
        """
        critical = [f for f in ctx["findings"] if f.get("risk_score", 0) >= 0.6]
        if not critical:
            return {"analyzed": 0, "reason": "no critical findings"}

        try:
            adapter = self._get_council_adapter()

            # Build analysis prompt for context
            critical_sorted = sorted(
                critical, key=lambda f: f.get("risk_score", 0), reverse=True
            )[: self.MAX_LLM_FINDINGS]

            prompt = (
                f"Analyze {len(critical_sorted)} security findings for risk decision.\n"
                f"Service: {inp.org_id or 'unknown'}\n"
            )
            for f in critical_sorted[:10]:
                prompt += (
                    f"- {f.get('title', 'Unknown')}: severity={f.get('severity', 'medium')}, "
                    f"risk={f.get('risk_score', 0):.2f}, cve={f.get('cve_id', 'N/A')}\n"
                )

            # Use council adapter (handles 3-stage convene, escalation, memory)
            result = adapter.analyse(
                prompt=prompt,
                context={
                    "service_name": inp.org_id or "unknown_service",
                    "org_id": inp.org_id or "default",
                    "findings": critical_sorted,
                },
                findings=critical_sorted,
            )

            # Store verdict in context for downstream steps
            ctx["council_verdict"] = result
            ctx["council_stats"] = adapter.get_council_stats()

            return result

        except (ImportError, TimeoutError) as e:
            logger.warning(
                "LLM Council unavailable (%s), falling back to consensus: %s",
                type(e).__name__,
                e,
            )
            return self._step_llm_consensus(ctx, inp)
        except (OSError, ValueError, KeyError, RuntimeError, TypeError) as e:
            logger.warning("LLM Council failed: %s", type(e).__name__)
            return self._step_llm_consensus(ctx, inp)

    # ------------------------------------------------------------------
    # Step 10: MicroPenTest proves reality
    # ------------------------------------------------------------------
    def _step_micro_pentest(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Run MPTE validation on high-risk findings."""
        import asyncio

        high_risk = [
            f
            for f in ctx["findings"]
            if f.get("risk_score", 0) >= 0.75
            and f.get("cve_id")
            and f.get("reachable", True)  # [V5] skip unreachable findings
        ]
        if not high_risk:
            return {"tested": 0, "reason": "no high-risk CVEs to test"}

        cve_ids = list(set(f.get("cve_id") for f in high_risk if f.get("cve_id")))[:10]
        target_urls = list(
            set(
                a.get("url", a.get("endpoint", ""))
                for a in ctx["assets"]
                if a.get("url") or a.get("endpoint")
            )
        )[:5]
        if not target_urls:
            target_urls = ["https://localhost:8443"]

        try:
            from core.micro_pentest import run_micro_pentest

            # Safe async loop handling: reuse running loop or create new one
            try:
                loop = asyncio.get_running_loop()
                # We're in an async context — can't run_until_complete.
                # Use a thread-safe approach.
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    def _run_pentest():
                        _loop = asyncio.new_event_loop()
                        try:
                            return _loop.run_until_complete(
                                run_micro_pentest(cve_ids, target_urls)
                            )
                        finally:
                            _loop.close()
                    future = pool.submit(_run_pentest)
                    pentest_result = future.result(timeout=120)
            except RuntimeError:
                # No running loop — safe to create one
                loop = asyncio.new_event_loop()
                try:
                    pentest_result = loop.run_until_complete(
                        run_micro_pentest(cve_ids, target_urls)
                    )
                finally:
                    loop.close()

            ctx["pentest_results"] = [
                {
                    "cve_ids": cve_ids,
                    "status": pentest_result.status,
                    "flow_id": pentest_result.flow_id,
                }
            ]
            return {
                "tested_cves": len(cve_ids),
                "status": pentest_result.status,
                "flow_id": pentest_result.flow_id,
            }
        except TimeoutError:
            logger.warning("MicroPenTest timed out after 120s")
            return {"tested": 0, "skipped": True, "reason": "timeout"}
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("MicroPenTest skipped: %s", type(e).__name__)
            return {"tested": 0, "skipped": True, "reason": type(e).__name__}

    # ------------------------------------------------------------------
    # Step 11: Playbooks mobilize remediation
    # ------------------------------------------------------------------
    def _step_run_playbooks(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Execute remediation playbooks for actionable findings."""
        actionable = [
            f
            for f in ctx["findings"]
            if f.get("policy_action") in ("block", "review", "escalate")
        ]
        if not actionable:
            return {"executed": 0, "reason": "no actionable findings"}

        playbook_results = []

        # Hoist AutoFixEngine creation outside the loop to avoid
        # re-instantiation per finding (perf: O(1) init vs O(n) init)
        autofix_engine = None
        block_findings = [f for f in actionable if f.get("policy_action") == "block" and f.get("cve_id")]
        if block_findings:
            try:
                from core.autofix_engine import AutoFixEngine
                autofix_engine = AutoFixEngine()
            except ImportError:
                pass

        for f in actionable:
            action = f.get("policy_action", "review")
            pb = {
                "finding_id": f.get("id", ""),
                "cve_id": f.get("cve_id"),
                "action": action,
                "playbook": f"auto-{action}",
                "status": "dispatched",
                "assignee": None,
            }
            # Attempt autofix for block actions
            if action == "block" and f.get("cve_id"):
                if autofix_engine is not None:
                    try:
                        fix = autofix_engine.generate_fix(
                            vulnerability={
                                "cve_id": f["cve_id"],
                                "severity": f.get("severity", "high"),
                            },
                            code_context=f.get("code_context", {}),
                        )
                        pb["autofix"] = {"status": "generated", "fix_id": fix.get("fix_id")}
                    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
                        pb["autofix"] = {"status": "skipped"}
                else:
                    pb["autofix"] = {"status": "skipped", "reason": "engine_unavailable"}
            playbook_results.append(pb)

        ctx["playbook_results"] = playbook_results

        # ------------------------------------------------------------------
        # Real connector dispatch: Jira tickets + Slack notification + GitHub PRs
        #
        # Each connector is attempted independently.  A failure in any one
        # NEVER blocks the others or crashes the pipeline.  Missing config =
        # graceful skip.  Results are accumulated and returned in step output.
        # ------------------------------------------------------------------
        jira_dispatched = 0
        slack_dispatched = 0
        github_prs_created = 0
        connector_errors: List[str] = []

        # ---- 11a. Jira — create tickets for "block" and "escalate" actions --
        jira_url = os.environ.get("FIXOPS_JIRA_URL", "")
        jira_user = os.environ.get("FIXOPS_JIRA_USER", "")
        jira_token = os.environ.get("FIXOPS_JIRA_TOKEN", "")
        jira_project = os.environ.get("FIXOPS_JIRA_PROJECT", "")
        if jira_url and jira_user and jira_token and jira_project:
            try:
                from core.connectors import JiraConnector

                jira = JiraConnector(
                    {
                        "url": jira_url,
                        "user_email": jira_user,
                        "token": jira_token,
                        "project_key": jira_project,
                    }
                )
                for pb in playbook_results:
                    if pb.get("action") in ("block", "escalate"):
                        cve_id = pb.get("cve_id") or "unknown"
                        finding_id = pb.get("finding_id") or "unknown"
                        jira_action = {
                            "summary": (
                                f"[ALdeci] {pb['action'].upper()} — {cve_id}"
                                f" on {finding_id}"
                            ),
                            "description": (
                                f"ALdeci Brain Pipeline detected a '{pb['action']}'"
                                f" policy action.\n\n"
                                f"Finding ID: {finding_id}\n"
                                f"CVE: {cve_id}\n"
                                f"Org: {ctx.get('org_id', 'unknown')}\n"
                                f"Autofix: {pb.get('autofix', {}).get('status', 'n/a')}\n\n"
                                f"Run ID: {ctx.get('run_id', 'unknown')}"
                            ),
                            "priority": "High" if pb["action"] == "block" else "Medium",
                        }
                        outcome = jira.create_issue(jira_action)
                        if outcome.status == "sent":
                            jira_dispatched += 1
                            pb["jira_issue"] = outcome.details.get("issue_key")
                        elif outcome.status == "failed":
                            connector_errors.append(
                                "jira:{}:{}".format(
                                    finding_id,
                                    outcome.details.get("reason", "unknown"),
                                )
                            )
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                connector_errors.append(f"jira:{type(exc).__name__}")
                logger.debug("Jira dispatch error in Step 11: %s", type(exc).__name__)

        # ---- 11b. Slack — notify on "review" actions + overall summary ------
        slack_webhook = os.environ.get("FIXOPS_SLACK_WEBHOOK", "")
        if slack_webhook and playbook_results:
            try:
                from core.connectors import SlackConnector

                slack = SlackConnector({"webhook_url": slack_webhook})

                # Per-finding Slack messages for "review" actions
                for pb in playbook_results:
                    if pb.get("action") == "review":
                        cve_id = pb.get("cve_id") or "unknown"
                        finding_id = pb.get("finding_id") or "unknown"
                        review_action = {
                            "text": (
                                f":eyes: *ALdeci REVIEW Required* — Finding `{finding_id}`"
                                f" (CVE: `{cve_id}`) requires manual review.\n"
                                f"Org: `{ctx.get('org_id', 'unknown')}`  "
                                f"Jira: `{pb.get('jira_issue', 'pending')}`"
                            ),
                        }
                        outcome = slack.post_message(review_action)
                        if outcome.status == "sent":
                            slack_dispatched += 1
                        elif outcome.status == "failed":
                            connector_errors.append(
                                f"slack:review:{outcome.details.get('reason', 'unknown')}"
                            )

                # Overall pipeline summary message
                block_count = sum(
                    1 for p in playbook_results if p.get("action") == "block"
                )
                escalate_count = sum(
                    1 for p in playbook_results if p.get("action") == "escalate"
                )
                review_count = sum(
                    1 for p in playbook_results if p.get("action") == "review"
                )
                summary_action = {
                    "text": (
                        f":shield: *ALdeci Brain Pipeline* — Playbooks dispatched"
                        f" for org `{ctx.get('org_id', 'unknown')}`\n"
                        f"• Block: {block_count}  Escalate: {escalate_count}"
                        f"  Review: {review_count}  Total: {len(playbook_results)}\n"
                        f"• Jira tickets: {jira_dispatched}"
                        f"  GitHub PRs: {github_prs_created}"
                    ),
                }
                outcome = slack.post_message(summary_action)
                if outcome.status == "sent":
                    slack_dispatched += 1
                elif outcome.status == "failed":
                    connector_errors.append(
                        f"slack:summary:{outcome.details.get('reason', 'unknown')}"
                    )
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                connector_errors.append(f"slack:{type(exc).__name__}")
                logger.debug("Slack dispatch error in Step 11: %s", type(exc).__name__)

        # ---- 11c. GitHub PRs — create PRs for findings with autofix patches -
        gh_token = os.environ.get("FIXOPS_GITHUB_TOKEN", "")
        gh_owner = os.environ.get("FIXOPS_GITHUB_OWNER", "")
        gh_repo = os.environ.get("FIXOPS_GITHUB_REPO", "")
        gh_base_branch = os.environ.get("FIXOPS_GITHUB_BASE_BRANCH", "main")
        if gh_token and gh_owner and gh_repo:
            try:
                import json as _json
                import urllib.error
                import urllib.request

                gh_api_base = f"https://api.github.com/repos/{gh_owner}/{gh_repo}"
                gh_headers = {
                    "Authorization": f"Bearer {gh_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "Content-Type": "application/json",
                }

                def _gh_request(
                    method: str, url: str, body: Optional[Dict[str, Any]] = None
                ) -> Dict[str, Any]:
                    """Minimal GitHub REST call — no dependency on connector class."""
                    data = _json.dumps(body).encode() if body else None
                    req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                        url, data=data, headers=gh_headers, method=method
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310  # nosemgrep: dynamic-urllib-use-detected  # nosec
                            return _json.loads(resp.read()) if resp.length != 0 else {}
                    except urllib.error.HTTPError as exc:
                        error_body = exc.read().decode(errors="replace")
                        raise RuntimeError(
                            f"GitHub API {method} {url} -> {exc.code}: {error_body[:200]}"
                        ) from exc

                # Get HEAD SHA for base branch
                try:
                    ref_data = _gh_request(
                        "GET",
                        f"{gh_api_base}/git/ref/heads/{gh_base_branch}",
                    )
                    base_sha = (
                        ref_data.get("object", {}).get("sha", "")
                    )
                except (OSError, ValueError, KeyError, RuntimeError) as sha_exc:  # narrowed from bare Exception
                    logger.debug(
                        "GitHub: could not fetch base branch SHA: %s",
                        type(sha_exc).__name__,
                    )
                    base_sha = ""

                if base_sha:
                    for pb in playbook_results:
                        # Only create PRs for block actions with generated autofix patches
                        autofix = pb.get("autofix") or {}
                        if pb.get("action") != "block":
                            continue
                        if autofix.get("status") != "generated":
                            continue
                        patch_content = autofix.get("patch") or autofix.get("fix_content")
                        if not patch_content:
                            continue

                        cve_id = pb.get("cve_id") or "unknown"
                        finding_id = pb.get("finding_id") or "unknown"
                        fix_id = autofix.get("fix_id", uuid.uuid4().hex[:8])
                        branch_name = (
                            f"aldeci/autofix-{cve_id.replace('/', '-').lower()}"
                            f"-{fix_id[:8]}"
                        )
                        try:
                            # Create a new branch off base
                            _gh_request(
                                "POST",
                                f"{gh_api_base}/git/refs",
                                {
                                    "ref": f"refs/heads/{branch_name}",
                                    "sha": base_sha,
                                },
                            )

                            # Determine target file path from autofix metadata
                            file_path = (
                                autofix.get("file_path")
                                or autofix.get("target_file")
                                or f"aldeci-patches/{fix_id[:8]}.patch"
                            )
                            # Encode file content
                            import base64 as _b64

                            encoded_content = _b64.b64encode(
                                str(patch_content).encode()
                            ).decode()

                            # Get current file SHA if it already exists (for update)
                            current_file_sha: Optional[str] = None
                            try:
                                existing = _gh_request(
                                    "GET",
                                    f"{gh_api_base}/contents/{file_path}"
                                    f"?ref={branch_name}",
                                )
                                current_file_sha = existing.get("sha")
                            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                                pass  # File does not exist yet — create it

                            commit_body: Dict[str, Any] = {
                                "message": (
                                    f"fix(security): ALdeci autofix for {cve_id}\n\n"
                                    f"Finding: {finding_id}\n"
                                    f"Fix ID: {fix_id}\n"
                                    f"Generated by ALdeci Brain Pipeline"
                                ),
                                "content": encoded_content,
                                "branch": branch_name,
                            }
                            if current_file_sha:
                                commit_body["sha"] = current_file_sha

                            _gh_request(
                                "PUT",
                                f"{gh_api_base}/contents/{file_path}",
                                commit_body,
                            )

                            # Create PR
                            pr_data = _gh_request(
                                "POST",
                                f"{gh_api_base}/pulls",
                                {
                                    "title": (
                                        f"[ALdeci AutoFix] {cve_id} —"
                                        f" {finding_id}"
                                    ),
                                    "body": (
                                        f"## ALdeci AutoFix\n\n"
                                        f"**CVE**: {cve_id}  \n"
                                        f"**Finding ID**: {finding_id}  \n"
                                        f"**Fix ID**: {fix_id}  \n"
                                        f"**Org**: {ctx.get('org_id', 'unknown')}  \n\n"
                                        f"This PR was automatically generated by ALdeci"
                                        f" Brain Pipeline (Step 11 — Playbook Dispatch)."
                                        f"\n\nPlease review before merging."
                                    ),
                                    "head": branch_name,
                                    "base": gh_base_branch,
                                    "draft": True,
                                },
                            )
                            pr_url = pr_data.get("html_url", "")
                            pr_number = pr_data.get("number")
                            pb["github_pr"] = {
                                "url": pr_url,
                                "number": pr_number,
                                "branch": branch_name,
                                "status": "created",
                            }
                            github_prs_created += 1
                            logger.info(
                                "GitHub PR created for %s: %s", cve_id, pr_url
                            )
                        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as pr_exc:
                            pb["github_pr"] = {
                                "status": "failed",
                                "error": type(pr_exc).__name__,
                            }
                            connector_errors.append(
                                f"github_pr:{finding_id}:{type(pr_exc).__name__}"
                            )
                            logger.debug(
                                "GitHub PR creation failed for %s: %s",
                                finding_id,
                                type(pr_exc).__name__,
                            )

            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                connector_errors.append(f"github:{type(exc).__name__}")
                logger.debug(
                    "GitHub connector error in Step 11: %s", type(exc).__name__
                )

        result = {
            "executed": len(playbook_results),
            "actions": {
                a: sum(1 for p in playbook_results if p["action"] == a)
                for a in set(p["action"] for p in playbook_results)
            },
            "jira_tickets_created": jira_dispatched,
            "slack_notifications_sent": slack_dispatched,
            "github_prs_created": github_prs_created,
        }
        if connector_errors:
            result["connector_errors"] = connector_errors
        return result

    # ------------------------------------------------------------------
    # Step 12: SOC2 Type II evidence pack
    # ------------------------------------------------------------------
    def _step_generate_evidence(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Generate SOC2 evidence pack from the pipeline results and sign it cryptographically.

        [V10] CTEM + cryptographic evidence — produces a hybrid RSA-4096 + ML-DSA-65
        signed evidence bundle suitable for SOC2 Type II, FedRAMP, and compliance auditors.

        Signing is attempted via crypto.sign_evidence().  If keys are not configured or
        the cryptography dependency is absent (air-gap mode), the bundle is returned
        unsigned with ``signed: false`` — the pipeline NEVER fails due to missing keys.
        """
        now = datetime.now(timezone.utc)
        evidence = {
            "framework": inp.evidence_framework,
            "generated_at": now.isoformat(),
            "org_id": ctx["org_id"],
            "timeframe_days": inp.evidence_timeframe_days,
            "summary": {
                "total_findings": len(ctx["findings"]),
                "clusters": len(ctx.get("clusters", [])),
                "exposure_cases": len(ctx.get("exposure_cases", [])),
                "avg_risk_score": ctx.get("risk_scores", {}).get("avg", 0),
                "critical_findings": ctx.get("risk_scores", {}).get("critical", 0),
                "policy_decisions": len(ctx.get("policy_decisions", [])),
                "pentests_run": len(ctx.get("pentest_results", [])),
                "playbooks_executed": len(ctx.get("playbook_results", [])),
            },
            "controls": {
                "vulnerability_management": {
                    "status": "effective"
                    if ctx.get("risk_scores", {}).get("avg", 1) < 0.6
                    else "needs_improvement",
                    "findings_triaged": len(ctx["findings"]),
                    "mean_time_to_detect": "< 24h",
                },
                "change_management": {
                    "status": "effective",
                    "autofix_generated": sum(
                        1
                        for p in ctx.get("playbook_results", [])
                        if p.get("autofix", {}).get("status") == "generated"
                    ),
                },
                "logging_monitoring": {
                    "status": "effective",
                    "events_captured": len(ctx.get("policy_decisions", [])),
                    "graph_nodes": ctx.get("graph_stats", {}).get("total_nodes", 0),
                },
            },
        }

        # ------------------------------------------------------------------
        # Cryptographic signing — [V6+V10] Quantum-secure evidence integrity
        # Attempts hybrid RSA-4096 + ML-DSA-65 signing via HybridQuantumSigner.
        # Falls back to RSA-only via sign_evidence(), then unsigned if keys absent.
        # ------------------------------------------------------------------
        signed = False
        signature_algorithm = None
        key_fingerprint = None
        signing_error = None
        quantum_signed = False

        # Try hybrid quantum signing first (FIPS 204 ML-DSA + RSA)
        try:
            import json as _json

            from core.quantum_crypto import HybridQuantumSigner

            hybrid_signer = HybridQuantumSigner()
            evidence_bytes = _json.dumps(evidence, sort_keys=True, default=str).encode("utf-8")
            hybrid_sig = hybrid_signer.sign(evidence_bytes)

            evidence["quantum_signature"] = hybrid_sig.to_dict()
            evidence["signature_format"] = "hybrid-rsa-mldsa"
            signed = True
            quantum_signed = True
            signature_algorithm = f"hybrid-{hybrid_sig.classical_algorithm}+{hybrid_sig.quantum_algorithm}"
            key_fingerprint = hybrid_sig.classical_key_fingerprint
            logger.info(
                "Evidence bundle quantum-signed: algorithm=%s quantum_backend=%s",
                signature_algorithm,
                hybrid_signer._mldsa._backend if hybrid_signer._mldsa else "disabled",
            )
        except ImportError:
            signing_error = "quantum_crypto module not available"
            logger.debug("Quantum signing skipped: %s", signing_error)
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            signing_error = type(exc).__name__
            logger.debug("Quantum signing skipped: %s — %s", type(exc).__name__, exc)

        # Fall back to classical RSA-only signing if quantum failed
        if not signed:
            try:
                from core.crypto import sign_evidence

                signed_bundle = sign_evidence(evidence)
                evidence = signed_bundle
                sig_block = evidence.get("signature", {})
                signed = True
                signature_algorithm = sig_block.get("algorithm", "RSA-SHA256")
                key_fingerprint = sig_block.get("key_fingerprint")
                logger.info(
                    "Evidence bundle RSA-signed: algorithm=%s fingerprint=%s",
                    signature_algorithm,
                    key_fingerprint,
                )
            except ImportError:
                signing_error = "crypto module not available (air-gap mode)"
                logger.debug("Evidence signing skipped: %s", signing_error)
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                signing_error = type(exc).__name__
                logger.debug("Evidence signing skipped: %s — %s", type(exc).__name__, exc)

        # Store signed evidence bundle in context for downstream consumers
        ctx["evidence"] = evidence

        # Build step output (returned to StepResult.output and pipeline summary)
        step_output = dict(evidence)
        step_output["signed"] = signed
        step_output["quantum_signed"] = quantum_signed
        if signed:
            step_output["signature_algorithm"] = signature_algorithm
            step_output["key_fingerprint"] = key_fingerprint
        else:
            step_output["signing_skipped_reason"] = signing_error or "unknown"

        # Feed results to self-learning for Loop 4 (remediation tracking)
        try:
            from core.self_learning import SelfLearningEngine
            learning = SelfLearningEngine.get_instance()
            learning.record_pipeline_run(
                run_id=ctx.get("run_id", ""),
                findings_count=len(ctx["findings"]),
                decision=ctx.get("llm_results", [{}])[0].get("final_decision", "unknown") if ctx.get("llm_results") else "unknown",
                signed=signed,
                quantum_signed=quantum_signed,
            )
        except (ImportError, OSError, ValueError, RuntimeError, AttributeError):
            pass  # Self-learning not available

        return step_output

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------
    def _emit_event(self, result: PipelineResult) -> None:
        """Emit pipeline completion event to the event bus.

        Also runs anomaly detection and trend analysis on the pipeline
        findings to detect unusual patterns. [V3] Decision Intelligence.
        """
        # Run anomaly detection on pipeline findings
        anomaly_result = self._run_anomaly_check(result)

        # Feed results to trend analyzer for posture tracking [V3]
        self._feed_trend_analyzer(result)

        try:
            import asyncio

            from core.event_bus import Event, EventType, get_event_bus

            bus = get_event_bus()
            event_data = {
                "run_id": result.run_id,
                "status": result.status.value,
                "findings_ingested": result.findings_ingested,
                "duration_ms": result.total_duration_ms,
            }
            if anomaly_result:
                event_data["anomaly_detected"] = anomaly_result.get(
                    "is_anomalous", False
                )
                event_data["anomaly_score"] = anomaly_result.get(
                    "anomaly_score", 0.0
                )
                event_data["anomaly_reasons"] = anomaly_result.get(
                    "anomaly_reasons", []
                )

            event = Event(
                event_type=EventType.SCAN_COMPLETED,
                source="brain_pipeline",
                org_id=result.org_id,
                data=event_data,
            )

            # ── Pipeline → Issues bridge (onboarding bug fix 2026-04-27) ──
            # After mirror to SecurityFindingsEngine, emit two more events so
            # the Issues dashboard auto-populates without admin "Refresh
            # Finding Index" workaround:
            #   1. PIPELINE_COMPLETED — high-level signal for SSE/UI polling
            #   2. FINDINGS_INDEX_REFRESH — federation cache invalidation
            mirrored_count = getattr(
                result, "findings_mirrored_to_dashboard", 0
            )
            pipeline_event = Event(
                event_type=EventType.PIPELINE_COMPLETED,
                source="brain_pipeline",
                org_id=result.org_id,
                data={
                    **event_data,
                    "findings_mirrored_to_dashboard": mirrored_count,
                },
            )
            refresh_event = Event(
                event_type=EventType.FINDINGS_INDEX_REFRESH,
                source="brain_pipeline",
                org_id=result.org_id,
                data={
                    "run_id": result.run_id,
                    "findings_mirrored": mirrored_count,
                    "reason": "pipeline_completed",
                },
            )

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(bus.emit(event))
                loop.create_task(bus.emit(pipeline_event))
                loop.create_task(bus.emit(refresh_event))
            except RuntimeError:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(bus.emit(event))
                loop.run_until_complete(bus.emit(pipeline_event))
                loop.run_until_complete(bus.emit(refresh_event))
                loop.close()
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Event emission skipped: %s", type(e).__name__)

    def _run_anomaly_check(
        self, result: PipelineResult
    ) -> Optional[Dict[str, Any]]:
        """Run anomaly detection on pipeline findings.

        [V3] Decision Intelligence — Detects unusual scan patterns
        that may indicate compromised infrastructure, misconfigured
        scanners, or emerging threats.

        Returns None if anomaly detection is unavailable.
        """
        try:
            from core.ml.anomaly_detector import AnomalyDetector

            detector = AnomalyDetector()
            # Use heuristic detection (no baseline needed)
            findings = []
            for step in result.steps:
                if step.output and isinstance(step.output, dict):
                    step_findings = step.output.get("findings", [])
                    if isinstance(step_findings, list):
                        findings.extend(step_findings)

            if not findings:
                return None

            anomaly = detector.detect(findings)
            if anomaly.is_anomalous:
                logger.warning(
                    "ANOMALY DETECTED in run %s: score=%.4f, reasons=%s",
                    result.run_id,
                    anomaly.anomaly_score,
                    anomaly.anomaly_reasons[:3],
                )
            return anomaly.to_dict()
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Anomaly detection skipped: %s", type(e).__name__)
            return None

    def _feed_trend_analyzer(self, result: PipelineResult) -> None:
        """Feed pipeline results to the trend analyzer for posture tracking.

        [V3] Decision Intelligence — Builds historical scan data for
        trend detection (severity drift, CWE emergence, recurrence).
        Non-blocking: failures are logged but never crash the pipeline.
        """
        try:
            from core.ml.trend_analyzer import get_trend_analyzer

            # Build scan record from pipeline result
            findings_for_trend = []
            for step in result.steps:
                if step.output and isinstance(step.output, dict):
                    step_findings = step.output.get("findings", [])
                    if isinstance(step_findings, list):
                        for f in step_findings:
                            if isinstance(f, dict):
                                findings_for_trend.append({
                                    "cve_id": f.get("cve_id", ""),
                                    "severity": f.get("severity", "unknown"),
                                    "cwe_id": f.get("cwe_id", ""),
                                    "cvss_score": f.get("cvss_score", 0.0),
                                    "title": f.get("title", ""),
                                    "scanner": f.get("scanner", "unknown"),
                                })

            scan_record = {
                "scan_id": result.run_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "org_id": result.org_id,
                "app_id": "",
                "findings": findings_for_trend,
                "pipeline_status": result.status.value,
                "findings_ingested": result.findings_ingested,
            }

            analyzer = get_trend_analyzer()
            analyzer.add_scan(scan_record)
            logger.debug(
                "Trend analyzer fed scan %s (%d findings)",
                result.run_id,
                len(findings_for_trend),
            )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Trend analysis skipped: %s", type(e).__name__)


# ---------------------------------------------------------------------------
# False Positive Feedback Store
# ---------------------------------------------------------------------------
import sqlite3 as _sqlite3


class FPFeedbackStore:
    """Persistent store for false-positive feedback on findings.

    Tracks analyst decisions (is_false_positive, reason, scanner, CWE, app_id)
    and provides auto-suppression logic when a pattern recurs 3+ times.
    """

    _instance: Optional["FPFeedbackStore"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or os.path.join(
            os.getenv("FIXOPS_DATA_DIR", ".fixops_data"), "fp_feedback.db"
        )
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        self._conn = _sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS fp_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                is_false_positive INTEGER NOT NULL DEFAULT 1,
                reason TEXT DEFAULT '',
                scanner TEXT DEFAULT '',
                cwe_id TEXT DEFAULT '',
                app_id TEXT DEFAULT '',
                org_id TEXT DEFAULT '',
                rule_id TEXT DEFAULT '',
                title TEXT DEFAULT '',
                analyst TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_fp_scanner_cwe
            ON fp_feedback(scanner, cwe_id, is_false_positive)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_fp_rule
            ON fp_feedback(rule_id, is_false_positive)
        """)
        self._conn.commit()

    @classmethod
    def get_instance(cls) -> "FPFeedbackStore":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def record_feedback(
        self,
        finding_id: str,
        is_false_positive: bool,
        reason: str = "",
        scanner: str = "",
        cwe_id: str = "",
        app_id: str = "",
        org_id: str = "",
        rule_id: str = "",
        title: str = "",
        analyst: str = "",
    ) -> Dict[str, Any]:
        """Record analyst feedback on a finding."""
        self._conn.execute(
            """INSERT INTO fp_feedback
               (finding_id, is_false_positive, reason, scanner, cwe_id,
                app_id, org_id, rule_id, title, analyst)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, int(is_false_positive), reason, scanner, cwe_id,
             app_id, org_id, rule_id, title, analyst),
        )
        self._conn.commit()
        return {
            "finding_id": finding_id,
            "is_false_positive": is_false_positive,
            "auto_suppress_eligible": self.should_auto_suppress(
                scanner=scanner, cwe_id=cwe_id, rule_id=rule_id
            ),
        }

    def should_auto_suppress(
        self,
        scanner: str = "",
        cwe_id: str = "",
        rule_id: str = "",
        threshold: int = 3,
    ) -> bool:
        """Check if a finding pattern should be auto-suppressed.

        Returns True if the same scanner+CWE or rule_id has been marked
        as FP at least `threshold` times.
        """
        if rule_id:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM fp_feedback WHERE rule_id = ? AND is_false_positive = 1",
                (rule_id,),
            ).fetchone()
            if row and row[0] >= threshold:
                return True
        if scanner and cwe_id:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM fp_feedback WHERE scanner = ? AND cwe_id = ? AND is_false_positive = 1",
                (scanner, cwe_id),
            ).fetchone()
            if row and row[0] >= threshold:
                return True
        return False

    def get_fp_rate(
        self,
        scanner: Optional[str] = None,
        cwe_id: Optional[str] = None,
        app_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Calculate false positive rate with optional filters."""
        conditions: List[str] = []
        params: List[Any] = []
        if scanner:
            conditions.append("scanner = ?")
            params.append(scanner)
        if cwe_id:
            conditions.append("cwe_id = ?")
            params.append(cwe_id)
        if app_id:
            conditions.append("app_id = ?")
            params.append(app_id)
        if org_id:
            conditions.append("org_id = ?")
            params.append(org_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        row = self._conn.execute(
            f"SELECT COUNT(*), SUM(is_false_positive) FROM fp_feedback {where}",  # nosec B608
            params,
        ).fetchone()
        total = row[0] if row else 0
        fp_count = int(row[1] or 0) if row else 0
        tp_count = total - fp_count

        # Breakdown by scanner
        scanner_rows = self._conn.execute(
            f"""SELECT scanner, COUNT(*) as total,SUM(is_false_positive) as fps
                FROM fp_feedback {where}
                GROUP BY scanner ORDER BY total DESC""",  # nosec B608
            params,
        ).fetchall()
        by_scanner = [
            {
                "scanner": r[0] or "unknown",
                "total": r[1],
                "false_positives": int(r[2] or 0),
                "fp_rate": round(int(r[2] or 0) / r[1], 4) if r[1] else 0,
            }
            for r in scanner_rows
        ]

        # Breakdown by CWE
        cwe_rows = self._conn.execute(
            f"""SELECT cwe_id, COUNT(*) as total,SUM(is_false_positive) as fps
                FROM fp_feedback {where}
                GROUP BY cwe_id ORDER BY total DESC LIMIT 20""",  # nosec B608
            params,
        ).fetchall()
        by_cwe = [
            {
                "cwe_id": r[0] or "unknown",
                "total": r[1],
                "false_positives": int(r[2] or 0),
                "fp_rate": round(int(r[2] or 0) / r[1], 4) if r[1] else 0,
            }
            for r in cwe_rows
        ]

        return {
            "total_feedback": total,
            "false_positives": fp_count,
            "true_positives": tp_count,
            "fp_rate": round(fp_count / total, 4) if total else 0.0,
            "by_scanner": by_scanner,
            "by_cwe": by_cwe,
        }

    def get_recent_feedback(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent feedback entries."""
        rows = self._conn.execute(
            "SELECT finding_id, is_false_positive, reason, scanner, cwe_id, "
            "app_id, org_id, rule_id, title, analyst, created_at "
            "FROM fp_feedback ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "finding_id": r[0],
                "is_false_positive": bool(r[1]),
                "reason": r[2],
                "scanner": r[3],
                "cwe_id": r[4],
                "app_id": r[5],
                "org_id": r[6],
                "rule_id": r[7],
                "title": r[8],
                "analyst": r[9],
                "created_at": r[10],
            }
            for r in rows
        ]

    def get_auto_suppress_rules(self, threshold: int = 3) -> List[Dict[str, Any]]:
        """Get patterns that qualify for auto-suppression."""
        rows = self._conn.execute(
            """SELECT scanner, cwe_id, rule_id, COUNT(*) as fp_count
               FROM fp_feedback WHERE is_false_positive = 1
               GROUP BY scanner, cwe_id, rule_id
               HAVING COUNT(*) >= ?
               ORDER BY fp_count DESC""",
            (threshold,),
        ).fetchall()
        return [
            {
                "scanner": r[0] or "",
                "cwe_id": r[1] or "",
                "rule_id": r[2] or "",
                "fp_count": r[3],
            }
            for r in rows
        ]


def get_fp_feedback_store() -> FPFeedbackStore:
    """Get the global FPFeedbackStore singleton."""
    return FPFeedbackStore.get_instance()


# ---------------------------------------------------------------------------
# Module-level singleton (thread-safe via double-checked locking)
# ---------------------------------------------------------------------------
_pipeline_instance: Optional[BrainPipeline] = None
_pipeline_lock = threading.Lock()


def get_brain_pipeline() -> BrainPipeline:
    """Get the global BrainPipeline instance (thread-safe).

    Uses double-checked locking pattern to avoid lock contention
    after initialization.
    """
    global _pipeline_instance
    if _pipeline_instance is None:
        with _pipeline_lock:
            if _pipeline_instance is None:
                _pipeline_instance = BrainPipeline()
    return _pipeline_instance
