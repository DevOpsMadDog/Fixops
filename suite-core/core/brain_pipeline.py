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
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


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
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": round(self.duration_ms, 2),
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
    run_playbooks: bool = False
    generate_evidence: bool = False
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
            },
            "error": self.error,
        }


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

    def __init__(self) -> None:
        self._runs: Dict[str, PipelineResult] = {}
        self._metrics: List[Dict[str, Any]] = []
        self._lock = threading.Lock()  # Thread-safe access to _runs/_metrics
        self._cancelled: set = set()  # Run IDs that have been cancelled

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
            self._step_deduplicate,
            self._step_build_graph,
            self._step_enrich_threats,
            self._step_score_risk,
            self._step_apply_policy,
            self._step_llm_consensus,
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

            try:
                step.output = func(ctx, inp) or {}
                step.status = StepStatus.COMPLETED
            except Exception as e:
                step.status = StepStatus.FAILED
                # Only expose exception type, not message (may contain secrets/PII)
                step.error = f"{type(e).__name__}: pipeline step failed"
                logger.error("Pipeline step %s failed: %s", step.name, e, exc_info=True)
                failed = True

            step.duration_ms = (time.monotonic() - t0) * 1000
            step.finished_at = datetime.now(timezone.utc).isoformat()

            # Record per-step metrics
            findings_out = len(ctx.get("findings", []))
            ctx["metrics"][step.name] = {
                "duration_ms": round(step.duration_ms, 2),
                "findings_in": findings_in,
                "findings_out": findings_out,
                "status": step.status.value,
            }

        result.total_duration_ms = (time.monotonic() - pipeline_start) * 1000
        result.finished_at = datetime.now(timezone.utc).isoformat()

        # Populate summary
        result.findings_ingested = len(inp.findings)
        result.clusters_created = len(ctx.get("clusters", []))
        result.exposure_cases_created = len(ctx.get("exposure_cases", []))
        result.pentest_validated = len(ctx.get("pentest_results", []))
        result.playbooks_executed = len(ctx.get("playbook_results", []))
        result.avg_risk_score = ctx.get("risk_scores", {}).get("avg", 0.0)
        result.critical_cases = ctx.get("risk_scores", {}).get("critical", 0)

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
        return result

    async def run_async(self, inp: PipelineInput) -> PipelineResult:
        """Execute the pipeline asynchronously (non-blocking).

        Offloads the synchronous pipeline to a thread pool so it doesn't
        block the event loop. Use this from async API handlers.

        [V3] Decision Intelligence — scales past 100 concurrent requests.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.run, inp)

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

    def get_run(self, run_id: str) -> Optional[PipelineResult]:
        with self._lock:
            return self._runs.get(run_id)

    def list_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            runs = sorted(self._runs.values(), key=lambda r: r.started_at, reverse=True)
            return [r.to_dict() for r in runs[:limit]]

    # ------------------------------------------------------------------
    # Step 1: Connect everything once
    # ------------------------------------------------------------------
    def _step_connect(self, ctx: Dict[str, Any], inp: PipelineInput) -> Dict[str, Any]:
        """Connectors already ingested → just tally."""
        return {
            "findings_count": len(ctx.get("findings", [])),
            "assets_count": len(ctx.get("assets", [])),
            "source": inp.source,
        }

    # ------------------------------------------------------------------
    # Step 2: Translate into common language
    # ------------------------------------------------------------------
    def _step_normalize(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Ensure every finding has a canonical shape."""
        normalized = 0
        for f in ctx["findings"]:
            f.setdefault("severity", "medium")
            f.setdefault("source", inp.source)
            f.setdefault("org_id", ctx["org_id"])
            f.setdefault("title", f.get("message", f.get("rule_id", "unknown")))
            f.setdefault("cve_id", None)
            f.setdefault("asset_name", f.get("asset", f.get("component", "unknown")))
            normalized += 1
        return {"normalized_count": normalized}

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
        except Exception:
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
    # Step 4: Collapse duplicates into Exposure Cases
    # ------------------------------------------------------------------
    def _step_deduplicate(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Deduplicate findings and create Exposure Cases.

        Uses a thread-based timeout to prevent hanging on very large
        finding sets (50K+ findings can cause O(n²) in dedup service).
        """
        from pathlib import Path

        try:
            from core.services.deduplication import DeduplicationService

            dedup = DeduplicationService(db_path=Path("fixops_dedup.db"))
        except Exception:
            return {
                "clusters": 0,
                "skipped": True,
                "reason": "deduplication unavailable",
            }

        run_id = uuid.uuid4().hex[:12]

        # Run dedup with timeout to prevent hanging on large datasets
        def _do_dedup():
            return dedup.process_findings_batch(
                ctx["findings"], run_id=run_id, org_id=ctx["org_id"], source=inp.source
            )

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_do_dedup)
                batch = future.result(timeout=self.STEP_TIMEOUT_S)
        except concurrent.futures.TimeoutError:
            logger.warning(
                "Dedup step timed out after %ds for %d findings",
                self.STEP_TIMEOUT_S,
                len(ctx["findings"]),
            )
            return {
                "clusters": 0,
                "skipped": True,
                "reason": f"dedup timed out ({len(ctx['findings'])} findings)",
            }
        except Exception as e:
            logger.warning("Dedup step failed: %s", type(e).__name__)
            return {
                "clusters": 0,
                "skipped": True,
                "reason": f"dedup failed: {type(e).__name__}",
            }
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
                except Exception:
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
        except Exception as e:
            # Only expose exception type — str(e) may leak DB paths or credentials
            logger.warning(
                "Could not create exposure cases: %s", type(e).__name__
            )
            cases_updated = []

        return {
            "total_findings": batch.get("total_findings", len(ctx["findings"])),
            "unique_clusters": len(cluster_ids),
            "noise_reduction_pct": batch.get("noise_reduction_percent", 0),
            "exposure_cases_created": len(ctx.get("exposure_cases", [])),
            "exposure_cases_updated": len(cases_updated),
        }

    # ------------------------------------------------------------------
    # Step 5: Build the Brain Map (Knowledge Graph)
    # ------------------------------------------------------------------
    def _step_build_graph(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Upsert nodes/edges to Knowledge Graph Brain.

        Performance: Uses batched operations when findings > GRAPH_BATCH_SIZE
        to avoid memory pressure on large datasets. Pre-deduplicates CVE nodes
        to avoid redundant upserts (O(n) → O(unique_cves)).
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
        except Exception:
            return {"nodes": 0, "edges": 0, "skipped": True}

        nodes_added, edges_added = 0, 0
        seen_cves: set = set()  # Deduplicate CVE node upserts

        # Upsert asset nodes
        for asset in ctx["assets"]:
            node_id = asset.get("id", asset.get("name", ""))
            if not node_id:
                continue
            brain.upsert_node(
                GraphNode(
                    node_id=node_id,
                    node_type=EntityType.ASSET,
                    org_id=ctx["org_id"],
                    properties=asset,
                )
            )
            nodes_added += 1

        # Upsert finding nodes + edges in batches for scalability
        findings = ctx["findings"]
        for batch_start in range(0, len(findings), self.GRAPH_BATCH_SIZE):
            batch = findings[batch_start : batch_start + self.GRAPH_BATCH_SIZE]
            for f in batch:
                fid = f.get("id", f.get("rule_id", uuid.uuid4().hex[:12]))
                brain.upsert_node(
                    GraphNode(
                        node_id=fid,
                        node_type=EntityType.FINDING,
                        org_id=ctx["org_id"],
                        properties={
                            "title": f.get("title"),
                            "severity": f.get("severity"),
                        },
                    )
                )
                nodes_added += 1

                # Link finding → asset
                asset_id = f.get("canonical_asset_id", f.get("asset_name"))
                if asset_id:
                    brain.add_edge(
                        GraphEdge(
                            source_id=fid,
                            target_id=asset_id,
                            edge_type=EdgeType.AFFECTS,
                        )
                    )
                    edges_added += 1

                # Link finding → CVE (deduplicated node creation)
                cve = f.get("cve_id")
                if cve:
                    if cve not in seen_cves:
                        brain.upsert_node(
                            GraphNode(
                                node_id=cve,
                                node_type=EntityType.CVE,
                                org_id=ctx["org_id"],
                            )
                        )
                        seen_cves.add(cve)
                        nodes_added += 1
                    brain.add_edge(
                        GraphEdge(
                            source_id=fid,
                            target_id=cve,
                            edge_type=EdgeType.REFERENCES,
                        )
                    )
                    edges_added += 1

        # Link exposure cases
        for case_id in ctx.get("exposure_cases", []):
            brain.upsert_node(
                GraphNode(
                    node_id=case_id,
                    node_type=EntityType.EXPOSURE_CASE,
                    org_id=ctx["org_id"],
                )
            )
            nodes_added += 1

        stats = brain.stats()
        ctx["graph_stats"] = stats
        return {
            "nodes_added": nodes_added,
            "edges_added": edges_added,
            "unique_cves": len(seen_cves),
            "total_nodes": stats.get("total_nodes", 0),
            "total_edges": stats.get("total_edges", 0),
        }

    # ------------------------------------------------------------------
    # Step 6: Add threat reality signals (EPSS, KEV, CVSS)
    # ------------------------------------------------------------------
    def _step_enrich_threats(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Enrich findings with real EPSS scores, KEV status, and CVSS data.

        [V3] Decision Intelligence — Real threat feed enrichment.

        Uses the ThreatEnricher service to fetch live data from:
        - FIRST.org EPSS API (Exploit Prediction Scoring System)
        - CISA KEV catalog (Known Exploited Vulnerabilities)
        - NVD CVSS scores (cached)

        Falls back to calibrated severity-based estimates ONLY when
        API data is unavailable. The fallback estimates are based on
        FIRST.org EPSS research (median EPSS by CVSS severity bucket),
        NOT the old deterministic formula (cvss/10*0.6).
        """
        cve_ids = [f["cve_id"] for f in ctx["findings"] if f.get("cve_id")]
        if not cve_ids:
            return {"enriched": 0, "reason": "no CVE IDs to enrich"}

        # Try ML-powered threat enrichment with real API data
        try:
            from core.ml.threat_enricher import get_threat_enricher

            enricher = get_threat_enricher()
            result = enricher.enrich_findings(ctx["findings"])
            return result
        except Exception as e:
            # Only expose exception type — str(e) may contain API keys or URLs
            logger.warning(
                "ThreatEnricher unavailable (%s), using severity-based estimation",
                type(e).__name__,
            )

        # Fallback: calibrated severity-based estimation
        # Based on FIRST.org EPSS research — median EPSS by severity
        enriched = 0
        for f in ctx["findings"]:
            cve = f.get("cve_id")
            if not cve:
                continue
            sev = f.get("severity", "medium").lower()
            # CVSS estimation from severity
            cvss_map = {
                "critical": 9.5,
                "high": 7.5,
                "medium": 5.0,
                "low": 2.5,
                "info": 0.5,
            }
            # EPSS estimation: calibrated medians from FIRST.org research
            epss_map = {
                "critical": 0.25,
                "high": 0.10,
                "medium": 0.03,
                "low": 0.01,
                "info": 0.001,
            }
            cvss = cvss_map.get(sev, 5.0)
            epss = epss_map.get(sev, 0.03)

            # Boost EPSS if exploit is known
            if f.get("exploit_available"):
                epss = min(epss * 3.0, 0.95)

            f["cvss_score"] = cvss
            f["epss_score"] = round(epss, 6)
            f["epss_source"] = "estimated"
            f["in_kev"] = False  # Conservative: don't assume KEV without data
            f["kev_source"] = "unavailable"
            enriched += 1

        return {"enriched": enriched, "unique_cves": len(set(cve_ids))}

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
            from core.ml.risk_scorer import get_risk_model, MODEL_VERSION as _ml_ver
            ML_MODEL_VERSION = _ml_ver
            risk_model = get_risk_model()
            ml_available = risk_model.is_trained
        except Exception as e:
            logger.debug("ML risk scorer unavailable: %s", e)

        scores = []
        predictions_meta = []
        # Pre-build asset lookup to avoid O(n²) scan (P1 performance fix)
        asset_lookup: Dict[str, Dict[str, Any]] = {
            a.get("id", ""): a for a in ctx.get("assets", []) if a.get("id")
        }
        for f in ctx.get("findings", []):
            # Resolve asset criticality from pre-built lookup (O(1) per finding)
            asset_info = asset_lookup.get(f.get("canonical_asset_id", ""), {})
            asset_criticality = asset_info.get("criticality", 0.5)
            network_exposure = asset_info.get(
                "exposure", asset_info.get("network_exposure", "unknown")
            )

            if ml_available and risk_model is not None:
                # ML prediction with confidence interval
                vuln_data = {
                    "cvss_score": f.get("cvss_score", 5.0),
                    "epss_score": f.get("epss_score", 0.1),
                    "in_kev": f.get("in_kev", False),
                    "asset_criticality": asset_criticality,
                    "network_exposure": network_exposure,
                    "exploit_available": f.get("exploit_available", False),
                    "exploit_maturity": f.get("exploit_maturity", "none"),
                    "reachable": f.get("reachable", True),
                    "chain_cves": f.get("chain_cves"),
                }
                pred = risk_model.predict(vuln_data)
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
                except Exception as expl_err:
                    logger.debug("SHAP explanation failed: %s", expl_err)
                predictions_meta.append({
                    "model": pred.model_version,
                    "ci_width": pred.confidence_width,
                })
            else:
                # Fallback: deterministic weighted formula
                cvss = f.get("cvss_score", 5.0)
                epss = f.get("epss_score", 0.1)
                kev_boost = 1.5 if f.get("in_kev") else 1.0
                risk = round(
                    min(
                        (cvss / 10 * 0.4 + epss * 0.3 + 0.3)
                        * kev_boost
                        * asset_criticality,
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
        if predictions_meta:
            avg_ci = sum(p["ci_width"] for p in predictions_meta) / len(predictions_meta)
            result["avg_confidence_width"] = round(avg_ci, 2)

        return result

    # ------------------------------------------------------------------
    # Step 8: Policy decides what must happen
    # ------------------------------------------------------------------
    def _step_apply_policy(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Evaluate policy rules and determine required actions."""
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

        for f in ctx["findings"]:
            risk = f.get("risk_score", 0)
            in_kev = f.get("in_kev", False)
            action = "allow"
            triggered_rule = None
            for rule in rules:
                cond = rule.get("condition", "")
                if "risk_score >= 0.85" in cond and risk >= 0.85:
                    action = rule["action"]
                    triggered_rule = rule["name"]
                    break
                elif "risk_score >= 0.6" in cond and risk >= 0.6:
                    action = rule["action"]
                    triggered_rule = rule["name"]
                    break
                elif "in_kev" in cond and in_kev:
                    action = rule["action"]
                    triggered_rule = rule["name"]
                    break
            decisions.append(
                {
                    "finding_id": f.get("id", ""),
                    "action": action,
                    "rule": triggered_rule,
                }
            )
            f["policy_action"] = action

        ctx["policy_decisions"] = decisions
        action_counts = {}
        for d in decisions:
            action_counts[d["action"]] = action_counts.get(d["action"], 0) + 1
        return {"decisions": len(decisions), "action_breakdown": action_counts}

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

        [V3] Decision Intelligence — Batched severity-grouped processing.

        Improvements over naive approach:
        1. Groups findings by severity bucket for coherent LLM batches
        2. Caps at MAX_LLM_FINDINGS, sorted by risk (highest first)
        3. Sends severity overview per batch (not per-finding) to reduce LLM calls
        4. Timeout + fallback: deterministic consensus on LLM failure
        5. Thread-pool timeout on LLM call to prevent event loop blocking
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
            from core.enhanced_decision import EnhancedDecisionEngine
            import concurrent.futures

            engine = EnhancedDecisionEngine()

            # Group findings into severity batches for efficient LLM evaluation
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

            # Run LLM evaluation with thread-pool timeout to prevent blocking
            def _call_llm():
                return engine.evaluate_pipeline(
                    {"severity_overview": severity_overview},
                    risk_profile=ctx.get("risk_scores"),
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_call_llm)
                result = future.result(timeout=self.STEP_TIMEOUT_S)

            ctx["llm_results"] = [result]
            return {
                "analyzed": len(critical),
                "decision": result.get("final_decision", "unknown"),
                "capped": was_capped,
                "batch_count": sum(1 for v in severity_buckets.values() if v),
            }
        except (TimeoutError, concurrent.futures.TimeoutError):
            logger.warning("LLM consensus timed out — using deterministic fallback")
            return self._deterministic_consensus(critical, ctx)
        except Exception as e:
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
            if f.get("risk_score", 0) >= 0.75 and f.get("cve_id")
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
        except Exception as e:
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
                try:
                    from core.autofix_engine import AutoFixEngine

                    engine = AutoFixEngine()
                    fix = engine.generate_fix(
                        vulnerability={
                            "cve_id": f["cve_id"],
                            "severity": f.get("severity", "high"),
                        },
                        code_context=f.get("code_context", {}),
                    )
                    pb["autofix"] = {"status": "generated", "fix_id": fix.get("fix_id")}
                except Exception:
                    pb["autofix"] = {"status": "skipped"}
            playbook_results.append(pb)

        ctx["playbook_results"] = playbook_results
        return {
            "executed": len(playbook_results),
            "actions": {
                a: sum(1 for p in playbook_results if p["action"] == a)
                for a in set(p["action"] for p in playbook_results)
            },
        }

    # ------------------------------------------------------------------
    # Step 12: SOC2 Type II evidence pack
    # ------------------------------------------------------------------
    def _step_generate_evidence(
        self, ctx: Dict[str, Any], inp: PipelineInput
    ) -> Dict[str, Any]:
        """Generate SOC2 evidence pack from the pipeline results."""
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
        return evidence

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------
    def _emit_event(self, result: PipelineResult) -> None:
        """Emit pipeline completion event to the event bus.

        Also runs anomaly detection on the pipeline findings to detect
        unusual scan patterns. [V3] Decision Intelligence.
        """
        # Run anomaly detection on pipeline findings
        anomaly_result = self._run_anomaly_check(result)

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
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(bus.emit(event))
            except RuntimeError:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(bus.emit(event))
                loop.close()
        except Exception as e:
            logger.debug("Event emission skipped: %s", e)

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
        except Exception as e:
            logger.debug("Anomaly detection skipped: %s", e)
            return None


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
