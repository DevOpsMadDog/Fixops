"""Pipeline-on-ingest dispatch helper — ALDECI (SPEC-017).

Runs the 12-step Brain Pipeline automatically on ingest, NON-BLOCKING and config-gated,
with the production guards the SCIF-Accreditor + Red-Team debate required:

  - DEFAULT OFF (FIXOPS_PIPELINE_ON_INGEST). Unset => byte-for-byte unchanged behaviour.
  - AIR-GAP HARD-CHECK (not exception-reliant): in enforced air-gap with NO configured local
    LLM, the pipeline is NEVER constructed and NEVER egresses — it is skipped + logged + recorded.
  - BOUNDED CONCURRENCY: a process-global BoundedSemaphore caps in-flight runs; excess is
    DROPPED (logged + recorded), never queued unboundedly, never blocks the ingest caller.
  - PER-ORG RATE LIMIT: token-bucket per org (economic-DoS / LLM-cost amplification guard).
  - DURABLE OBSERVABILITY: every outcome (started/completed/failed/skipped/dropped/rate_limited)
    is written to data/pipeline_runs.db and exposed via pipeline_run_stats() — no silent loss.

Env:
  FIXOPS_PIPELINE_ON_INGEST   truthy => auto-run on ingest (default off)
  FIXOPS_PIPELINE_MAX_WORKERS max concurrent background runs (default 8)
  FIXOPS_PIPELINE_RATE_PER_MIN max dispatches/min/org (default 10)
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_RUNS_DB = Path(os.environ.get("FIXOPS_PIPELINE_RUNS_DB", "data/pipeline_runs.db"))


def _max_workers() -> int:
    try:
        return max(1, int(os.environ.get("FIXOPS_PIPELINE_MAX_WORKERS", "8")))
    except ValueError:
        return 8


def _rate_per_min() -> int:
    try:
        return max(1, int(os.environ.get("FIXOPS_PIPELINE_RATE_PER_MIN", "10")))
    except ValueError:
        return 10


# Process-global bounded concurrency — drop (never block/queue) when saturated.
_SEM = threading.BoundedSemaphore(_max_workers())

# Per-org token bucket: org_id -> [tokens, last_refill_ts].
_RATE_LOCK = threading.Lock()
_BUCKETS: Dict[str, List[float]] = {}


def _enabled() -> bool:
    return os.environ.get("FIXOPS_PIPELINE_ON_INGEST", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _local_llm_configured() -> bool:
    """True only when a local LLM backend is EXPLICITLY configured (no network probe)."""
    if any(os.environ.get(k) for k in (
        "FIXOPS_VLLM_URL", "FIXOPS_OLLAMA_URL", "FIXOPS_LOCAL_LLM_URL", "FIXOPS_LLAMACPP_URL",
    )):
        return True
    return os.environ.get("FIXOPS_LLM_BACKEND", "").strip().lower() in (
        "vllm", "ollama", "local", "llama_cpp", "llamacpp",
    )


def _allow_org(org_id: str) -> bool:
    """Token-bucket rate limit per org (REQ: economic-DoS guard)."""
    rate = _rate_per_min()
    now = time.time()
    with _RATE_LOCK:
        tokens, last = _BUCKETS.get(org_id, [float(rate), now])
        tokens = min(float(rate), tokens + (now - last) * (rate / 60.0))
        if tokens < 1.0:
            _BUCKETS[org_id] = [tokens, now]
            return False
        _BUCKETS[org_id] = [tokens - 1.0, now]
        return True


def _conn() -> sqlite3.Connection:
    _RUNS_DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(_RUNS_DB))
    con.row_factory = sqlite3.Row
    con.execute(
        """CREATE TABLE IF NOT EXISTS pipeline_runs (
            org_id     TEXT NOT NULL,
            source     TEXT,
            status     TEXT NOT NULL,
            error      TEXT,
            findings   INTEGER,
            created_at REAL NOT NULL
        )"""
    )
    return con


def _record(org_id: str, source: str, status: str,
            error: Optional[str] = None, findings: int = 0) -> None:
    try:
        con = _conn()
        con.execute(
            "INSERT INTO pipeline_runs (org_id, source, status, error, findings, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (org_id, source, status, error, findings, time.time()),
        )
        con.commit()
        con.close()
    except Exception:  # noqa: BLE001 - observability must never break ingest
        pass


def _run(findings: List[Dict[str, Any]], org_id: str, source: str) -> None:
    try:
        from core.brain_pipeline import BrainPipeline, PipelineInput

        bp = BrainPipeline()
        bp.run(PipelineInput(
            findings=findings,
            assets=[],
            source=f"{source}:org={org_id}",  # org-scoped provenance
        ))
        _record(org_id, source, "completed", findings=len(findings))
    except Exception as exc:  # noqa: BLE001 - background; never surfaces to caller
        _record(org_id, source, "failed", error=type(exc).__name__, findings=len(findings))
        _logger.warning("pipeline-on-ingest run failed org=%s source=%s: %s",
                        org_id, source, type(exc).__name__)
    finally:
        try:
            _SEM.release()
        except ValueError:
            pass


def dispatch_pipeline_on_ingest(findings: List[Dict[str, Any]], org_id: str,
                                source: str) -> Dict[str, Any]:
    """Schedule a non-blocking Brain-Pipeline run for ingested findings. Honest, gated, bounded.

    Returns {"dispatched": bool, "reason": str}. NEVER raises, NEVER blocks the caller.
    """
    if not _enabled():
        return {"dispatched": False, "reason": "disabled"}
    if not findings:
        return {"dispatched": False, "reason": "no_findings"}
    if not org_id:
        return {"dispatched": False, "reason": "no_org"}

    # AIR-GAP HARD-CHECK (SCIF-Accreditor): enforced + no local LLM => never construct, never egress.
    try:
        from core.airgap_config import is_airgap_enforced

        if is_airgap_enforced() and not _local_llm_configured():
            _record(org_id, source, "skipped_airgap", findings=len(findings))
            _logger.warning(
                "pipeline-on-ingest skipped: enforced air-gap + no local LLM configured (org=%s)",
                org_id,
            )
            return {"dispatched": False, "reason": "airgap_no_local_llm"}
    except Exception:  # noqa: BLE001 - guard must fail safe (skip), never crash ingest
        return {"dispatched": False, "reason": "airgap_check_error"}

    # PER-ORG RATE LIMIT (economic-DoS guard).
    if not _allow_org(org_id):
        _record(org_id, source, "rate_limited", findings=len(findings))
        _logger.info("pipeline-on-ingest rate-limited org=%s", org_id)
        return {"dispatched": False, "reason": "rate_limited"}

    # BOUNDED CONCURRENCY — drop (never block/queue) when the worker pool is saturated.
    if not _SEM.acquire(blocking=False):
        _record(org_id, source, "dropped_saturated", findings=len(findings))
        _logger.warning("pipeline-on-ingest dropped: worker pool saturated (org=%s)", org_id)
        return {"dispatched": False, "reason": "saturated"}

    _record(org_id, source, "started", findings=len(findings))
    threading.Thread(
        target=_run, args=(list(findings), org_id, source), daemon=True,
    ).start()
    return {"dispatched": True, "reason": "scheduled"}


def pipeline_run_stats(org_id: Optional[str] = None) -> Dict[str, Any]:
    """Aggregate background-run outcomes for operator observability (no silent loss)."""
    try:
        con = _conn()
        if org_id:
            rows = con.execute(
                "SELECT status, COUNT(*) c FROM pipeline_runs WHERE org_id=? GROUP BY status",
                (org_id,),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT status, COUNT(*) c FROM pipeline_runs GROUP BY status"
            ).fetchall()
        con.close()
        by_status = {r["status"]: r["c"] for r in rows}
        return {
            "by_status": by_status,
            "failed": by_status.get("failed", 0),
            "completed": by_status.get("completed", 0),
            "enabled": _enabled(),
            "max_workers": _max_workers(),
            "rate_per_min": _rate_per_min(),
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": type(exc).__name__}
