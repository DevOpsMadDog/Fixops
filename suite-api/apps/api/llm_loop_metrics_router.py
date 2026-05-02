"""LLM Phase 1 Telemetry Router — closed-loop visibility for the CTO/CISO.

Surfaces the live health of the LLM Learning Loop:

    EventBus  --(finding.created)-->  llm_learning_loop  -->
        learning_signals.db (council_verdicts + feedback_pairs)
            -->  AgentDB semantic store (.swarm/memory.db)

Exposes ONE endpoint:

    GET /api/v1/llm-loop/metrics

…that returns a single JSON payload the Brain hero "Learning Loop" tab can render
without orchestrating multiple round-trips. All counts come from the live SQLite
DB at ``data/learning_signals.db`` (or whatever ``FIXOPS_LLM_LOOP_SIGNALS_DB``
points at). The in-process bus is queried for processed-event counts + last
event time. AgentDB health is best-effort — if the bridge isn't initialised the
endpoint still returns 200.

NEVER raises on data issues. Returns ``status: "empty" | "sparse" | "ok"`` so
the UI can render an informative state instead of a network error.

Identity: CTEM+ (Step 7 risk score uses the verdicts; Step 9 LLM consensus is
fed by the same loop). Air-gap clean — no cloud calls.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/llm-loop", tags=["LLM Loop Telemetry"])


# ---------------------------------------------------------------------------
# Constants & helpers
# ---------------------------------------------------------------------------

_DEFAULT_SIGNALS_DB = "data/learning_signals.db"
_DISTILL_THRESHOLD = 10_000  # Phase 2 distillation kicks in at 10k DPO pairs.


def _signals_db_path() -> str:
    """Resolve the signals DB path the loop is currently writing to."""
    return os.environ.get("FIXOPS_LLM_LOOP_SIGNALS_DB", _DEFAULT_SIGNALS_DB)


def _connect_ro(path: str) -> Optional[sqlite3.Connection]:
    """Open the signals DB read-only. Returns None if missing/corrupt."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        # immutable URI mode → no schema migration side-effects
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as exc:
        logger.warning("llm-loop metrics: cannot open signals db %s: %s", path, exc)
        return None


_ALLOWED_TABLES = frozenset({"council_verdicts", "feedback_pairs"})

_SAFE_TABLE_RE = __import__("re").compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _validate_table(table: str) -> str:
    """Return the table name if it is in the explicit allowlist, raise ValueError otherwise."""
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"llm-loop metrics: disallowed table name: {table!r}")
    return table


def _safe_count(conn: sqlite3.Connection, table: str) -> int:
    try:
        t = _validate_table(table)
        row = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()  # nosec B608 — table validated by allowlist
        return int(row[0]) if row else 0
    except (sqlite3.Error, ValueError):
        return 0


def _last_created(conn: sqlite3.Connection, table: str) -> Optional[str]:
    try:
        t = _validate_table(table)
        row = conn.execute(
            f"SELECT created_at FROM {t} ORDER BY created_at DESC LIMIT 1"  # nosec B608 — table validated by allowlist
        ).fetchone()
        return row[0] if row else None
    except (sqlite3.Error, ValueError):
        return None


def _pairs_in_last_hours(conn: sqlite3.Connection, hours: int = 24) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM feedback_pairs WHERE created_at >= ?",
            (cutoff,),
        ).fetchone()
        return int(row[0]) if row else 0
    except sqlite3.Error:
        return 0


def _empty_growth_buckets(hours: int = 24, bucket_count: int = 12) -> List[Dict[str, Any]]:
    """Same time-axis as :func:`_pairs_growth_buckets` but with all counts = 0.

    Returned in oldest-first order so chart axes match the populated path.
    """
    end = datetime.now(timezone.utc)
    bucket_h = max(hours / bucket_count, 0.5)
    out: List[Dict[str, Any]] = []
    for i in range(bucket_count):
        b_end = end - timedelta(hours=bucket_h * i)
        b_start = b_end - timedelta(hours=bucket_h)
        out.append(
            {
                "bucket_start": b_start.isoformat(),
                "bucket_end": b_end.isoformat(),
                "count": 0,
            }
        )
    out.reverse()
    return out


def _pairs_growth_buckets(
    conn: sqlite3.Connection, hours: int = 24, bucket_count: int = 12
) -> List[Dict[str, Any]]:
    """Return a list of {bucket_start_iso, count} for the last `hours` hours.

    Bucket size is uniform: hours/bucket_count. Default is 12 buckets x 2h = 24h.
    """
    end = datetime.now(timezone.utc)
    bucket_h = max(hours / bucket_count, 0.5)
    buckets: List[Dict[str, Any]] = []
    for i in range(bucket_count):
        b_end = end - timedelta(hours=bucket_h * i)
        b_start = b_end - timedelta(hours=bucket_h)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM feedback_pairs "
                "WHERE created_at >= ? AND created_at < ?",
                (b_start.isoformat(), b_end.isoformat()),
            ).fetchone()
            count = int(row[0]) if row else 0
        except sqlite3.Error:
            count = 0
        buckets.append(
            {
                "bucket_start": b_start.isoformat(),
                "bucket_end": b_end.isoformat(),
                "count": count,
            }
        )
    # Oldest first for chart consumers
    buckets.reverse()
    return buckets


def _classify_finding_source(finding_id: str) -> str:
    """Map a finding_id prefix → source_kind. Best-effort heuristic.

    The loop tags findings with their origin via the finding_id prefix or via
    the raw_event payload. This mirrors how scanners stamp IDs:

        SAST-…     -> sast
        SECRETS-…  -> secrets
        SCA-…      -> sca
        DAST-…     -> dast
        IAC-…      -> iac
        CSPM-…     -> cspm
        CONTAINER- -> container
        SMOKE-…    -> smoke   (skeleton/test)
        alert_…    -> alert
        threat_…   -> threat
        f_…        -> bus     (raw EventBus, no scanner stamp)
    """
    fid = (finding_id or "").upper()
    if fid.startswith("SAST"):
        return "sast"
    if fid.startswith("SCA"):
        return "sca"
    if fid.startswith("SECRETS"):
        return "secrets"
    if fid.startswith("DAST"):
        return "dast"
    if fid.startswith("IAC"):
        return "iac"
    if fid.startswith("CSPM"):
        return "cspm"
    if fid.startswith("CONTAINER"):
        return "container"
    if fid.startswith("KUBE"):
        return "kube"
    if fid.startswith("SMOKE"):
        return "smoke"
    if fid.startswith("ALERT_"):
        return "alert"
    if fid.startswith("THREAT_"):
        return "threat"
    if fid.startswith("F_"):
        return "bus"
    return "other"


def _top_n_sources(conn: sqlite3.Connection, n: int = 5) -> List[Dict[str, Any]]:
    """Tally verdicts by classified source_kind, return top N."""
    buckets: Dict[str, int] = {}
    try:
        for row in conn.execute("SELECT finding_id FROM council_verdicts"):
            kind = _classify_finding_source(row["finding_id"])
            buckets[kind] = buckets.get(kind, 0) + 1
    except sqlite3.Error:
        return []
    ordered = sorted(buckets.items(), key=lambda kv: kv[1], reverse=True)
    return [{"source_kind": k, "count": v} for k, v in ordered[:n]]


def _percentiles(values: List[float], pcts: Tuple[int, ...] = (50, 95, 99)) -> Dict[str, float]:
    """Pure-python percentile (no NumPy) — values are assumed unsorted, ms."""
    if not values:
        return {f"p{p}": 0.0 for p in pcts}
    sorted_vals = sorted(values)
    out: Dict[str, float] = {}
    for p in pcts:
        # simple nearest-rank
        idx = max(0, min(len(sorted_vals) - 1, int(round(p / 100.0 * (len(sorted_vals) - 1)))))
        out[f"p{p}"] = round(sorted_vals[idx], 2)
    return out


def _latency_stats(
    conn: sqlite3.Connection, sample_limit: int = 1000
) -> Dict[str, Any]:
    """Compute p50/p95/p99 latency over the last `sample_limit` verdicts.

    Latency is parsed from the JSON-encoded raw_verdict.latency_ms field. Rows
    without a numeric latency are skipped silently.
    """
    latencies: List[float] = []
    escalations = 0
    total = 0
    try:
        cur = conn.execute(
            "SELECT raw_verdict FROM council_verdicts "
            "ORDER BY created_at DESC LIMIT ?",
            (sample_limit,),
        )
        for row in cur:
            total += 1
            try:
                rv = json.loads(row["raw_verdict"]) if row["raw_verdict"] else {}
            except (json.JSONDecodeError, TypeError):
                continue
            lm = rv.get("latency_ms")
            if isinstance(lm, (int, float)) and lm >= 0:
                latencies.append(float(lm))
            if rv.get("escalated"):
                escalations += 1
    except sqlite3.Error:
        pass

    pcts = _percentiles(latencies)
    return {
        "p50": pcts["p50"],
        "p95": pcts["p95"],
        "p99": pcts["p99"],
        "sample_size": len(latencies),
        "sample_window": sample_limit,
        "escalation_rate_in_sample": (
            round(escalations / total, 4) if total else 0.0
        ),
        "escalations_in_sample": escalations,
    }


def _agentdb_status() -> Dict[str, Any]:
    """Best-effort AgentDB health snapshot. Returns minimal stub if unavailable.

    The bridge instantiation is gated by ``FIXOPS_AGENTDB_ENABLED`` and
    ``FIXOPS_TEST_MODE`` — when either disables it we skip import entirely so
    tests never reach the (slow) MiniLM model download path.
    """
    if os.environ.get("FIXOPS_TEST_MODE", "0") in ("1", "true", "yes"):
        return {
            "available": False,
            "enabled": False,
            "entries": 0,
            "store_path": None,
            "skipped_reason": "FIXOPS_TEST_MODE=1",
        }
    if os.environ.get("FIXOPS_AGENTDB_ENABLED", "1") in ("0", "false", "no"):
        return {
            "available": False,
            "enabled": False,
            "entries": 0,
            "store_path": None,
            "skipped_reason": "FIXOPS_AGENTDB_ENABLED=0",
        }
    try:
        from trustgraph.agentdb_bridge import get_agentdb_bridge

        bridge = get_agentdb_bridge()
        h = bridge.health()
        return {
            "available": bool(h.get("available")),
            "enabled": bool(h.get("enabled")),
            "entries": int(h.get("entries_active") or 0),
            "store_path": h.get("store_path"),
            "embedder": h.get("embedder"),
            "writes": int(h.get("writes") or 0),
            "searches": int(h.get("searches") or 0),
            "failures": int(h.get("failures") or 0),
        }
    except (ImportError, AttributeError, OSError) as exc:
        return {
            "available": False,
            "enabled": False,
            "entries": 0,
            "store_path": None,
            "error": type(exc).__name__,
        }


def _loop_status() -> Dict[str, Any]:
    """Pull live status from the in-process LLM learning loop singleton."""
    try:
        from core.llm_learning_loop import get_llm_learning_loop

        loop = get_llm_learning_loop()
        if loop is None:
            return {
                "running": False,
                "processed_events": 0,
                "last_error": None,
                "council_built": False,
            }
        st = loop.status()
        return {
            "running": bool(st.get("running")),
            "processed_events": int(st.get("processed_events") or 0),
            "last_error": st.get("last_error"),
            "council_built": bool(st.get("council_built")),
            "subscribed_event_types": st.get("subscribed_event_types") or [],
        }
    except (ImportError, AttributeError, RuntimeError) as exc:
        return {
            "running": False,
            "processed_events": 0,
            "last_error": f"{type(exc).__name__}: {exc}",
            "council_built": False,
        }


def _classify_status(verdicts: int, pairs: int) -> str:
    if verdicts == 0 and pairs == 0:
        return "empty"
    if verdicts < 50 or pairs < 10:
        return "sparse"
    return "ok"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/metrics",
    summary="LLM Phase 1 closed-loop telemetry",
    description=(
        "One-shot health snapshot of the LLM Learning Loop. "
        "Powers the Brain hero 'Learning Loop' tab. Counts come from "
        "data/learning_signals.db; runtime status comes from the in-process bus."
    ),
)
async def get_llm_loop_metrics() -> Dict[str, Any]:
    """Live closed-loop telemetry — no auth so Brain hero KPI cards stay snappy."""
    started = time.perf_counter()
    db_path = _signals_db_path()
    conn = _connect_ro(db_path)

    # Default empty payload — populated below if the DB is reachable.
    verdicts_total = 0
    pairs_total = 0
    pairs_24h = 0
    # Always emit 12 zero-buckets so chart consumers never receive an empty
    # array (even when the DB doesn't exist). Bucket boundaries match the live
    # path so the UI can pre-render axes without conditional logic.
    growth_buckets: List[Dict[str, Any]] = _empty_growth_buckets(
        hours=24, bucket_count=12
    )
    top_sources: List[Dict[str, Any]] = []
    last_pair_at: Optional[str] = None
    last_verdict_at: Optional[str] = None
    latency: Dict[str, Any] = {
        "p50": 0.0,
        "p95": 0.0,
        "p99": 0.0,
        "sample_size": 0,
        "sample_window": 0,
        "escalation_rate_in_sample": 0.0,
        "escalations_in_sample": 0,
    }

    db_reachable = conn is not None
    if conn is not None:
        try:
            verdicts_total = _safe_count(conn, "council_verdicts")
            pairs_total = _safe_count(conn, "feedback_pairs")
            pairs_24h = _pairs_in_last_hours(conn, hours=24)
            last_pair_at = _last_created(conn, "feedback_pairs")
            last_verdict_at = _last_created(conn, "council_verdicts")
            growth_buckets = _pairs_growth_buckets(conn, hours=24, bucket_count=12)
            top_sources = _top_n_sources(conn, n=5)
            latency = _latency_stats(conn, sample_limit=1000)
        finally:
            conn.close()

    pairs_per_hour = round(pairs_24h / 24.0, 2)
    distill_pct = (
        round(min(pairs_total / _DISTILL_THRESHOLD, 1.0) * 100.0, 2)
        if pairs_total
        else 0.0
    )

    # Council fall-through is meaningful only after a student model is loaded.
    # Today no student is wired into the loop, so this is 0.0; the field exists
    # so the UI can render the metric the moment Phase 2 lands.
    student_loaded = (
        os.environ.get("FIXOPS_PHASE2_STUDENT_LOADED", "0").lower() in ("1", "true", "yes")
    )
    council_fall_through_rate = 0.0  # placeholder until student gating is wired

    # Opus escalation rate — share of recent verdicts that escalated.
    opus_escalation_rate = latency.get("escalation_rate_in_sample", 0.0)

    loop = _loop_status()
    agentdb = _agentdb_status()

    last_event_processed_at = last_verdict_at  # most recent council write = last processed
    duration_ms = round((time.perf_counter() - started) * 1000.0, 2)

    return {
        "status": _classify_status(verdicts_total, pairs_total),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": duration_ms,
        "db_path": db_path,
        "db_reachable": db_reachable,
        # Headline counters (KPI cards)
        "council_verdicts_total": verdicts_total,
        "feedback_pairs_total": pairs_total,
        "pairs_per_hour": pairs_per_hour,
        "pairs_last_24h": pairs_24h,
        # Phase 2 distillation progress
        "distill_threshold_progress": {
            "current_pairs": pairs_total,
            "target_pairs": _DISTILL_THRESHOLD,
            "percent": distill_pct,
        },
        # Routing health
        "council_fall_through_rate": council_fall_through_rate,
        "student_loaded": student_loaded,
        "opus_escalation_rate": opus_escalation_rate,
        # Latency (p50 / p95 / p99 ms over last 1000 verdicts)
        "avg_latency_ms": latency,
        # Source distribution
        "top_5_finding_types": top_sources,
        # Time-series for charts
        "pairs_growth_24h": growth_buckets,
        # Activity
        "last_event_processed_at": last_event_processed_at,
        "last_pair_at": last_pair_at,
        "last_verdict_at": last_verdict_at,
        # Subsystem status
        "loop": loop,
        "agentdb_entries_count": agentdb["entries"],
        "agentdb_health": agentdb,
    }


@router.get(
    "/health",
    summary="Lightweight liveness for the LLM telemetry router",
)
async def llm_loop_metrics_health() -> Dict[str, Any]:
    """Tiny health check — confirms the router is mounted and DB path resolves."""
    db_path = _signals_db_path()
    return {
        "status": "ok",
        "router": "llm-loop-metrics",
        "signals_db": db_path,
        "signals_db_exists": Path(db_path).exists(),
    }
