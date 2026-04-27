"""In-process throughput benchmark for the LLM Phase 1 closed-loop.

Bypasses the HTTP layer entirely: fires synthetic FINDING_CREATED events
DIRECTLY at the in-process EventBus and measures how fast the
LLMLearningLoop subscriber can drain them.

What we measure:
    - Total wall time for N events
    - Per-event end-to-end latency (event emit -> verdict persisted -> decision
      republished). Captured by wrapping the loop's _on_event with a timer.
    - Throughput: events/sec
    - DB write rate: rows added to council_verdicts + feedback_pairs per second
    - AgentDB write rate: inferred from delta in agentdb file size (when bridge
      is enabled)

What we vary (modes):
    - --mode deterministic   : DeterministicLLMProvider (no API keys, no
      sentence-transformers). The reproducible baseline.
    - --mode deterministic-agentdb : same council, but AgentDB bridge enabled
      (sentence-transformers MiniLM if installed, hash-fallback otherwise).
    - --mode real-council    : CouncilFactory().create_security_council() —
      whatever providers happen to be wired (will fall back to deterministic
      if no API keys are present, in which case results match `deterministic`).

Usage:
    python scripts/benchmark_llm_loop_inprocess.py \\
        --events 1000 --mode deterministic --concurrency 1

    python scripts/benchmark_llm_loop_inprocess.py \\
        --events 200 --mode deterministic-agentdb --concurrency 4

The benchmark writes a tmp signals DB under /tmp/ and a tmp trustgraph DB
under /tmp/ — these are wiped between runs so previous data doesn't skew
throughput numbers.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# sys.path setup — make this script runnable from anywhere
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
for suite in (
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-integrations",
    "suite-evidence-risk",
):
    p = _PROJECT_ROOT / suite
    if p.is_dir():
        sys.path.insert(0, str(p))
sys.path.insert(0, str(_PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Synthetic event factory
# ---------------------------------------------------------------------------

_SEVERITIES = ("low", "medium", "high", "critical")
_CVE_TEMPLATES = [
    "CVE-2024-{:04d}",
    "CVE-2025-{:04d}",
    "CVE-2026-{:04d}",
]
_TITLES = [
    "SQL injection in /api/users",
    "XSS in profile renderer",
    "Outdated dependency lodash",
    "SSRF via webhook URL parameter",
    "Hardcoded AWS credential in config",
    "Deserialization gadget in pickle.loads",
    "Path traversal in file upload",
    "Race condition in token refresh",
    "Open redirect in oauth callback",
    "Weak crypto MD5 in password hash",
]
_SERVICES = ["payment-svc", "auth-svc", "billing-api", "frontend", "search-svc"]


def synth_event_data(i: int) -> Dict[str, Any]:
    return {
        "finding_id": f"f_bench_{i:06d}_{uuid.uuid4().hex[:6]}",
        "title": _TITLES[i % len(_TITLES)],
        "severity": _SEVERITIES[i % len(_SEVERITIES)],
        "cve_id": _CVE_TEMPLATES[i % len(_CVE_TEMPLATES)].format(1000 + (i % 9000)),
        "service_name": _SERVICES[i % len(_SERVICES)],
        "asset_criticality": "high" if i % 3 == 0 else "medium",
        "tenant": "bench-org",
    }


# ---------------------------------------------------------------------------
# Benchmark driver
# ---------------------------------------------------------------------------

async def run_bench(
    *,
    events: int,
    mode: str,
    concurrency: int,
    signals_db: str,
    tg_db: str,
    with_agentdb_async: bool = False,
) -> Dict[str, Any]:
    # Configure AgentDB based on mode BEFORE any imports of the loop module
    if mode == "deterministic-agentdb":
        os.environ["FIXOPS_AGENTDB_ENABLED"] = "1"
    else:
        os.environ["FIXOPS_AGENTDB_ENABLED"] = "0"

    # Per-run isolated queue DB so we can measure drain rate without polluting
    # the shared .aldeci/agentdb_async_queue.db
    if with_agentdb_async:
        queue_db = signals_db.replace("signals_", "agentdb_queue_")
        os.environ["FIXOPS_AGENTDB_QUEUE_DB"] = queue_db
        # Force-reload module-level singleton state in agentdb_bridge
        try:
            Path(queue_db).unlink()
        except FileNotFoundError:
            pass

    # Force a fresh signals DB for this run
    os.environ["FIXOPS_LLM_LOOP_SIGNALS_DB"] = signals_db
    os.environ["FIXOPS_LLM_LOOP_TG_DB"] = tg_db
    os.environ["FIXOPS_LLM_LEARNING_LOOP"] = "1"

    # Wipe pre-existing tmp DBs so we measure cold-start numbers per mode
    for path in (signals_db, tg_db):
        try:
            Path(path).unlink()
        except FileNotFoundError:
            pass

    # Now import — any cached singletons from prior runs are reset
    from core.event_bus import Event, EventBus, EventType  # noqa: WPS433
    from core import llm_learning_loop as loop_mod  # noqa: WPS433

    # Reset bus + loop singletons for clean measurement
    EventBus.reset_instance()
    loop_mod._loop_singleton = None  # type: ignore[attr-defined]

    bus = EventBus.get_instance()

    # Build the loop. For real-council mode let CouncilFactory run; for
    # deterministic modes, force the fallback by monkey-patching the builder.
    if mode in ("deterministic", "deterministic-agentdb"):
        original_builder = loop_mod._build_council_with_fallback

        def _force_deterministic() -> Any:
            from core.llm_council import CouncilMember, LLMCouncilEngine
            from core.llm_providers import DeterministicLLMProvider

            det = DeterministicLLMProvider("deterministic-bench", style="consensus")
            return LLMCouncilEngine(
                members=[
                    CouncilMember(
                        provider=det,
                        expertise="vulnerability_assessment",
                        weight=1.0,
                        name="deterministic-bench",
                    )
                ],
                chairman=det,
                escalation_provider=None,
                confidence_threshold=0.0,
                max_disagreement=99,
            )

        loop_mod._build_council_with_fallback = _force_deterministic  # type: ignore[assignment]

    loop = loop_mod.LLMLearningLoop(
        tg_db_path=tg_db,
        signals_db_path=signals_db,
        org_id="bench-org",
    )
    loop.start()

    # Wrap _on_event to capture per-event latency (emit -> handler complete)
    latencies_ms: List[float] = []
    original_on_event = loop._on_event

    async def timed_on_event(event: Event) -> None:
        t0 = time.perf_counter()
        await original_on_event(event)
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

    loop._on_event = timed_on_event  # type: ignore[assignment]
    # Re-subscribe with the wrapped handler (loop.start() registered the
    # original; we replace the registry entry)
    bus._subscribers[EventType.FINDING_CREATED.value] = [timed_on_event]

    # Snapshot agentdb file size BEFORE
    agentdb_path = Path(_PROJECT_ROOT) / "agentdb.rvf"
    agentdb_before = agentdb_path.stat().st_size if agentdb_path.exists() else 0

    # ----------------------------------------------------------------------
    # Fire all events
    # ----------------------------------------------------------------------
    print(
        f"[bench] mode={mode} events={events} concurrency={concurrency} "
        f"signals_db={signals_db}"
    )
    t_start = time.perf_counter()

    semaphore = asyncio.Semaphore(concurrency)

    async def emit_one(i: int) -> None:
        async with semaphore:
            await bus.emit(
                Event(
                    event_type=EventType.FINDING_CREATED,
                    source="bench",
                    data=synth_event_data(i),
                    org_id="bench-org",
                )
            )

    # Schedule all emits
    await asyncio.gather(*(emit_one(i) for i in range(events)))

    t_end = time.perf_counter()
    total_s = t_end - t_start

    # ----------------------------------------------------------------------
    # Metrics
    # ----------------------------------------------------------------------
    agentdb_after = agentdb_path.stat().st_size if agentdb_path.exists() else 0
    agentdb_delta_bytes = agentdb_after - agentdb_before

    summary = loop.signals_summary()
    verdict_count = summary["verdicts"]
    pair_count = summary["pairs"]

    def pct(p: float) -> float:
        if not latencies_ms:
            return 0.0
        s = sorted(latencies_ms)
        k = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
        return s[k]

    metrics = {
        "mode": mode,
        "events_fired": events,
        "events_processed": loop._processed,
        "concurrency": concurrency,
        "total_seconds": round(total_s, 4),
        "throughput_evt_per_sec": round(events / total_s, 2) if total_s > 0 else 0.0,
        "latency_ms": {
            "count": len(latencies_ms),
            "p50": round(pct(50), 3),
            "p95": round(pct(95), 3),
            "p99": round(pct(99), 3),
            "mean": round(statistics.mean(latencies_ms), 3) if latencies_ms else 0.0,
            "max": round(max(latencies_ms), 3) if latencies_ms else 0.0,
            "min": round(min(latencies_ms), 3) if latencies_ms else 0.0,
        },
        "db_writes": {
            "verdicts": verdict_count,
            "pairs": pair_count,
            "verdicts_per_sec": round(verdict_count / total_s, 2) if total_s > 0 else 0.0,
            "pairs_per_sec": round(pair_count / total_s, 2) if total_s > 0 else 0.0,
        },
        "agentdb": {
            "bytes_written": agentdb_delta_bytes,
            "bytes_per_sec": round(agentdb_delta_bytes / total_s, 0) if total_s > 0 else 0,
            "enabled": os.environ.get("FIXOPS_AGENTDB_ENABLED", "0") == "1",
        },
        "loop_state": {
            "last_error": loop._last_error,
            "running": loop._running,
        },
    }

    # ----------------------------------------------------------------------
    # Optional: drain the AgentDB async queue and report drain throughput.
    # Demonstrates that the council hot path latency does NOT include the
    # MiniLM compute — that work is deferred to the queue worker.
    # ----------------------------------------------------------------------
    if with_agentdb_async:
        try:
            # Reset bridge module so it picks up the per-run queue DB env var
            import importlib

            from trustgraph import agentdb_bridge as _bridge_mod  # noqa: WPS433

            importlib.reload(_bridge_mod)
            stats_before = _bridge_mod.async_queue_stats()

            drain_t0 = time.perf_counter()
            drain_result = _bridge_mod.drain_async_queue(max_jobs=10000)
            drain_seconds = time.perf_counter() - drain_t0

            metrics["agentdb_async_queue"] = {
                "queue_db": os.environ.get("FIXOPS_AGENTDB_QUEUE_DB"),
                "stats_before_drain": stats_before,
                "stats_after_drain": _bridge_mod.async_queue_stats(),
                "drain_processed": drain_result.get("processed", 0),
                "drain_failed": drain_result.get("failed", 0),
                "drain_remaining": drain_result.get("remaining", 0),
                "drain_seconds": round(drain_seconds, 4),
                "drain_throughput_per_sec": (
                    round(drain_result.get("processed", 0) / drain_seconds, 2)
                    if drain_seconds > 0
                    else 0.0
                ),
            }
        except Exception as exc:  # noqa: BLE001
            metrics["agentdb_async_queue"] = {"error": f"{type(exc).__name__}: {exc}"}

    loop.stop()
    return metrics


def text_chart(metrics_list: List[Dict[str, Any]]) -> str:
    """Render a small ASCII bar chart of throughput across modes."""
    if not metrics_list:
        return ""
    max_tput = max(m["throughput_evt_per_sec"] for m in metrics_list) or 1.0
    out = ["Throughput (events/sec):"]
    width = 40
    for m in metrics_list:
        bar = "#" * max(1, int(width * m["throughput_evt_per_sec"] / max_tput))
        out.append(
            f"  {m['mode']:30s} | {bar} {m['throughput_evt_per_sec']:8.2f} evt/s"
        )
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=1000)
    ap.add_argument(
        "--mode",
        choices=("deterministic", "deterministic-agentdb", "real-council", "all"),
        default="all",
    )
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--out", type=str, default="-")
    ap.add_argument(
        "--with-agentdb-async",
        action="store_true",
        help=(
            "Force the AgentDB write path through the persistent async queue "
            "(see scripts/agentdb_async_worker.py). The benchmark drains the "
            "queue post-run and reports queue stats + drain rate."
        ),
    )
    args = ap.parse_args()

    modes = (
        ["deterministic", "deterministic-agentdb", "real-council"]
        if args.mode == "all"
        else [args.mode]
    )

    all_metrics: List[Dict[str, Any]] = []
    tmpdir = tempfile.mkdtemp(prefix="bench_llm_loop_")
    for i, mode in enumerate(modes):
        signals_db = os.path.join(tmpdir, f"signals_{mode}.db")
        tg_db = os.path.join(tmpdir, f"trustgraph_{mode}.db")
        try:
            metrics = asyncio.run(
                run_bench(
                    events=args.events,
                    mode=mode,
                    concurrency=args.concurrency,
                    signals_db=signals_db,
                    tg_db=tg_db,
                    with_agentdb_async=args.with_agentdb_async,
                )
            )
            all_metrics.append(metrics)
            print(json.dumps(metrics, indent=2))
        except Exception as exc:  # noqa: BLE001
            print(f"[bench] mode={mode} FAILED: {type(exc).__name__}: {exc}")
            all_metrics.append({"mode": mode, "error": f"{type(exc).__name__}: {exc}"})

    print()
    print(text_chart([m for m in all_metrics if "throughput_evt_per_sec" in m]))

    if args.out and args.out != "-":
        Path(args.out).write_text(json.dumps(all_metrics, indent=2))
        print(f"[bench] wrote results to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
