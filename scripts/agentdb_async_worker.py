"""AgentDB async write worker daemon.

Drains the ``agentdb_write_queue`` (populated by
``trustgraph.agentdb_bridge.enqueue_council_verdict``) and runs the actual
MiniLM-encoded AgentDB writes off the council hot path.

Why a separate daemon (not just a daemon thread)?
-------------------------------------------------
Spawning one daemon thread per verdict (the original pattern) doesn't scale:

* Each thread runs the ~430 ms MiniLM encode.
* Under bulk load (1000+ verdicts) we'd have 1000 daemon threads contending
  for the GIL and each holding a sqlite connection — the council main thread
  may not be joined-blocked, but throughput collapses anyway because Python
  has only one CPU under the GIL.

By draining sequentially in a single dedicated process we:

* Bound concurrency to ``max_jobs`` per cycle (configurable, default 100).
* Pay the MiniLM model load cost ONCE per worker process, not per event.
* Get a durable queue: if the worker dies, jobs persist in
  ``.aldeci/agentdb_async_queue.db`` and resume on restart.

Usage
-----

    # One-shot drain (cron / systemd timer)
    python scripts/agentdb_async_worker.py --max-jobs 500

    # Long-running daemon, drains every 2s
    python scripts/agentdb_async_worker.py --interval 2

    # Stats only, no drain
    python scripts/agentdb_async_worker.py --stats

Env knobs (inherited from agentdb_bridge):
    FIXOPS_AGENTDB_QUEUE_DB    path to the queue DB (default .aldeci/agentdb_async_queue.db)
    FIXOPS_AGENTDB_PATH        target memory_entries DB (default .swarm/memory.db)
    FIXOPS_AGENTDB_EMBED_MODEL "minilm" | "hash"  default minilm
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# sys.path setup — runnable from anywhere
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


def _drain_once(max_jobs: int) -> dict:
    """One drain pass. Returns the stats dict from drain_async_queue."""
    from trustgraph.agentdb_bridge import drain_async_queue

    return drain_async_queue(max_jobs=max_jobs)


def _print_stats() -> int:
    """Print queue depth and exit. Used for ops dashboards / cron monitoring."""
    from trustgraph.agentdb_bridge import async_queue_stats

    stats = async_queue_stats()
    print(json.dumps(stats, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentDB async write worker")
    ap.add_argument(
        "--max-jobs",
        type=int,
        default=100,
        help="Maximum jobs per drain cycle (default 100)",
    )
    ap.add_argument(
        "--interval",
        type=float,
        default=0,
        help=(
            "Drain interval in seconds (loop forever). "
            "0 = single drain then exit (default)."
        ),
    )
    ap.add_argument(
        "--stats",
        action="store_true",
        help="Print queue stats and exit (no drain).",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Only print summary on exit, not per-cycle.",
    )
    args = ap.parse_args()

    if args.stats:
        return _print_stats()

    cycles = 0
    total_processed = 0
    total_failed = 0
    t_start = time.perf_counter()

    try:
        while True:
            cycle_start = time.perf_counter()
            stats = _drain_once(args.max_jobs)
            cycles += 1
            total_processed += stats.get("processed", 0)
            total_failed += stats.get("failed", 0)
            elapsed_ms = (time.perf_counter() - cycle_start) * 1000.0

            if not args.quiet:
                print(
                    json.dumps(
                        {
                            "cycle": cycles,
                            "processed": stats.get("processed", 0),
                            "failed": stats.get("failed", 0),
                            "remaining": stats.get("remaining", 0),
                            "elapsed_ms": round(elapsed_ms, 1),
                        }
                    ),
                    flush=True,
                )

            if args.interval <= 0:
                # One-shot mode — drain everything currently queued, but
                # exit if a cycle made no progress (avoids spinning when
                # all remaining jobs are permanently failed).
                if stats.get("remaining", 0) == 0:
                    break
                if stats.get("processed", 0) == 0:
                    # No forward progress this cycle; remaining jobs are
                    # likely poisoned. Bail rather than spin.
                    break
                continue

            time.sleep(args.interval)
    except KeyboardInterrupt:
        if not args.quiet:
            print("interrupted", file=sys.stderr)

    total_elapsed = time.perf_counter() - t_start
    summary = {
        "summary": True,
        "cycles": cycles,
        "processed": total_processed,
        "failed": total_failed,
        "elapsed_seconds": round(total_elapsed, 3),
        "throughput_per_sec": (
            round(total_processed / total_elapsed, 2) if total_elapsed > 0 else 0.0
        ),
    }
    print(json.dumps(summary), flush=True)
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
