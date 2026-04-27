"""Backfill ReasoningBank from Phase-1 closed-loop DPO pairs.

Reads all rows from data/learning_signals.db (council_verdicts + feedback_pairs),
constructs Trajectory objects, and persists them via ReasoningBank.record().

DPO correctness logic
---------------------
All 5,196 verdicts: council_action=review, confidence=0.5, escalated=True.
All feedback_pairs:  chosen_action=remediate_high, rejected_action=review.

Interpretation: the council's "review" was overruled by the learning signal
(analyst preference or llm_learning_loop override to "remediate_high").
  - council was WRONG  → correctness_score = 0.0
  - outcome = "dpo_overruled"

This gives distill_patterns() a labeled dataset. We call distill_patterns()
with min_correctness=0.0 and min_dominance=0.50 to extract patterns from
overruled verdicts — the signal is "council always said review, but the right
answer was remediate_high" which is a learnable correction pattern.

Finding shape reconstruction
-----------------------------
The learning_signals.db does not store the original finding dict. We reconstruct
a synthetic finding from the verdict row:
  - finding_id from verdict_id / finding_id column
  - type inferred from finding_id prefix (SAST-, DAST-, SCA-, SMOKE-, etc.)
  - severity = "high" (feedback chosen_action = remediate_HIGH implies high)
  - escalated = True (all rows have escalation_reason)
  - council_member_count = 5 (5 member_votes in every raw_verdict)
  - kev / reachable / exploit_available = False (Phase-1 cold-start, no enrichment)
  - epss = 0.0
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path bootstrap — mirrors sitecustomize.py
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
for _sub in ("suite-core", "suite-core/core", "suite-core/trustgraph"):
    _p = _REPO_ROOT / _sub
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("backfill_rb")

# ---------------------------------------------------------------------------
# Imports (after path bootstrap)
# ---------------------------------------------------------------------------
from core.reasoning_bank import ReasoningBank, get_reasoning_bank  # noqa: E402

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_PATH = _REPO_ROOT / "data" / "learning_signals.db"
BATCH_SIZE = 200          # log progress every N rows
DISTILL_MIN_SUPPORT = 5   # lower than default 10 — we have uniform feature set
DISTILL_MIN_CORRECTNESS = 0.0  # all rows correctness=0.0; distill the pattern
DISTILL_MIN_DOMINANCE = 0.50


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_finding_type(finding_id: str) -> str:
    """Map finding_id prefix to a canonical finding type."""
    fid = (finding_id or "").upper()
    if fid.startswith("SAST-"):
        return "sast"
    if fid.startswith("DAST-"):
        return "dast"
    if fid.startswith("SCA-"):
        return "sca"
    if fid.startswith("SECRET-"):
        return "secret"
    if fid.startswith("CONTAINER-"):
        return "container"
    if fid.startswith("SMOKE-"):
        return "smoke_test"
    return "vuln"


def _parse_raw_verdict(raw_verdict_str: str) -> Dict[str, Any]:
    """Parse the raw_verdict JSON column; return {} on failure."""
    if not raw_verdict_str:
        return {}
    try:
        return json.loads(raw_verdict_str)
    except Exception:
        return {}


def _build_finding(
    verdict_id: str,
    finding_id: str,
    org_id: str,
    council_action: str,
    raw_verdict: Dict[str, Any],
    chosen_action: Optional[str],
) -> Dict[str, Any]:
    """Reconstruct a synthetic finding dict from verdict columns."""
    finding_type = _infer_finding_type(finding_id)
    # All Phase-1 verdicts were cold-start with no enrichment — no CWE/EPSS/KEV.
    # Severity is inferred from the DPO chosen_action: remediate_HIGH → "high".
    severity = "high" if (chosen_action or "").endswith("high") else "medium"

    return {
        "finding_id": finding_id,
        "id": finding_id,
        "type": finding_type,
        "category": finding_type,
        "severity": severity,
        "title": f"{finding_type.upper()} finding {finding_id}",
        "description": f"Phase-1 closed-loop finding from org={org_id}",
        "service_name": org_id,
        # Feature flags — Phase-1 had no enrichment
        "kev": False,
        "reachable": False,
        "exploit_available": False,
        "epss": 0.0,
        # Preserve council member count as metadata
        "council_member_count": len(raw_verdict.get("member_votes") or []),
    }


def _build_verdict(
    verdict_id: str,
    council_action: str,
    confidence: float,
    reasoning: str,
    raw_verdict: Dict[str, Any],
    chosen_action: Optional[str],
) -> Dict[str, Any]:
    """Build a verdict dict from the DB row."""
    escalated = bool(raw_verdict.get("escalated", False))
    # DPO overrule: council said X, feedback says chosen_action is better
    # Store both so the bank has full DPO signal.
    return {
        "action": council_action,
        "recommended_action": council_action,
        "confidence": confidence,
        "reasoning": reasoning or "",
        "escalated": escalated,
        "escalation_reason": raw_verdict.get("escalation_reason", ""),
        "member_votes": raw_verdict.get("member_votes", []),
        "dpo_chosen_action": chosen_action,
        "verdict_id": verdict_id,
    }


def _ts_to_ms(ts_str: str) -> int:
    """Convert ISO8601 timestamp string to milliseconds since epoch."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# Main backfill
# ---------------------------------------------------------------------------

def load_rows(db_path: Path) -> List[Tuple]:
    """Load all council_verdicts LEFT JOIN feedback_pairs."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT
                cv.verdict_id,
                cv.finding_id,
                cv.org_id,
                cv.council_action,
                cv.confidence,
                cv.reasoning,
                cv.raw_verdict,
                cv.created_at,
                fp.chosen_action,
                fp.rejected_action,
                fp.pair_source,
                fp.metadata AS pair_metadata
            FROM council_verdicts cv
            LEFT JOIN feedback_pairs fp ON fp.verdict_id = cv.verdict_id
            ORDER BY cv.created_at ASC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def backfill(bank: ReasoningBank, rows: List[Dict]) -> Dict[str, Any]:
    """Iterate rows and call bank.record() for each.

    Returns summary dict: {total, success, failed, skipped, elapsed_s}
    """
    total = len(rows)
    success = 0
    failed = 0
    skipped = 0
    t0 = time.time()

    log.info("Starting backfill of %d rows into ReasoningBank...", total)

    for i, row in enumerate(rows, 1):
        verdict_id = row["verdict_id"]
        finding_id = row["finding_id"]
        org_id = row["org_id"]
        council_action = row["council_action"]
        confidence = float(row["confidence"] or 0.5)
        reasoning = row["reasoning"] or ""
        raw_verdict = _parse_raw_verdict(row["raw_verdict"])
        chosen_action = row.get("chosen_action")
        created_at = row.get("created_at", "")

        # Determine correctness: council said "review", DPO says "remediate_high"
        # Council was overruled → correctness = 0.0
        # If no feedback pair exists, we treat it as unknown (None) — no label.
        if chosen_action is not None:
            # DPO overrule present
            if chosen_action != council_action:
                outcome = "dpo_overruled"
                correctness_score = 0.0
            else:
                outcome = "dpo_confirmed"
                correctness_score = 1.0
        else:
            # No feedback pair — completed verdict, label unknown
            outcome = "completed_no_feedback"
            correctness_score = None

        finding = _build_finding(
            verdict_id=verdict_id,
            finding_id=finding_id,
            org_id=org_id,
            council_action=council_action,
            raw_verdict=raw_verdict,
            chosen_action=chosen_action,
        )

        verdict = _build_verdict(
            verdict_id=verdict_id,
            council_action=council_action,
            confidence=confidence,
            reasoning=reasoning,
            raw_verdict=raw_verdict,
            chosen_action=chosen_action,
        )

        context = {
            "org_id": org_id,
            "tenant": org_id,
            "source": "phase1_closed_loop_backfill",
            "pair_source": row.get("pair_source") or "",
            "created_at": created_at,
        }

        result = bank.record(
            finding=finding,
            verdict=verdict,
            context=context,
            outcome=outcome,
            correctness_score=correctness_score,
        )

        if result is not None:
            success += 1
        else:
            # Bridge may be unavailable or build failed
            failed += 1
            if failed <= 5:
                log.warning("record() returned None for verdict_id=%s", verdict_id)

        if i % BATCH_SIZE == 0 or i == total:
            elapsed = time.time() - t0
            rate = i / elapsed if elapsed > 0 else 0
            log.info(
                "Progress: %d/%d  success=%d  failed=%d  %.1f rows/s",
                i, total, success, failed, rate,
            )

    elapsed = time.time() - t0
    return {
        "total": total,
        "success": success,
        "failed": failed,
        "skipped": skipped,
        "elapsed_s": round(elapsed, 2),
    }


def run_distillation(bank: ReasoningBank) -> List[Any]:
    """Run distill_patterns() with relaxed thresholds for Phase-1 data."""
    log.info(
        "Running distill_patterns(min_support=%d, min_correctness=%.2f, "
        "min_dominance=%.2f)...",
        DISTILL_MIN_SUPPORT,
        DISTILL_MIN_CORRECTNESS,
        DISTILL_MIN_DOMINANCE,
    )
    patterns = bank.distill_patterns(
        min_support=DISTILL_MIN_SUPPORT,
        min_correctness=DISTILL_MIN_CORRECTNESS,
        min_dominance=DISTILL_MIN_DOMINANCE,
    )
    log.info("Distillation complete: %d patterns emitted", len(patterns))
    return patterns


def print_top_patterns(patterns: List[Any], n: int = 5) -> None:
    """Print the top-N patterns by confidence * support."""
    if not patterns:
        log.warning("No patterns distilled — check min_support threshold.")
        return
    print("\n" + "=" * 70)
    print(f"TOP {min(n, len(patterns))} DISTILLED PATTERNS")
    print("=" * 70)
    for i, p in enumerate(patterns[:n], 1):
        print(f"\n[{i}] Pattern ID : {p.pattern_id}")
        print(f"    Predicate  : {p.feature_predicate}")
        print(f"    Action     : {p.verdict_action}")
        print(f"    Support    : {p.support}")
        print(f"    Correctness: {p.correctness:.4f}")
        print(f"    Confidence : {p.confidence:.4f}")
    print("=" * 70 + "\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if not DB_PATH.exists():
        log.error("learning_signals.db not found at %s", DB_PATH)
        sys.exit(1)

    # ── Before state ──────────────────────────────────────────────────────
    bank = get_reasoning_bank()
    before_health = bank.health()
    log.info("BEFORE  records=%d  patterns_cached=%d",
             before_health["records"], before_health["patterns_cached"])

    # ── Load rows ─────────────────────────────────────────────────────────
    rows = load_rows(DB_PATH)
    log.info("Loaded %d rows from learning_signals.db", len(rows))

    # DPO pair stats
    with_feedback = sum(1 for r in rows if r.get("chosen_action"))
    log.info("Rows with DPO feedback: %d  (%.1f%%)",
             with_feedback, 100 * with_feedback / max(len(rows), 1))

    # ── Backfill ──────────────────────────────────────────────────────────
    summary = backfill(bank, rows)

    after_health = bank.health()
    log.info(
        "AFTER   records=%d  patterns_cached=%d  (bridge_failures=%d)",
        after_health["records"], after_health["patterns_cached"],
        after_health["failures"],
    )

    print("\n--- BACKFILL SUMMARY ---")
    print(f"  Total rows     : {summary['total']}")
    print(f"  Success        : {summary['success']}")
    print(f"  Failed         : {summary['failed']}")
    print(f"  Elapsed        : {summary['elapsed_s']}s")
    print(f"  Bank records+  : {after_health['records'] - before_health['records']}")

    # ── Distillation ──────────────────────────────────────────────────────
    patterns = run_distillation(bank)

    after_distill_health = bank.health()
    print(f"\n  Patterns distilled: {len(patterns)}")
    print(f"  Distillations run : {after_distill_health['distillations']}")

    print_top_patterns(patterns, n=5)

    # ── Write JSON export ─────────────────────────────────────────────────
    export_path = _REPO_ROOT / "data" / "reasoning_patterns_v1.json"
    pattern_dicts = [p.to_dict() for p in patterns]
    export_path.write_text(json.dumps(pattern_dicts, indent=2))
    log.info("Patterns exported to %s", export_path)

    # ── Final report ──────────────────────────────────────────────────────
    print("\n--- FINAL STATE ---")
    final = bank.health()
    print(f"  ReasoningBank records : {final['records']}")
    print(f"  Patterns cached       : {final['patterns_cached']}")
    print(f"  Bridge available      : {final['bridge'].get('available', '?')}")
    print(f"  Failures              : {final['failures']}")

    if summary["failed"] > 0:
        log.warning(
            "%d records failed to write — AgentDB bridge may be partially "
            "unavailable. Check suite-core/trustgraph/agentdb_bridge.py config.",
            summary["failed"],
        )

    log.info("Backfill complete.")


if __name__ == "__main__":
    main()
