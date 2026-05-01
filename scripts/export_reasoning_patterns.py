#!/usr/bin/env python3
"""Export the top-N distilled ReasoningBank patterns to JSON.

Usage::

    python scripts/export_reasoning_patterns.py [--top 50] [--out PATH]
                                                [--min-support 10]
                                                [--min-correctness 0.70]

The output JSON is the cheap fallback consumed by the Phase-2 student model:
the student tries to match a finding against these patterns *before*
spending a full council convene budget.

Output schema::

    {
      "schema": "reasoning_patterns.v1",
      "generated_at_ms": 1730000000000,
      "patterns_count": 50,
      "min_support": 10,
      "min_correctness": 0.70,
      "patterns": [
        {
          "pattern_id": "pattern::remediate_critical::cwe=CWE-79&...",
          "predicate": {"cwe": "CWE-79", "kev": true, ...},
          "verdict_action": "remediate_critical",
          "support": 82,
          "correctness": 0.94,
          "confidence": 0.89,
          "sample_trajectory_ids": ["traj_...", "traj_..."]
        },
        ...
      ]
    }
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict

# Make suite-core importable when invoked directly from repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
for _sub in ("suite-core", "suite-api"):
    _p = _REPO_ROOT / _sub
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--top",
        type=int,
        default=50,
        help="Maximum number of patterns to emit (default 50).",
    )
    p.add_argument(
        "--min-support",
        type=int,
        default=10,
        help="Minimum number of trajectories per pattern (default 10).",
    )
    p.add_argument(
        "--min-correctness",
        type=float,
        default=0.70,
        help="Minimum mean correctness_score for a pattern (default 0.70).",
    )
    p.add_argument(
        "--min-dominance",
        type=float,
        default=0.60,
        help="Minimum verdict_action dominance share (default 0.60).",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=_REPO_ROOT / "data" / "reasoning_patterns_v1.json",
        help="Output path.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    _setup_logging(args.verbose)
    logger = logging.getLogger("export_reasoning_patterns")

    from core.reasoning_bank import get_reasoning_bank

    bank = get_reasoning_bank()
    health = bank.health()
    logger.info(
        "ReasoningBank health: %s",
        {k: v for k, v in health.items() if k != "bridge"},
    )

    patterns = bank.distill_patterns(
        min_support=args.min_support,
        min_correctness=args.min_correctness,
        min_dominance=args.min_dominance,
        max_patterns=args.top,
    )
    logger.info("Distilled %d patterns", len(patterns))

    out_payload: Dict[str, Any] = {
        "schema": "reasoning_patterns.v1",
        "generated_at_ms": int(time.time() * 1000),
        "patterns_count": len(patterns),
        "min_support": args.min_support,
        "min_correctness": args.min_correctness,
        "min_dominance": args.min_dominance,
        "bridge_health": health.get("bridge", {}),
        "patterns": [p.to_dict() for p in patterns],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out_payload, indent=2, default=str))
    logger.info("Wrote %d patterns to %s", len(patterns), args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
