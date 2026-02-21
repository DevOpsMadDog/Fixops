"""Replay golden regression CVE cases against the FixOps decision engine."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any, Dict


def _bootstrap_path() -> None:
    root = Path(__file__).resolve().parents[1]
    src_path = root / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))


_bootstrap_path()

from core.services.enterprise.decision_engine import DecisionEngine  # noqa: E402
from core.services.enterprise.golden_regression_store import (  # noqa: E402
    GoldenRegressionStore,
)


def _format_confidence(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.2f}"


def _format_delta(delta: Dict[str, Any]) -> str:
    confidence_delta = delta.get("confidence_delta")
    if confidence_delta is None:
        return "n/a"
    sign = "+" if confidence_delta >= 0 else ""
    return f"{sign}{confidence_delta:.2f}"


async def main() -> None:
    engine = DecisionEngine()
    store = GoldenRegressionStore()

    report = await store.evaluate(engine, initialize_engine=True)
    summary = report["summary"]

    print("FixOps Golden Regression Report")
    print("=" * 34)
    print(
        f"Total cases: {summary['total_cases']} | Matches: {summary['matches']} | "
        f"Mismatches: {summary['mismatches']} | Accuracy: {summary['accuracy']:.1%}"
    )
    print()

    for case in report["cases"]:
        status = "✅" if case["match"] else "❌"
        expected = case["expected"]
        actual = case["actual"]
        delta = case["delta"]

        print(
            f"{status} {case['case_id']} ({case.get('cve_id', 'n/a')}): "
            f"expected {expected['decision']} (conf {_format_confidence(expected.get('confidence'))}) vs "
            f"actual {actual.get('decision', 'UNKNOWN')} (conf {_format_confidence(actual.get('confidence'))})"
        )
        print(
            f"    Δ decision: {'match' if case['match'] else 'changed'} | "
            f"Δ confidence: {_format_delta(delta)}"
        )
        if actual.get("reasoning"):
            print(f"    Reasoning: {actual['reasoning']}")
        if case.get("metadata"):
            print(f"    Metadata: {case['metadata']}")
        print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted")
