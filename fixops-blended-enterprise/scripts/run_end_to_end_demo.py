#!/usr/bin/env python3
"""Utility script to run the FixOps sample end-to-end demo pipeline.

The script executes the asynchronous `run_complete_demo` helper used by the
FastAPI demo endpoint and prints a concise summary of each stage, highlighting
any fallbacks that were triggered because optional third-party libraries are not
available in the local environment.
"""

import asyncio
import sys
import types
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

while True:
    try:
        from src.api.v1.sample_data_demo import run_complete_demo
        break
    except ModuleNotFoundError as exc:  # pragma: no cover - CLI fallback
        if exc.name == "fastapi":
            fastapi_stub = types.ModuleType("fastapi")

            class _StubRouter:  # minimal subset for import-time decorators
                def __init__(self, *args, **kwargs):
                    pass

                def get(self, *args, **kwargs):
                    def decorator(func):
                        return func

                    return decorator

                def post(self, *args, **kwargs):
                    def decorator(func):
                        return func

                    return decorator

            class _HTTPException(Exception):
                pass

            fastapi_stub.APIRouter = _StubRouter
            fastapi_stub.HTTPException = _HTTPException
            sys.modules["fastapi"] = fastapi_stub
            continue
        if exc.name == "pydantic":
            pydantic_stub = types.ModuleType("pydantic")

            class _BaseModel:  # minimal stub
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)

            pydantic_stub.BaseModel = _BaseModel
            sys.modules["pydantic"] = pydantic_stub
            continue
        if exc.name == "structlog":
            structlog_stub = types.ModuleType("structlog")

            class _Logger:
                def bind(self, **kwargs):
                    return self

                def info(self, *args, **kwargs):
                    pass

                def error(self, *args, **kwargs):
                    pass

                def warning(self, *args, **kwargs):
                    pass

            def get_logger(*args, **kwargs):
                return _Logger()

            structlog_stub.get_logger = get_logger
            sys.modules["structlog"] = structlog_stub
            continue
        raise


def _collect_stage_summary(stage_key: str, stage_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Derive a human-readable summary and status for a pipeline stage."""
    status = "success"
    notes: List[str] = []
    fallbacks: List[str] = list(stage_payload.get("fallbacks", []))

    if stage_payload.get("status") == "error":
        status = "error"
        notes.append(stage_payload.get("error", "Stage reported an unspecified error"))
    elif stage_key == "stage_1_input_parsing":
        parsing_results = stage_payload.get("parsing_results", {})
        if parsing_results.get("sbom_components_extracted", 0) == 0:
            notes.append("lib4sbom parser unavailable (SBOM components not extracted)")
    elif stage_key == "stage_2_processing_layer":
        processing_components = stage_payload.get("processing_components", {})
        for component_name, component_data in processing_components.items():
            output = component_data.get("output")
            component_status = None
            if isinstance(output, dict):
                component_status = output.get("status")
            if component_status and component_status.endswith("_unavailable"):
                notes.append(f"{component_name} missing dependency ({component_status})")
            if component_data.get("fallback_used"):
                fallbacks.append(
                    component_data.get(
                        "fallback_reason",
                        f"{component_name} used fallback implementation",
                    )
                )
            elif isinstance(output, dict) and output.get("fallback_used"):
                fallbacks.append(
                    output.get(
                        "fallback_reason",
                        f"{component_name} used fallback implementation",
                    )
                )
    elif stage_key == "stage_3_decision_layer":
        decision = stage_payload.get("final_decision", {})
        if decision.get("recommendation") is None:
            status = "error"
            notes.append("Decision engine did not produce a recommendation")
    elif stage_key == "stage_4_output_layer":
        outputs = stage_payload.get("output_formats", {})
        if not outputs:
            status = "error"
            notes.append("No output formats generated")
    elif stage_key == "stage_5_cicd_integration":
        integration = stage_payload.get("sample_decision_response", {})
        if not integration:
            status = "error"
            notes.append("CI/CD sample response missing")

    if status == "success" and notes:
        status = "warning"

    deduped_fallbacks = list(dict.fromkeys(fallbacks)) if fallbacks else []

    return {
        "Stage": stage_payload.get("stage", stage_key),
        "Status": status,
        "Notes": "; ".join(notes) if notes else "",
        "_notes": notes,
        "_fallbacks": deduped_fallbacks,
    }


def _render_table(rows: List[Dict[str, Any]]) -> str:
    """Render a simple GitHub-flavored table without external deps."""

    headers = ["Stage", "Status", "Notes"]
    widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            widths[header] = max(widths[header], len(str(row.get(header, ""))))

    def _format_row(row_values: List[str]) -> str:
        padded = [value.ljust(widths[header]) for value, header in zip(row_values, headers)]
        return f"| {' | '.join(padded)} |"

    header_row = _format_row(headers)
    separator = "| " + " | ".join("-" * widths[header] for header in headers) + " |"
    body_rows = [_format_row([str(row.get(header, "")) for header in headers]) for row in rows]
    return "\n".join([header_row, separator, *body_rows])


def _summarize(result: Dict[str, Any]) -> None:
    stages = result.get("processing_stages", {})
    summaries = [_collect_stage_summary(key, payload) for key, payload in stages.items()]

    total = len(summaries)
    successes = sum(1 for summary in summaries if summary["Status"] == "success")
    warnings = [summary for summary in summaries if summary["Status"] == "warning"]
    errors = [summary for summary in summaries if summary["Status"] == "error"]
    completed = total - len(errors)
    success_rate = (successes / total * 100) if total else 0
    fallbacks = [fallback for summary in summaries for fallback in summary.get("_fallbacks", [])]

    print("\n=== FixOps End-to-End Demo Summary ===")
    print(_render_table(summaries))
    print(f"\nCoverage: {completed}/{total} stages completed without fatal errors")
    print(f"Testing success rate: {success_rate:.1f}% ({successes}/{total} stages without warnings)")

    print("\nTesting scenarios covered:")
    for summary in summaries:
        status_label = summary["Status"].upper()
        print(f"  - {summary['Stage']}: {status_label}")

    if warnings:
        print("\nWarnings detected (fallbacks/partial coverage):")
        for summary in warnings:
            for note in summary.get("_notes", []):
                print(f"  - {summary['Stage']}: {note}")
    else:
        print("\nNo warnings detected.")

    if fallbacks:
        print("\nOptional dependency fallbacks used:")
        seen_fallbacks = set()
        for fallback in fallbacks:
            if fallback in seen_fallbacks:
                continue
            seen_fallbacks.add(fallback)
            print(f"  - {fallback}")
    else:
        print("\nNo optional dependency fallbacks used.")

    if errors:
        print("\nErrors requiring attention:")
        for summary in errors:
            for note in summary.get("_notes", []) or ["Stage reported an unspecified error"]:
                print(f"  - {summary['Stage']}: {note}")

    final_decision = stages.get("stage_3_decision_layer", {}).get("final_decision", {})
    if final_decision:
        print("\nFinal Decision Output:")
        print(f"  Recommendation: {final_decision.get('recommendation', 'unknown')}")
        print(f"  Confidence: {final_decision.get('confidence', 'n/a')}")
        reasoning = final_decision.get("reasoning")
        if reasoning:
            print(f"  Reasoning: {reasoning}")


def main() -> None:
    result = asyncio.run(run_complete_demo())
    _summarize(result)


if __name__ == "__main__":
    main()
