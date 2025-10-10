"""Utility helpers for overlay-driven pipeline modules."""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional

from core.configuration import OverlayConfig

if True:  # mypy hint, maintain runtime import
    from apps.api.normalizers import (
        NormalizedCNAPP,
        NormalizedCVEFeed,
        NormalizedSARIF,
        NormalizedSBOM,
        NormalizedVEX,
    )


@dataclass
class PipelineContext:
    """Context supplied to custom modules executed by the orchestrator."""

    design_rows: List[Dict[str, Any]]
    crosswalk: List[Dict[str, Any]]
    sbom: "NormalizedSBOM"
    sarif: "NormalizedSARIF"
    cve: "NormalizedCVEFeed"
    overlay: OverlayConfig
    result: MutableMapping[str, Any]
    context_summary: Optional[Mapping[str, Any]] = None
    compliance_status: Optional[Mapping[str, Any]] = None
    policy_summary: Optional[Mapping[str, Any]] = None
    ssdlc_assessment: Optional[Mapping[str, Any]] = None
    compliance_results: Optional[List[Dict[str, Any]]] = None
    vex: Optional["NormalizedVEX"] = None
    cnapp: Optional["NormalizedCNAPP"] = None


def _resolve_callable(entrypoint: str) -> Callable[[MutableMapping[str, Any], PipelineContext, Mapping[str, Any]], Any]:
    """Import a custom module callable from a string path."""

    if not entrypoint:
        raise ValueError("Custom module entrypoint must be a non-empty string")
    module_path: str
    attribute: str
    if ":" in entrypoint:
        module_path, attribute = entrypoint.split(":", 1)
    else:
        if "." not in entrypoint:
            raise ValueError(
                "Entrypoint must contain a module attribute, e.g. 'package.module:function'"
            )
        module_path, attribute = entrypoint.rsplit(".", 1)
    module = importlib.import_module(module_path)
    try:
        candidate = getattr(module, attribute)
    except AttributeError as exc:  # pragma: no cover - defensive guard
        raise ImportError(f"Entrypoint '{entrypoint}' is not importable") from exc
    if not callable(candidate):
        raise TypeError(f"Entrypoint '{entrypoint}' is not callable")
    return candidate  # type: ignore[return-value]


def execute_custom_modules(
    specs: Iterable[Mapping[str, Any]],
    context: PipelineContext,
) -> List[Dict[str, Any]]:
    """Execute custom modules defined in the overlay and collect outcomes."""

    outcomes: List[Dict[str, Any]] = []
    for spec in specs:
        if not isinstance(spec, Mapping):
            continue
        if not spec.get("enabled", True):
            outcomes.append(
                {
                    "name": spec.get("name") or spec.get("entrypoint"),
                    "status": "skipped",
                    "reason": "disabled",
                }
            )
            continue
        entrypoint = str(spec.get("entrypoint") or "").strip()
        if not entrypoint:
            outcomes.append(
                {
                    "name": spec.get("name") or "unknown",
                    "status": "error",
                    "error": "missing entrypoint",
                }
            )
            continue
        try:
            handler = _resolve_callable(entrypoint)
        except Exception as exc:  # pragma: no cover - surfaced via outcome
            outcomes.append(
                {
                    "name": spec.get("name") or entrypoint,
                    "status": "error",
                    "error": str(exc),
                }
            )
            continue
        config = spec.get("config") if isinstance(spec.get("config"), Mapping) else {}
        try:
            result = handler(context.result, context, config)
        except Exception as exc:  # pragma: no cover - module failures reported as outcome
            outcomes.append(
                {
                    "name": spec.get("name") or entrypoint,
                    "status": "error",
                    "error": str(exc),
                }
            )
            continue
        if isinstance(result, Mapping):
            context.result.update(result)
        outcomes.append(
            {
                "name": spec.get("name") or entrypoint,
                "status": "executed",
            }
        )
    return outcomes


__all__ = ["PipelineContext", "execute_custom_modules"]
