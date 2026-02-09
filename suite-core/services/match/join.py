"""Join helpers for correlating design rows with indexed artefacts."""

from __future__ import annotations

from typing import Any, Iterable, List, Mapping

from domain import CrosswalkRow

from .utils import LookupTokens


def build_crosswalk(
    rows: Iterable[Mapping[str, Any]],
    tokens: LookupTokens,
    *,
    component_index: Mapping[str, Mapping[str, Any]],
    finding_index: Mapping[str, List[Mapping[str, Any]]],
    cve_index: Mapping[str, List[Mapping[str, Any]]],
) -> List[CrosswalkRow]:
    """Construct the crosswalk rows for the supplied artefacts."""

    crosswalk: List[CrosswalkRow] = []
    for index, row in enumerate(rows):
        token = tokens.token_by_index.get(index)
        component = component_index.get(token) if token else None
        findings = finding_index.get(token, []) if token else []
        cves = cve_index.get(token, []) if token else []
        crosswalk.append(
            CrosswalkRow(
                design_index=index,
                design_row=dict(row),
                sbom_component=(
                    dict(component) if isinstance(component, Mapping) else component
                ),
                findings=tuple(dict(item) for item in findings),
                cves=tuple(dict(item) for item in cves),
            )
        )
    return crosswalk
