"""Indexes for correlating design rows with security artefacts."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping

from apps.api.normalizers import CVERecordSummary, SarifFinding, SBOMComponent

from .utils import (
    LookupTokens,
    build_finding_search_text,
    build_record_search_text,
    group_matches,
)


def build_component_index(
    components: Iterable[SBOMComponent],
) -> Dict[str, Mapping[str, Any]]:
    """Return a token → component index for SBOM lookups."""

    lookup: Dict[str, Mapping[str, Any]] = {}
    for component in components:
        name = getattr(component, "name", None)
        if not isinstance(name, str):
            continue
        token = name.strip().lower()
        if not token:
            continue
        lookup[token] = component.to_dict()
    return lookup


def build_finding_index(
    findings: Iterable[SarifFinding],
    tokens: LookupTokens,
) -> Dict[str, List[Mapping[str, Any]]]:
    """Return a token → findings index using the supplied design tokens."""

    return group_matches(
        findings,
        tokens.tokens,
        search=lambda finding: build_finding_search_text(finding.to_dict()),
        to_mapping=lambda finding: finding.to_dict(),
    )


def build_cve_index(
    records: Iterable[CVERecordSummary],
    tokens: LookupTokens,
) -> Dict[str, List[Mapping[str, Any]]]:
    """Return a token → CVE record index."""

    return group_matches(
        records,
        tokens.tokens,
        search=lambda record: build_record_search_text(record.to_dict()),
        to_mapping=lambda record: record.to_dict(),
    )
