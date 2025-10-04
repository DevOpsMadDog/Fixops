from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from .normalizers import (
    CVERecordSummary,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    SBOMComponent,
    SarifFinding,
)


def _lower(value: Optional[str]) -> Optional[str]:
    return value.lower() if isinstance(value, str) else None


class PipelineOrchestrator:
    """Derive intermediate insights from the uploaded artefacts."""

    @staticmethod
    def _extract_component_name(row: Dict[str, Any]) -> Optional[str]:
        """Return the first non-empty component identifier in a design row."""

        for key in ("component", "Component", "service"):
            value = row.get(key)
            if isinstance(value, str):
                stripped = value.strip()
                if stripped:
                    return stripped
        return None

    @staticmethod
    def _build_finding_search_text(finding: SarifFinding) -> str:
        """Concatenate searchable portions of a SARIF finding once."""

        parts: List[str] = []
        if finding.file:
            parts.append(finding.file)
        if finding.message:
            parts.append(finding.message)
        if finding.rule_id:
            parts.append(finding.rule_id)
        analysis_target = finding.raw.get("analysisTarget") if finding.raw else None
        if analysis_target:
            try:
                parts.append(
                    json.dumps(
                        analysis_target,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            except TypeError:
                parts.append(str(analysis_target))
        return " ".join(parts)

    @staticmethod
    def _build_record_search_text(record: CVERecordSummary) -> str:
        parts: List[str] = []
        if record.cve_id:
            parts.append(record.cve_id)
        if record.title:
            parts.append(record.title)
        if record.severity:
            parts.append(record.severity)
        try:
            parts.append(
                json.dumps(record.raw, sort_keys=True, separators=(",", ":"))
            )
        except TypeError:
            parts.append(str(record.raw))
        return " ".join(parts)

    def _match_components(
        self,
        sbom_components: Iterable[SBOMComponent],
    ) -> Dict[str, SBOMComponent]:
        lookup: Dict[str, SBOMComponent] = {}
        for component in sbom_components:
            key = _lower(component.name)
            if key:
                lookup[key] = component
        return lookup

    def run(
        self,
        design_dataset: Dict[str, Any],
        sbom: NormalizedSBOM,
        sarif: NormalizedSARIF,
        cve: NormalizedCVEFeed,
    ) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = list(design_dataset.get("rows", []))

        design_components: List[str] = []
        tokens: Dict[str, Optional[str]] = {}
        for row in rows:
            name = self._extract_component_name(row)
            if name:
                design_components.append(name)
                tokens[name] = _lower(name)

        lookup_tokens = {
            token for token in tokens.values() if token
        }

        sbom_lookup = self._match_components(sbom.components)

        findings_by_level = Counter(
            finding.level or "none" for finding in sarif.findings
        )
        exploited_count = sum(1 for record in cve.records if record.exploited)

        finding_matches: Dict[str, List[dict[str, Any]]] = {
            token: [] for token in lookup_tokens
        }
        for finding in sarif.findings:
            payload = finding.to_dict()
            haystack = self._build_finding_search_text(finding).lower()
            for token in lookup_tokens:
                if token in haystack:
                    finding_matches[token].append(dict(payload))

        cve_matches: Dict[str, List[dict[str, Any]]] = {
            token: [] for token in lookup_tokens
        }
        for record in cve.records:
            payload = record.to_dict()
            haystack = self._build_record_search_text(record).lower()
            for token in lookup_tokens:
                if token in haystack:
                    cve_matches[token].append(dict(payload))

        crosswalk: List[dict[str, Any]] = []
        for row in rows:
            component_name = self._extract_component_name(row)
            token = tokens.get(component_name) if component_name else None
            match = sbom_lookup.get(token) if token else None

            crosswalk.append(
                {
                    "design_row": row,
                    "sbom_component": match.to_dict() if match else None,
                    "findings": list(finding_matches.get(token, [])),
                    "cves": list(cve_matches.get(token, [])),
                }
            )

        result: Dict[str, Any] = {
            "status": "ok",
            "design_summary": {
                "row_count": len(rows),
                "unique_components": sorted(set(design_components)),
            },
            "sbom_summary": {
                **sbom.metadata,
                "format": sbom.format,
                "document_name": sbom.document.get("name"),
            },
            "sarif_summary": {
                **sarif.metadata,
                "severity_breakdown": dict(findings_by_level),
                "tools": sarif.tool_names,
            },
            "cve_summary": {
                **cve.metadata,
                "exploited_count": exploited_count,
            },
            "crosswalk": crosswalk,
        }

        return result
