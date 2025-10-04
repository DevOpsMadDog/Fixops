from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from .normalizers import (
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

    def _match_components(
        self,
        design_rows: Iterable[Dict[str, Any]],
        sbom_components: Iterable[SBOMComponent],
    ) -> Dict[str, SBOMComponent]:
        lookup: Dict[str, SBOMComponent] = {}
        for component in sbom_components:
            key = _lower(component.name)
            if key:
                lookup[key] = component
        return lookup

    def _group_findings(
        self, design_name: str, findings: Iterable[SarifFinding]
    ) -> List[dict[str, Any]]:
        results: List[dict[str, Any]] = []
        token = _lower(design_name)
        for finding in findings:
            haystack = "".join(
                str(part or "")
                for part in (
                    finding.file,
                    json.dumps(finding.raw.get("analysisTarget", {})),
                )
            )
            if token and token in haystack.lower():
                results.append(finding.to_dict())
        return results

    def _group_cves(
        self, design_name: str, records: Iterable
    ) -> List[dict[str, Any]]:
        token = _lower(design_name)
        grouped: List[dict[str, Any]] = []
        for record in records:
            serialised = json.dumps(record.raw)
            if token and token in serialised.lower():
                grouped.append(record.to_dict())
        return grouped

    def run(
        self,
        design_dataset: Dict[str, Any],
        sbom: NormalizedSBOM,
        sarif: NormalizedSARIF,
        cve: NormalizedCVEFeed,
    ) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = list(design_dataset.get("rows", []))
        design_components = [
            row.get("component")
            or row.get("Component")
            or row.get("service")
            for row in rows
        ]
        design_components = [name for name in design_components if name]

        sbom_lookup = self._match_components(rows, sbom.components)

        findings_by_level = Counter(
            finding.level or "none" for finding in sarif.findings
        )
        exploited_records = [record for record in cve.records if record.exploited]

        crosswalk: List[dict[str, Any]] = []
        for row in rows:
            component_name = (
                row.get("component")
                or row.get("Component")
                or row.get("service")
            )
            match = sbom_lookup.get(_lower(component_name)) if component_name else None
            matched_findings = (
                self._group_findings(component_name, sarif.findings)
                if component_name
                else []
            )
            matched_cves = (
                self._group_cves(component_name, cve.records)
                if component_name
                else []
            )

            crosswalk.append(
                {
                    "design_row": row,
                    "sbom_component": match.to_dict() if match else None,
                    "findings": matched_findings,
                    "cves": matched_cves,
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
                "exploited_count": len(exploited_records),
            },
            "crosswalk": crosswalk,
        }

        return result
