"""Minimal parser shim used for tests when lib4sbom is unavailable."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class SBOMParser:
    """Tiny subset of :mod:`lib4sbom` used in the tests."""

    def __init__(self, sbom_type: str = "auto") -> None:
        self._sbom_type = sbom_type
        self._document: Dict[str, Any] = {}

    def parse_string(self, payload: str) -> None:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            self._document = {}
        else:
            if isinstance(data, dict):
                self._document = data
            else:
                self._document = {"document": data}

    def get_packages(self) -> List[Dict[str, Any]]:
        candidates = (
            self._document.get("components") or self._document.get("packages") or []
        )
        if isinstance(candidates, list):
            return [item for item in candidates if isinstance(item, dict)]
        return []

    def get_relationships(self) -> List[Any]:
        relationships = self._document.get("relationships", [])
        return relationships if isinstance(relationships, list) else []

    def get_services(self) -> List[Any]:
        services = self._document.get("services", [])
        return services if isinstance(services, list) else []

    def get_vulnerabilities(self) -> List[Any]:
        vulns = self._document.get("vulnerabilities", [])
        return vulns if isinstance(vulns, list) else []

    def get_document(self) -> Dict[str, Any]:
        return dict(self._document)

    def get_type(self) -> str:
        bom_format = self._document.get("bomFormat")
        if isinstance(bom_format, str):
            return bom_format
        return self._sbom_type or "unknown"
