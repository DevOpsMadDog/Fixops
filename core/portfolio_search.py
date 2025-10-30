"""Portfolio search and inventory query capabilities.

Enables cross-dimensional querying across SBOM, CVE, APP, org_id, component.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

LOGGER = logging.getLogger(__name__)


@dataclass
class PortfolioSearchResult:
    """Result from portfolio search query."""

    run_id: str
    app_name: str
    org_id: Optional[str] = None
    mode: str = "unknown"
    component_count: int = 0
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    matched_components: List[str] = field(default_factory=list)
    matched_cves: List[str] = field(default_factory=list)
    bundle_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "run_id": self.run_id,
            "app_name": self.app_name,
            "org_id": self.org_id,
            "mode": self.mode,
            "component_count": self.component_count,
            "total_cves": self.total_cves,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "matched_components": self.matched_components,
            "matched_cves": self.matched_cves,
            "bundle_path": self.bundle_path,
            "metadata": self.metadata,
        }


class PortfolioSearchEngine:
    """Search engine for portfolio inventory across multiple dimensions."""

    def __init__(self, evidence_dir: str | Path = "data/evidence"):
        """Initialize portfolio search engine.

        Parameters
        ----------
        evidence_dir:
            Directory containing evidence bundles.
        """
        self.evidence_dir = Path(evidence_dir)
        self.logger = logging.getLogger(__name__)
        self._index: Dict[str, Dict[str, Any]] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Build search index from evidence bundles."""
        if not self.evidence_dir.exists():
            self.logger.warning(
                "Evidence directory does not exist: %s", self.evidence_dir
            )
            return

        self.logger.info("Building portfolio search index")
        indexed_count = 0

        for bundle_file in self.evidence_dir.rglob("bundle.json"):
            try:
                bundle_data = json.loads(bundle_file.read_text(encoding="utf-8"))
                run_id = bundle_data.get("run_id", "unknown")

                design_summary = bundle_data.get("design_summary", {})
                sbom_summary = bundle_data.get("sbom_summary", {})
                cve_summary = bundle_data.get("cve_summary", {})
                severity_overview = bundle_data.get("severity_overview", {})

                self._index[run_id] = {
                    "run_id": run_id,
                    "app_name": design_summary.get("app_name", ""),
                    "app_type": design_summary.get("app_type", ""),
                    "org_id": design_summary.get("org_id", ""),
                    "mode": bundle_data.get("mode", "unknown"),
                    "component_count": sbom_summary.get("component_count", 0),
                    "components": self._extract_components(sbom_summary),
                    "total_cves": cve_summary.get("total_cves", 0),
                    "cves": self._extract_cves(cve_summary),
                    "critical_count": severity_overview.get("critical", 0),
                    "high_count": severity_overview.get("high", 0),
                    "medium_count": severity_overview.get("medium", 0),
                    "low_count": severity_overview.get("low", 0),
                    "bundle_path": str(bundle_file),
                    "bundle_data": bundle_data,
                }
                indexed_count += 1

            except Exception as exc:
                self.logger.error("Failed to index bundle %s: %s", bundle_file, exc)

        self.logger.info("Built portfolio search index with %d bundles", indexed_count)

    def _extract_components(self, sbom_summary: Dict[str, Any]) -> Set[str]:
        """Extract component names from SBOM summary."""
        components: Set[str] = set()

        for component in sbom_summary.get("components", []):
            if isinstance(component, dict):
                name = component.get("name", "")
                if name:
                    components.add(name.lower())

        for component in sbom_summary.get("top_components", []):
            if isinstance(component, dict):
                name = component.get("name", "")
                if name:
                    components.add(name.lower())

        return components

    def _extract_cves(self, cve_summary: Dict[str, Any]) -> Set[str]:
        """Extract CVE IDs from CVE summary."""
        cves: Set[str] = set()

        for cve in cve_summary.get("cves", []):
            if isinstance(cve, dict):
                cve_id = cve.get("id", "")
                if cve_id:
                    cves.add(cve_id.upper())

        for cve in cve_summary.get("critical_cves", []):
            if isinstance(cve, dict):
                cve_id = cve.get("id", "")
                if cve_id:
                    cves.add(cve_id.upper())

        return cves

    def search_by_component(self, component_name: str) -> List[PortfolioSearchResult]:
        """Search portfolio by component name.

        Parameters
        ----------
        component_name:
            Component name to search for.

        Returns
        -------
        List[PortfolioSearchResult]
            List of matching portfolio entries.
        """
        self.logger.info("Searching portfolio by component: %s", component_name)
        results: List[PortfolioSearchResult] = []
        component_lower = component_name.lower()

        for run_id, entry in self._index.items():
            if component_lower in entry["components"]:
                result = PortfolioSearchResult(
                    run_id=run_id,
                    app_name=entry["app_name"],
                    org_id=entry["org_id"],
                    mode=entry["mode"],
                    component_count=entry["component_count"],
                    total_cves=entry["total_cves"],
                    critical_count=entry["critical_count"],
                    high_count=entry["high_count"],
                    matched_components=[component_name],
                    bundle_path=entry["bundle_path"],
                )
                results.append(result)

        self.logger.info(
            "Found %d portfolio entries with component %s", len(results), component_name
        )
        return results

    def search_by_cve(self, cve_id: str) -> List[PortfolioSearchResult]:
        """Search portfolio by CVE ID.

        Parameters
        ----------
        cve_id:
            CVE ID to search for.

        Returns
        -------
        List[PortfolioSearchResult]
            List of matching portfolio entries.
        """
        self.logger.info("Searching portfolio by CVE: %s", cve_id)
        results: List[PortfolioSearchResult] = []
        cve_upper = cve_id.upper()

        for run_id, entry in self._index.items():
            if cve_upper in entry["cves"]:
                result = PortfolioSearchResult(
                    run_id=run_id,
                    app_name=entry["app_name"],
                    org_id=entry["org_id"],
                    mode=entry["mode"],
                    component_count=entry["component_count"],
                    total_cves=entry["total_cves"],
                    critical_count=entry["critical_count"],
                    high_count=entry["high_count"],
                    matched_cves=[cve_id],
                    bundle_path=entry["bundle_path"],
                )
                results.append(result)

        self.logger.info("Found %d portfolio entries with CVE %s", len(results), cve_id)
        return results

    def search_by_app(self, app_name: str) -> List[PortfolioSearchResult]:
        """Search portfolio by application name.

        Parameters
        ----------
        app_name:
            Application name to search for.

        Returns
        -------
        List[PortfolioSearchResult]
            List of matching portfolio entries.
        """
        self.logger.info("Searching portfolio by app: %s", app_name)
        results: List[PortfolioSearchResult] = []
        app_lower = app_name.lower()

        for run_id, entry in self._index.items():
            if app_lower in entry["app_name"].lower():
                result = PortfolioSearchResult(
                    run_id=run_id,
                    app_name=entry["app_name"],
                    org_id=entry["org_id"],
                    mode=entry["mode"],
                    component_count=entry["component_count"],
                    total_cves=entry["total_cves"],
                    critical_count=entry["critical_count"],
                    high_count=entry["high_count"],
                    bundle_path=entry["bundle_path"],
                )
                results.append(result)

        self.logger.info(
            "Found %d portfolio entries for app %s", len(results), app_name
        )
        return results

    def search_by_org(self, org_id: str) -> List[PortfolioSearchResult]:
        """Search portfolio by organization ID.

        Parameters
        ----------
        org_id:
            Organization ID to search for.

        Returns
        -------
        List[PortfolioSearchResult]
            List of matching portfolio entries.
        """
        self.logger.info("Searching portfolio by org: %s", org_id)
        results: List[PortfolioSearchResult] = []

        for run_id, entry in self._index.items():
            if entry["org_id"] == org_id:
                result = PortfolioSearchResult(
                    run_id=run_id,
                    app_name=entry["app_name"],
                    org_id=entry["org_id"],
                    mode=entry["mode"],
                    component_count=entry["component_count"],
                    total_cves=entry["total_cves"],
                    critical_count=entry["critical_count"],
                    high_count=entry["high_count"],
                    bundle_path=entry["bundle_path"],
                )
                results.append(result)

        self.logger.info("Found %d portfolio entries for org %s", len(results), org_id)
        return results

    def search_multi_dimensional(
        self,
        component: Optional[str] = None,
        cve: Optional[str] = None,
        app: Optional[str] = None,
        org: Optional[str] = None,
        min_critical: Optional[int] = None,
        min_high: Optional[int] = None,
    ) -> List[PortfolioSearchResult]:
        """Multi-dimensional portfolio search.

        Parameters
        ----------
        component:
            Optional component name filter.
        cve:
            Optional CVE ID filter.
        app:
            Optional application name filter.
        org:
            Optional organization ID filter.
        min_critical:
            Optional minimum critical vulnerability count.
        min_high:
            Optional minimum high vulnerability count.

        Returns
        -------
        List[PortfolioSearchResult]
            List of matching portfolio entries.
        """
        self.logger.info("Multi-dimensional portfolio search")
        results: List[PortfolioSearchResult] = []

        for run_id, entry in self._index.items():
            if component and component.lower() not in entry["components"]:
                continue

            if cve and cve.upper() not in entry["cves"]:
                continue

            if app and app.lower() not in entry["app_name"].lower():
                continue

            if org and entry["org_id"] != org:
                continue

            if min_critical is not None and entry["critical_count"] < min_critical:
                continue

            if min_high is not None and entry["high_count"] < min_high:
                continue

            result = PortfolioSearchResult(
                run_id=run_id,
                app_name=entry["app_name"],
                org_id=entry["org_id"],
                mode=entry["mode"],
                component_count=entry["component_count"],
                total_cves=entry["total_cves"],
                critical_count=entry["critical_count"],
                high_count=entry["high_count"],
                matched_components=[component] if component else [],
                matched_cves=[cve] if cve else [],
                bundle_path=entry["bundle_path"],
            )
            results.append(result)

        self.logger.info("Found %d portfolio entries matching filters", len(results))
        return results

    def get_inventory_summary(self) -> Dict[str, Any]:
        """Get portfolio inventory summary.

        Returns
        -------
        Dict[str, Any]
            Portfolio inventory summary.
        """
        total_apps = len(self._index)
        total_components = sum(
            entry["component_count"] for entry in self._index.values()
        )
        total_cves = sum(entry["total_cves"] for entry in self._index.values())
        total_critical = sum(entry["critical_count"] for entry in self._index.values())
        total_high = sum(entry["high_count"] for entry in self._index.values())

        all_components: Set[str] = set()
        all_cves: Set[str] = set()
        all_orgs: Set[str] = set()

        for entry in self._index.values():
            all_components.update(entry["components"])
            all_cves.update(entry["cves"])
            if entry["org_id"]:
                all_orgs.add(entry["org_id"])

        return {
            "total_applications": total_apps,
            "total_organizations": len(all_orgs),
            "total_components": total_components,
            "unique_components": len(all_components),
            "total_vulnerabilities": total_cves,
            "unique_vulnerabilities": len(all_cves),
            "total_critical": total_critical,
            "total_high": total_high,
            "top_components": sorted(
                [
                    (
                        comp,
                        sum(1 for e in self._index.values() if comp in e["components"]),
                    )
                    for comp in all_components
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
            "top_cves": sorted(
                [
                    (cve, sum(1 for e in self._index.values() if cve in e["cves"]))
                    for cve in all_cves
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }


__all__ = ["PortfolioSearchEngine", "PortfolioSearchResult"]
