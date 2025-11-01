"""Evidence bundle indexing to VectorDB for semantic search.

Implements hybrid storage: file storage (audit/compliance) + VectorDB (semantic search).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from core.vector_store import (
    BaseVectorStore,
    ChromaVectorStore,
    InMemoryVectorStore,
    VectorMatch,
    VectorRecord,
    VectorStoreError,
)

LOGGER = logging.getLogger(__name__)


class EvidenceBundleIndexer:
    """Index evidence bundles to VectorDB for semantic search."""

    def __init__(
        self,
        vector_store_type: str = "chroma",
        collection_name: str = "evidence_bundles",
        persist_directory: Optional[Path] = None,
    ):
        """Initialize evidence bundle indexer.

        Parameters
        ----------
        vector_store_type:
            Type of vector store ("chroma" or "in_memory").
        collection_name:
            Name of the vector store collection.
        persist_directory:
            Optional persist directory for ChromaDB.
        """
        self.vector_store_type = vector_store_type
        self.collection_name = collection_name
        self.persist_directory = persist_directory
        self.logger = logging.getLogger(__name__)

        self.store: BaseVectorStore
        if vector_store_type == "chroma":
            try:
                self.store = ChromaVectorStore(
                    collection_name=collection_name, persist_directory=persist_directory
                )
                self.logger.info("Using ChromaDB vector store")
            except VectorStoreError as e:
                self.logger.warning(
                    "ChromaDB not available (%s), falling back to in-memory store", e
                )
                self.store = InMemoryVectorStore()
                self.vector_store_type = "in_memory"
        else:
            self.store = InMemoryVectorStore()

    def index_evidence_bundle(
        self, bundle_path: str | Path, bundle_data: Mapping[str, Any]
    ) -> None:
        """Index an evidence bundle to VectorDB.

        Parameters
        ----------
        bundle_path:
            Path to the evidence bundle file.
        bundle_data:
            Evidence bundle data.
        """
        run_id = bundle_data.get("run_id", "unknown")

        summary_text = self._build_summary_text(bundle_data)

        metadata = self._extract_metadata(bundle_data, bundle_path)

        record = VectorRecord(
            identifier=run_id,
            text=summary_text,
            metadata=metadata,
        )

        self.store.index([record])
        self.logger.info("Indexed evidence bundle %s to VectorDB", run_id)

    def _build_summary_text(self, bundle_data: Mapping[str, Any]) -> str:
        """Build summary text for semantic search.

        Parameters
        ----------
        bundle_data:
            Evidence bundle data.

        Returns
        -------
        str
            Summary text for semantic search.
        """
        parts: List[str] = []

        design_summary = bundle_data.get("design_summary", {})
        if isinstance(design_summary, Mapping):
            app_name = design_summary.get("app_name", "")
            app_type = design_summary.get("app_type", "")
            if app_name:
                parts.append(f"Application: {app_name}")
            if app_type:
                parts.append(f"Type: {app_type}")

        sbom_summary = bundle_data.get("sbom_summary", {})
        if isinstance(sbom_summary, Mapping):
            component_count = sbom_summary.get("component_count", 0)
            if component_count:
                parts.append(f"Components: {component_count}")

            top_components = sbom_summary.get("top_components", [])
            if top_components:
                component_names = [c.get("name", "") for c in top_components[:5]]
                parts.append(f"Key components: {', '.join(component_names)}")

        cve_summary = bundle_data.get("cve_summary", {})
        if isinstance(cve_summary, Mapping):
            total_cves = cve_summary.get("total_cves", 0)
            if total_cves:
                parts.append(f"Vulnerabilities: {total_cves}")

            critical_cves = cve_summary.get("critical_cves", [])
            if critical_cves:
                cve_ids = [cve.get("id", "") for cve in critical_cves[:5]]
                parts.append(f"Critical CVEs: {', '.join(cve_ids)}")

        severity_overview = bundle_data.get("severity_overview", {})
        if isinstance(severity_overview, Mapping):
            critical = severity_overview.get("critical", 0)
            high = severity_overview.get("high", 0)
            medium = severity_overview.get("medium", 0)
            low = severity_overview.get("low", 0)
            parts.append(
                f"Severity: {critical} critical, {high} high, {medium} medium, {low} low"
            )

        compliance_status = bundle_data.get("compliance_status", {})
        if isinstance(compliance_status, Mapping):
            frameworks = []
            for framework, status in compliance_status.items():
                if isinstance(status, Mapping):
                    compliant = status.get("compliant", False)
                    frameworks.append(f"{framework}: {'✓' if compliant else '✗'}")
            if frameworks:
                parts.append(f"Compliance: {', '.join(frameworks)}")

        ssdlc_assessment = bundle_data.get("ssdlc_assessment", {})
        if isinstance(ssdlc_assessment, Mapping):
            stage_scores = []
            for stage, data in ssdlc_assessment.items():
                if isinstance(data, Mapping):
                    score = data.get("score", 0)
                    stage_scores.append(f"{stage}: {score}")
            if stage_scores:
                parts.append(f"SSDLC: {', '.join(stage_scores)}")

        return " | ".join(parts)

    def _extract_metadata(
        self, bundle_data: Mapping[str, Any], bundle_path: str | Path
    ) -> Dict[str, Any]:
        """Extract metadata for filtering.

        Parameters
        ----------
        bundle_data:
            Evidence bundle data.
        bundle_path:
            Path to the evidence bundle file.

        Returns
        -------
        Dict[str, Any]
            Metadata for filtering.
        """
        metadata: Dict[str, Any] = {
            "run_id": bundle_data.get("run_id", "unknown"),
            "mode": bundle_data.get("mode", "unknown"),
            "bundle_path": str(bundle_path),
        }

        design_summary = bundle_data.get("design_summary", {})
        if isinstance(design_summary, Mapping):
            metadata["app_name"] = design_summary.get("app_name", "")
            metadata["app_type"] = design_summary.get("app_type", "")
            metadata["org_id"] = design_summary.get("org_id", "")

        sbom_summary = bundle_data.get("sbom_summary", {})
        if isinstance(sbom_summary, Mapping):
            metadata["component_count"] = sbom_summary.get("component_count", 0)

        cve_summary = bundle_data.get("cve_summary", {})
        if isinstance(cve_summary, Mapping):
            metadata["total_cves"] = cve_summary.get("total_cves", 0)

        severity_overview = bundle_data.get("severity_overview", {})
        if isinstance(severity_overview, Mapping):
            metadata["critical_count"] = severity_overview.get("critical", 0)
            metadata["high_count"] = severity_overview.get("high", 0)
            metadata["medium_count"] = severity_overview.get("medium", 0)
            metadata["low_count"] = severity_overview.get("low", 0)

        compliance_status = bundle_data.get("compliance_status", {})
        if isinstance(compliance_status, Mapping):
            for framework, status in compliance_status.items():
                if isinstance(status, Mapping):
                    metadata[f"compliant_{framework}"] = status.get("compliant", False)

        return metadata

    def search_similar_bundles(
        self, query: str, top_k: int = 5, filters: Optional[Dict[str, Any]] = None
    ) -> List[VectorMatch]:
        """Search for similar evidence bundles.

        Parameters
        ----------
        query:
            Search query (natural language).
        top_k:
            Number of results to return.
        filters:
            Optional metadata filters.

        Returns
        -------
        List[VectorMatch]
            List of matching evidence bundles.
        """
        self.logger.info("Searching for similar evidence bundles: %s", query)
        matches = self.store.search(query, top_k=top_k)
        self.logger.info("Found %d similar evidence bundles", len(matches))
        return matches

    def index_all_bundles(self, evidence_dir: str | Path) -> int:
        """Index all evidence bundles in a directory.

        Parameters
        ----------
        evidence_dir:
            Directory containing evidence bundles.

        Returns
        -------
        int
            Number of bundles indexed.
        """
        evidence_path = Path(evidence_dir)
        if not evidence_path.exists():
            self.logger.warning("Evidence directory does not exist: %s", evidence_path)
            return 0

        indexed_count = 0

        for bundle_file in evidence_path.rglob("bundle.json"):
            try:
                bundle_data = json.loads(bundle_file.read_text(encoding="utf-8"))
                self.index_evidence_bundle(bundle_file, bundle_data)
                indexed_count += 1
            except Exception as exc:
                self.logger.error("Failed to index bundle %s: %s", bundle_file, exc)

        self.logger.info("Indexed %d evidence bundles", indexed_count)
        return indexed_count


__all__ = ["EvidenceBundleIndexer"]
