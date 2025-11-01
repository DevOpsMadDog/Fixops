"""Comprehensive tests for evidence indexer and portfolio search."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.evidence_indexer import EvidenceBundleIndexer
from core.portfolio_search import PortfolioSearchEngine, PortfolioSearchResult


@pytest.fixture
def temp_evidence_dir(tmp_path: Path) -> Path:
    """Create temporary evidence directory with sample bundles."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    bundles = [
        {
            "run_id": "run-001",
            "mode": "production",
            "design_summary": {
                "app_name": "payment-service",
                "app_type": "microservice",
                "org_id": "org-123",
            },
            "sbom_summary": {
                "component_count": 50,
                "components": [
                    {"name": "express", "version": "4.18.0"},
                    {"name": "lodash", "version": "4.17.21"},
                ],
                "top_components": [
                    {"name": "express", "version": "4.18.0"},
                    {"name": "lodash", "version": "4.17.21"},
                ],
            },
            "cve_summary": {
                "total_cves": 5,
                "cves": [
                    {"id": "CVE-2024-1234", "severity": "HIGH"},
                    {"id": "CVE-2024-5678", "severity": "MEDIUM"},
                ],
                "critical_cves": [
                    {"id": "CVE-2024-1234", "severity": "HIGH"},
                ],
            },
            "severity_overview": {
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 1,
            },
            "compliance_status": {
                "SOC2": {"compliant": True},
                "ISO27001": {"compliant": False},
            },
        },
        {
            "run_id": "run-002",
            "mode": "production",
            "design_summary": {
                "app_name": "user-service",
                "app_type": "microservice",
                "org_id": "org-123",
            },
            "sbom_summary": {
                "component_count": 30,
                "components": [
                    {"name": "react", "version": "18.0.0"},
                    {"name": "axios", "version": "1.0.0"},
                ],
                "top_components": [
                    {"name": "react", "version": "18.0.0"},
                    {"name": "axios", "version": "1.0.0"},
                ],
            },
            "cve_summary": {
                "total_cves": 3,
                "cves": [
                    {"id": "CVE-2024-9999", "severity": "LOW"},
                ],
                "critical_cves": [],
            },
            "severity_overview": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 2,
            },
            "compliance_status": {
                "SOC2": {"compliant": True},
                "ISO27001": {"compliant": True},
            },
        },
        {
            "run_id": "run-003",
            "mode": "staging",
            "design_summary": {
                "app_name": "analytics-service",
                "app_type": "batch",
                "org_id": "org-456",
            },
            "sbom_summary": {
                "component_count": 75,
                "components": [
                    {"name": "pandas", "version": "2.0.0"},
                    {"name": "numpy", "version": "1.24.0"},
                    {"name": "lodash", "version": "4.17.21"},
                ],
                "top_components": [
                    {"name": "pandas", "version": "2.0.0"},
                    {"name": "numpy", "version": "1.24.0"},
                    {"name": "lodash", "version": "4.17.21"},
                ],
            },
            "cve_summary": {
                "total_cves": 10,
                "cves": [
                    {"id": "CVE-2024-1234", "severity": "HIGH"},
                    {"id": "CVE-2024-7777", "severity": "CRITICAL"},
                ],
                "critical_cves": [
                    {"id": "CVE-2024-7777", "severity": "CRITICAL"},
                ],
            },
            "severity_overview": {
                "critical": 2,
                "high": 3,
                "medium": 3,
                "low": 2,
            },
            "compliance_status": {
                "SOC2": {"compliant": False},
                "ISO27001": {"compliant": False},
            },
        },
    ]

    for bundle in bundles:
        run_dir = evidence_dir / bundle["mode"] / bundle["run_id"]
        run_dir.mkdir(parents=True, exist_ok=True)
        bundle_file = run_dir / "bundle.json"
        bundle_file.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    return evidence_dir


class TestEvidenceBundleIndexer:
    """Test evidence bundle indexer."""

    def test_indexer_creation(self):
        """Test creating evidence bundle indexer."""
        indexer = EvidenceBundleIndexer(vector_store_type="in_memory")

        assert indexer.vector_store_type == "in_memory"
        assert indexer.collection_name == "evidence_bundles"

    def test_build_summary_text(self, temp_evidence_dir: Path):
        """Test building summary text from bundle."""
        indexer = EvidenceBundleIndexer(vector_store_type="in_memory")

        bundle_file = temp_evidence_dir / "production" / "run-001" / "bundle.json"
        bundle_data = json.loads(bundle_file.read_text(encoding="utf-8"))

        summary_text = indexer._build_summary_text(bundle_data)

        assert "payment-service" in summary_text
        assert "microservice" in summary_text
        assert "Components: 50" in summary_text
        assert "Vulnerabilities: 5" in summary_text
        assert "express" in summary_text
        assert "lodash" in summary_text

    def test_extract_metadata(self, temp_evidence_dir: Path):
        """Test extracting metadata from bundle."""
        indexer = EvidenceBundleIndexer(vector_store_type="in_memory")

        bundle_file = temp_evidence_dir / "production" / "run-001" / "bundle.json"
        bundle_data = json.loads(bundle_file.read_text(encoding="utf-8"))

        metadata = indexer._extract_metadata(bundle_data, bundle_file)

        assert metadata["run_id"] == "run-001"
        assert metadata["mode"] == "production"
        assert metadata["app_name"] == "payment-service"
        assert metadata["app_type"] == "microservice"
        assert metadata["org_id"] == "org-123"
        assert metadata["component_count"] == 50
        assert metadata["total_cves"] == 5
        assert metadata["critical_count"] == 1
        assert metadata["high_count"] == 2

    def test_index_evidence_bundle(self, temp_evidence_dir: Path):
        """Test indexing evidence bundle."""
        indexer = EvidenceBundleIndexer(vector_store_type="in_memory")

        bundle_file = temp_evidence_dir / "production" / "run-001" / "bundle.json"
        bundle_data = json.loads(bundle_file.read_text(encoding="utf-8"))

        indexer.index_evidence_bundle(bundle_file, bundle_data)

    def test_index_all_bundles(self, temp_evidence_dir: Path):
        """Test indexing all evidence bundles."""
        indexer = EvidenceBundleIndexer(vector_store_type="in_memory")

        indexed_count = indexer.index_all_bundles(temp_evidence_dir)

        assert indexed_count == 3

    def test_search_similar_bundles(self, temp_evidence_dir: Path):
        """Test searching for similar bundles."""
        indexer = EvidenceBundleIndexer(vector_store_type="in_memory")

        indexer.index_all_bundles(temp_evidence_dir)

        matches = indexer.search_similar_bundles(
            "payment service with vulnerabilities", top_k=5
        )

        assert isinstance(matches, list)


class TestPortfolioSearchEngine:
    """Test portfolio search engine."""

    def test_search_engine_creation(self, temp_evidence_dir: Path):
        """Test creating portfolio search engine."""
        engine = PortfolioSearchEngine(evidence_dir=temp_evidence_dir)

        assert engine.evidence_dir == temp_evidence_dir
        assert len(engine._index) == 3

    def test_search_by_component(self, temp_evidence_dir: Path):
        """Test searching portfolio by component."""
        engine = PortfolioSearchEngine(evidence_dir=temp_evidence_dir)

        results = engine.search_by_component("lodash")

        assert len(results) == 2  # payment-service and analytics-service
        assert all(isinstance(r, PortfolioSearchResult) for r in results)
        assert any(r.app_name == "payment-service" for r in results)
        assert any(r.app_name == "analytics-service" for r in results)

    def test_search_by_cve(self, temp_evidence_dir: Path):
        """Test searching portfolio by CVE."""
        engine = PortfolioSearchEngine(evidence_dir=temp_evidence_dir)

        results = engine.search_by_cve("CVE-2024-1234")

        assert len(results) == 2  # payment-service and analytics-service
        assert all(isinstance(r, PortfolioSearchResult) for r in results)
        assert any(r.app_name == "payment-service" for r in results)
        assert any(r.app_name == "analytics-service" for r in results)

    def test_search_by_app(self, temp_evidence_dir: Path):
        """Test searching portfolio by application name."""
        engine = PortfolioSearchEngine(evidence_dir=temp_evidence_dir)

        results = engine.search_by_app("payment")

        assert len(results) == 1
        assert results[0].app_name == "payment-service"
        assert results[0].org_id == "org-123"

    def test_search_by_org(self, temp_evidence_dir: Path):
        """Test searching portfolio by organization."""
        engine = PortfolioSearchEngine(evidence_dir=temp_evidence_dir)

        results = engine.search_by_org("org-123")

        assert len(results) == 2  # payment-service and user-service
        assert all(r.org_id == "org-123" for r in results)

    def test_search_multi_dimensional(self, temp_evidence_dir: Path):
        """Test multi-dimensional portfolio search."""
        engine = PortfolioSearchEngine(evidence_dir=temp_evidence_dir)

        results = engine.search_multi_dimensional(
            component="lodash",
            min_critical=1,
        )

        assert len(results) == 2
        app_names = {r.app_name for r in results}
        assert "payment-service" in app_names
        assert "analytics-service" in app_names

    def test_search_multi_dimensional_complex(self, temp_evidence_dir: Path):
        """Test complex multi-dimensional search."""
        engine = PortfolioSearchEngine(evidence_dir=temp_evidence_dir)

        results = engine.search_multi_dimensional(
            org="org-123",
            cve="CVE-2024-1234",
        )

        assert len(results) == 1  # Only payment-service
        assert results[0].app_name == "payment-service"
        assert results[0].org_id == "org-123"

    def test_get_inventory_summary(self, temp_evidence_dir: Path):
        """Test getting portfolio inventory summary."""
        engine = PortfolioSearchEngine(evidence_dir=temp_evidence_dir)

        summary = engine.get_inventory_summary()

        assert summary["total_applications"] == 3
        assert summary["total_organizations"] == 2
        assert summary["total_components"] == 155  # 50 + 30 + 75
        assert (
            summary["unique_components"] == 6
        )  # express, lodash, react, axios, pandas, numpy
        assert summary["total_vulnerabilities"] == 18  # 5 + 3 + 10
        assert (
            summary["unique_vulnerabilities"] == 4
        )  # CVE-2024-1234, CVE-2024-5678, CVE-2024-9999, CVE-2024-7777
        assert summary["total_critical"] == 3  # 1 + 0 + 2
        assert summary["total_high"] == 5  # 2 + 0 + 3

    def test_portfolio_search_result_to_dict(self):
        """Test converting portfolio search result to dictionary."""
        result = PortfolioSearchResult(
            run_id="run-001",
            app_name="test-app",
            org_id="org-123",
            mode="production",
            component_count=50,
            total_cves=5,
            critical_count=1,
            high_count=2,
            matched_components=["lodash"],
            matched_cves=["CVE-2024-1234"],
            bundle_path="/path/to/bundle.json",
        )

        result_dict = result.to_dict()

        assert result_dict["run_id"] == "run-001"
        assert result_dict["app_name"] == "test-app"
        assert result_dict["org_id"] == "org-123"
        assert result_dict["component_count"] == 50
        assert result_dict["total_cves"] == 5
        assert result_dict["matched_components"] == ["lodash"]
        assert result_dict["matched_cves"] == ["CVE-2024-1234"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
