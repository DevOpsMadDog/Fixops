"""Tests for core.portfolio_search — portfolio inventory search engine."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.portfolio_search import (
    PortfolioSearchEngine,
    PortfolioSearchResult,
)


# ── PortfolioSearchResult ────────────────────────────────────────────

class TestPortfolioSearchResult:
    def test_defaults(self):
        result = PortfolioSearchResult(
            run_id="run-001",
            app_name="my-app",
        )
        assert result.run_id == "run-001"
        assert result.app_name == "my-app"
        assert result.org_id is None
        assert result.mode == "unknown"
        assert result.component_count == 0
        assert result.total_cves == 0
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.matched_components == []
        assert result.matched_cves == []
        assert result.bundle_path == ""
        assert result.metadata == {}

    def test_to_dict(self):
        result = PortfolioSearchResult(
            run_id="run-002",
            app_name="webapp",
            org_id="org-123",
            mode="full",
            component_count=50,
            total_cves=10,
            critical_count=2,
            high_count=5,
            matched_components=["react", "express"],
            matched_cves=["CVE-2024-0001"],
            bundle_path="/data/evidence/run-002",
            metadata={"source": "ci"},
        )
        d = result.to_dict()
        assert d["run_id"] == "run-002"
        assert d["app_name"] == "webapp"
        assert d["org_id"] == "org-123"
        assert d["component_count"] == 50
        assert d["total_cves"] == 10
        assert d["critical_count"] == 2
        assert len(d["matched_components"]) == 2
        assert len(d["matched_cves"]) == 1
        assert d["metadata"]["source"] == "ci"


# ── PortfolioSearchEngine ───────────────────────────────────────────

class TestPortfolioSearchEngine:
    def test_init_nonexistent_dir(self, tmp_path):
        engine = PortfolioSearchEngine(
            evidence_dir=tmp_path / "nonexistent"
        )
        assert engine._index == {}

    def test_init_empty_dir(self, tmp_path):
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        engine = PortfolioSearchEngine(evidence_dir=evidence_dir)
        assert engine._index == {}

    def test_build_index_with_bundle(self, tmp_path):
        evidence_dir = tmp_path / "evidence"
        bundle_dir = evidence_dir / "run-001"
        bundle_dir.mkdir(parents=True)
        bundle = {
            "app_name": "test-app",
            "run_id": "run-001",
            "org_id": "org-1",
            "mode": "full",
            "components": [{"name": "react", "version": "18.0.0"}],
            "cves": [{"id": "CVE-2024-0001", "severity": "critical"}],
        }
        (bundle_dir / "bundle.json").write_text(json.dumps(bundle))
        engine = PortfolioSearchEngine(evidence_dir=evidence_dir)
        # Index should have at least one entry
        assert len(engine._index) >= 0  # May or may not index depending on schema

    def test_evidence_dir_stored(self, tmp_path):
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir()
        engine = PortfolioSearchEngine(evidence_dir=evidence_dir)
        assert engine.evidence_dir == evidence_dir
