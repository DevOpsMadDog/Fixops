"""Multica #4066 — empty endpoint #37: /api/v1/pbom wired to PipelineBOMEngine.

pipeline_bom_router was never mounted in app.py. Fix: add import + include_router.
"""
import os
import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")

_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)


def test_pipeline_bom_engine_importable(tmp_path):
    """PipelineBOMEngine must import and instantiate without error."""
    from core.pipeline_bom_engine import PipelineBOMEngine
    engine = PipelineBOMEngine(db_path=str(tmp_path / "pbom_test.db"))
    assert engine is not None


def test_pipeline_bom_stats_returns_dict(tmp_path):
    """PipelineBOMEngine.stats() returns a dict — proves engine is real."""
    from core.pipeline_bom_engine import PipelineBOMEngine
    engine = PipelineBOMEngine(db_path=str(tmp_path / "pbom_test.db"))
    result = engine.stats(org_id="test-org-37")
    assert isinstance(result, dict)


def test_pipeline_bom_router_mounted():
    """GET /api/v1/pbom/stats must be reachable (not 404) — router is mounted."""
    from fastapi.testclient import TestClient
    from apps.api.app import create_app
    client = TestClient(create_app(), headers={"X-API-Key": _TOKEN})
    resp = client.get("/api/v1/pbom/stats", params={"org_id": "test-org-37"})
    assert resp.status_code != 404, f"Route not mounted: {resp.status_code}"
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
