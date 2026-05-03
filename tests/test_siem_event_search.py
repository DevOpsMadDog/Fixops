"""Tests for SIEM event search — GET /api/v1/siem/events/search.

Covers:
  1. Basic keyword match in raw_data
  2. Keyword match in parsed_fields
  3. No-match returns empty list
  4. Tenant isolation (org_id scoping)
  5. severity + keyword combined filter
  6. limit param respected
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from core.siem_integration_engine import SIEMIntegrationEngine
from apps.api.siem_integration_router import router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_engine(tmp_path: Path) -> SIEMIntegrationEngine:
    """Fresh engine backed by a temp DB."""
    return SIEMIntegrationEngine(db_path=str(tmp_path / "siem_search_test.db"))


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """FastAPI TestClient wired to a fresh engine instance."""
    import apps.api.siem_integration_router as _mod

    engine = SIEMIntegrationEngine(db_path=str(tmp_path / "siem_router_test.db"))
    monkeypatch.setattr(_mod, "_engine", engine)

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _register_source(engine: SIEMIntegrationEngine, org: str = "org1") -> str:
    src = engine.register_siem_source(org, {"name": "test-src", "source_type": "syslog"})
    return src["id"]


def _ingest(
    engine: SIEMIntegrationEngine,
    org: str,
    source_id: str,
    raw_data: dict,
    severity: str = "info",
    event_type: str = "auth",
    parsed_fields: dict | None = None,
) -> dict:
    return engine.ingest_siem_event(
        org,
        {
            "source_id": source_id,
            "event_type": event_type,
            "severity": severity,
            "raw_data": raw_data,
            "parsed_fields": parsed_fields,
        },
    )


# ---------------------------------------------------------------------------
# Engine-level unit tests
# ---------------------------------------------------------------------------


class TestSearchEventsEngine:
    def test_keyword_match_raw_data(self, tmp_engine: SIEMIntegrationEngine) -> None:
        """search_events finds event whose raw_data contains the keyword."""
        sid = _register_source(tmp_engine)
        _ingest(tmp_engine, "org1", sid, {"message": "failed login for root"}, severity="high")
        _ingest(tmp_engine, "org1", sid, {"message": "routine heartbeat ok"}, severity="info")

        hits = tmp_engine.search_events("org1", q="failed login")
        assert len(hits) == 1
        raw = hits[0]["raw_data"]
        assert "failed login" in json.dumps(raw)

    def test_keyword_match_parsed_fields(self, tmp_engine: SIEMIntegrationEngine) -> None:
        """search_events finds event whose parsed_fields contains the keyword."""
        sid = _register_source(tmp_engine)
        _ingest(
            tmp_engine,
            "org1",
            sid,
            {"message": "generic event"},
            parsed_fields={"user": "alice", "action": "sudo_exec"},
        )
        _ingest(tmp_engine, "org1", sid, {"message": "other event"})

        hits = tmp_engine.search_events("org1", q="sudo_exec")
        assert len(hits) == 1
        pf = hits[0].get("parsed_fields") or {}
        assert pf.get("action") == "sudo_exec"

    def test_no_match_returns_empty(self, tmp_engine: SIEMIntegrationEngine) -> None:
        """search_events returns [] when no events match the keyword."""
        sid = _register_source(tmp_engine)
        _ingest(tmp_engine, "org1", sid, {"message": "nothing relevant"})

        hits = tmp_engine.search_events("org1", q="XYZZY_NOMATCH_99")
        assert hits == []

    def test_tenant_isolation(self, tmp_engine: SIEMIntegrationEngine) -> None:
        """search_events must not return events belonging to a different org."""
        sid1 = _register_source(tmp_engine, "org-alpha")
        sid2 = _register_source(tmp_engine, "org-beta")
        _ingest(tmp_engine, "org-alpha", sid1, {"message": "secret alpha event"})
        _ingest(tmp_engine, "org-beta", sid2, {"message": "beta noise"})

        hits = tmp_engine.search_events("org-beta", q="secret alpha")
        assert hits == []

        hits_alpha = tmp_engine.search_events("org-alpha", q="secret alpha")
        assert len(hits_alpha) == 1

    def test_combined_severity_filter(self, tmp_engine: SIEMIntegrationEngine) -> None:
        """search_events respects severity filter alongside keyword."""
        sid = _register_source(tmp_engine)
        _ingest(tmp_engine, "org1", sid, {"message": "brute force detected"}, severity="critical")
        _ingest(tmp_engine, "org1", sid, {"message": "brute force low noise"}, severity="low")

        hits = tmp_engine.search_events("org1", q="brute force", severity="critical")
        assert len(hits) == 1
        assert hits[0]["severity"] == "critical"

    def test_limit_respected(self, tmp_engine: SIEMIntegrationEngine) -> None:
        """search_events returns at most `limit` results."""
        sid = _register_source(tmp_engine)
        for i in range(10):
            _ingest(tmp_engine, "org1", sid, {"message": f"repeated-keyword event-{i}"})

        hits = tmp_engine.search_events("org1", q="repeated-keyword", limit=3)
        assert len(hits) == 3


# ---------------------------------------------------------------------------
# Router-level HTTP tests
# ---------------------------------------------------------------------------


class TestSearchEventsRouter:
    def test_http_keyword_match(self, client: TestClient) -> None:
        """GET /events/search?q=... returns matching events via HTTP."""
        import apps.api.siem_integration_router as _mod

        engine: SIEMIntegrationEngine = _mod._engine  # type: ignore[assignment]
        sid = _register_source(engine)
        _ingest(engine, "default", sid, {"message": "lateral movement suspected"}, severity="high")

        resp = client.get("/api/v1/siem/events/search", params={"q": "lateral movement"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["q"] == "lateral movement"
        assert len(body["events"]) == 1

    def test_http_no_match(self, client: TestClient) -> None:
        """GET /events/search?q=... returns empty list when nothing matches."""
        resp = client.get(
            "/api/v1/siem/events/search",
            params={"q": "NOTHINGHERE_99999", "org_id": "default"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["events"] == []

    def test_http_missing_q_returns_422(self, client: TestClient) -> None:
        """GET /events/search without ?q= must return 422 Unprocessable Entity."""
        resp = client.get("/api/v1/siem/events/search")
        assert resp.status_code == 422
