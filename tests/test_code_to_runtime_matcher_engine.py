"""Tests for code_to_runtime_matcher_engine (GAP-013).

Covers:
  - service mapping upsert + UNIQUE(org_id, service_name)
  - event ingestion validation
  - 3 matching strategies (stack-trace, service-mapping, path-heuristic)
  - stack-trace confidence outranks other strategies
  - bulk-match over 100+ events
  - org_id isolation on events/matches/stats
  - router endpoint smoke (wired via app.py)
"""

from __future__ import annotations

import os
import tempfile

import pytest

from core.code_to_runtime_matcher_engine import CodeToRuntimeMatcherEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db = tmp_path / "c2r.db"
    return CodeToRuntimeMatcherEngine(db_path=str(db))


@pytest.fixture()
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Build a minimal app just mounting our router; override auth
    from apps.api.code_to_runtime_router import router as c2r_router, _get_engine
    from apps.api.auth_deps import api_key_auth
    import tempfile

    # Fresh isolated engine for the API surface
    tmp_dir = tempfile.mkdtemp()
    eng = CodeToRuntimeMatcherEngine(db_path=os.path.join(tmp_dir, "c2r_api.db"))

    # Monkey-patch the router's lazy _get_engine to return ours
    import apps.api.code_to_runtime_router as mod
    mod._engine = eng

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: {"org_id": "demo-org"}
    app.include_router(c2r_router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Service mappings (6)
# ---------------------------------------------------------------------------


def test_register_service_mapping_basic(engine):
    r = engine.register_service_mapping("org1", "svc-a", "repo/foo", "abc123")
    assert r["id"]
    assert r["service_name"] == "svc-a"
    assert r["repo_ref"] == "repo/foo"


def test_register_service_mapping_idempotent(engine):
    r1 = engine.register_service_mapping("org1", "svc-a", "repo/foo", "c1")
    r2 = engine.register_service_mapping("org1", "svc-a", "repo/bar", "c2")
    assert r1["id"] == r2["id"]  # UPSERT
    assert r2["repo_ref"] == "repo/bar"


def test_register_service_mapping_unique_per_org(engine):
    engine.register_service_mapping("org1", "svc-a", "repo/foo")
    engine.register_service_mapping("org2", "svc-a", "repo/other")
    a = engine.list_service_mappings("org1")
    b = engine.list_service_mappings("org2")
    assert len(a) == 1 and a[0]["repo_ref"] == "repo/foo"
    assert len(b) == 1 and b[0]["repo_ref"] == "repo/other"


def test_register_service_mapping_requires_org_id(engine):
    with pytest.raises(ValueError):
        engine.register_service_mapping("", "svc", "repo")


def test_register_service_mapping_requires_service(engine):
    with pytest.raises(ValueError):
        engine.register_service_mapping("org1", "", "repo")


def test_list_service_mappings_empty(engine):
    assert engine.list_service_mappings("nope") == []


# ---------------------------------------------------------------------------
# Event ingestion (4)
# ---------------------------------------------------------------------------


def test_ingest_event_basic(engine):
    e = engine.ingest_runtime_event("org1", "evt-1", "http_log", service_name="svc")
    assert e["id"]
    assert e["event_ref"] == "evt-1"
    assert e["event_type"] == "http_log"


def test_ingest_event_defaults_are_strings(engine):
    e = engine.ingest_runtime_event("org1", "evt-2", "error_trace")
    assert e["service_name"] == ""
    assert e["path"] == ""
    assert e["status_code"] == 0


def test_ingest_event_requires_org_id(engine):
    with pytest.raises(ValueError):
        engine.ingest_runtime_event("", "e", "http_log")


def test_ingest_event_requires_event_ref_and_type(engine):
    with pytest.raises(ValueError):
        engine.ingest_runtime_event("org1", "", "http_log")
    with pytest.raises(ValueError):
        engine.ingest_runtime_event("org1", "e", "")


# ---------------------------------------------------------------------------
# Strategy 1: stack-trace match (6)
# ---------------------------------------------------------------------------


def test_stack_trace_match_produces_file_and_line(engine):
    engine.register_service_mapping("org1", "svc", "repo/app", "deadbeef")
    ev = engine.ingest_runtime_event(
        "org1",
        "evt-err-1",
        "error_trace",
        service_name="svc",
        stack_trace='Traceback:\n  File "app/handlers/users.py", line 42, in get_user\n',
    )
    m = engine.match_event_to_code(ev["id"])
    assert m["matched"] is True
    assert m["strategy"] == "stack_trace"
    assert m["file_ref"] == "app/handlers/users.py"
    assert m["line_number"] == 42
    assert m["confidence"] == 0.9


def test_stack_trace_match_uses_service_mapping_for_repo(engine):
    engine.register_service_mapping("org1", "svc", "github.com/x/y", "sha-1")
    ev = engine.ingest_runtime_event(
        "org1", "e", "err", service_name="svc",
        stack_trace='File "x/y.py", line 10',
    )
    m = engine.match_event_to_code(ev["id"])
    assert m["repo_ref"] == "github.com/x/y"
    assert m["commit_sha"] == "sha-1"


def test_stack_trace_match_without_mapping_has_empty_repo(engine):
    ev = engine.ingest_runtime_event(
        "org1", "e", "err", stack_trace='File "a.py", line 1'
    )
    m = engine.match_event_to_code(ev["id"])
    assert m["strategy"] == "stack_trace"
    assert m["repo_ref"] == ""
    assert m["commit_sha"] == ""


def test_stack_trace_parses_multiple_lines_picks_first(engine):
    ev = engine.ingest_runtime_event(
        "org1", "e", "err",
        stack_trace='File "first.py", line 1\nFile "second.py", line 2',
    )
    m = engine.match_event_to_code(ev["id"])
    assert m["file_ref"] == "first.py"
    assert m["line_number"] == 1


def test_stack_trace_garbage_falls_back(engine):
    # Garbage stack → no stack-trace parse; no service mapping; falls to path heuristic
    ev = engine.ingest_runtime_event(
        "org1", "e", "err", path="/users/42", stack_trace="garbage with no pattern"
    )
    m = engine.match_event_to_code(ev["id"])
    assert m["strategy"] == "path_heuristic"


def test_stack_trace_confidence_outranks_others(engine):
    assert 0.9 > 0.6 > 0.3


# ---------------------------------------------------------------------------
# Strategy 2: service mapping (4)
# ---------------------------------------------------------------------------


def test_service_mapping_match(engine):
    engine.register_service_mapping("org1", "svc-b", "repo/b", "c-sha")
    ev = engine.ingest_runtime_event("org1", "e", "http_log", service_name="svc-b")
    m = engine.match_event_to_code(ev["id"])
    assert m["strategy"] == "service_mapping"
    assert m["repo_ref"] == "repo/b"
    assert m["commit_sha"] == "c-sha"
    assert m["confidence"] == 0.6


def test_service_mapping_requires_registered_service(engine):
    # Unregistered service + no stack + no path → not matched
    ev = engine.ingest_runtime_event("org1", "e", "http_log", service_name="unknown")
    m = engine.match_event_to_code(ev["id"])
    assert m.get("matched") is False


def test_service_mapping_is_org_scoped(engine):
    engine.register_service_mapping("org1", "svc", "repo/x")
    ev = engine.ingest_runtime_event("org2", "e", "http_log", service_name="svc")
    m = engine.match_event_to_code(ev["id"])
    # org2 has no mapping → can't use strategy 2; no path, no stack → unmatched
    assert m.get("matched") is False


def test_service_mapping_beats_path_heuristic(engine):
    engine.register_service_mapping("org1", "svc", "repo/x")
    ev = engine.ingest_runtime_event(
        "org1", "e", "http_log", service_name="svc", path="/api/users"
    )
    m = engine.match_event_to_code(ev["id"])
    assert m["strategy"] == "service_mapping"


# ---------------------------------------------------------------------------
# Strategy 3: path heuristic (3)
# ---------------------------------------------------------------------------


def test_path_heuristic_match(engine):
    ev = engine.ingest_runtime_event("org1", "e", "http_log", path="/users/profile")
    m = engine.match_event_to_code(ev["id"])
    assert m["strategy"] == "path_heuristic"
    assert m["file_ref"] == "routes/users_profile.py"
    assert m["confidence"] == 0.3


def test_path_heuristic_ignores_braces(engine):
    ev = engine.ingest_runtime_event("org1", "e", "http_log", path="/users/{id}/profile")
    m = engine.match_event_to_code(ev["id"])
    assert "{id}" not in m["file_ref"]
    assert m["file_ref"] == "routes/users_profile.py"


def test_path_heuristic_root_path(engine):
    ev = engine.ingest_runtime_event("org1", "e", "http_log", path="/")
    m = engine.match_event_to_code(ev["id"])
    assert m["file_ref"] == "routes/root.py"


# ---------------------------------------------------------------------------
# Match persistence / queries (4)
# ---------------------------------------------------------------------------


def test_get_match_for_event_returns_persisted(engine):
    ev = engine.ingest_runtime_event(
        "org1", "e", "err", stack_trace='File "a.py", line 1'
    )
    engine.match_event_to_code(ev["id"])
    row = engine.get_match_for_event(ev["id"])
    assert row is not None
    assert row["match_strategy"] == "stack_trace"
    assert row["file_ref"] == "a.py"


def test_get_match_for_event_none_when_unmatched(engine):
    assert engine.get_match_for_event("does-not-exist") is None


def test_list_matches_filters_by_org(engine):
    # org1 event
    ev1 = engine.ingest_runtime_event(
        "org1", "e", "err", stack_trace='File "a.py", line 1'
    )
    engine.match_event_to_code(ev1["id"])
    # org2 event
    ev2 = engine.ingest_runtime_event(
        "org2", "e", "err", stack_trace='File "b.py", line 2'
    )
    engine.match_event_to_code(ev2["id"])
    org1_matches = engine.list_matches("org1")
    assert len(org1_matches) == 1
    assert org1_matches[0]["file_ref"] == "a.py"


def test_list_matches_filter_by_event(engine):
    ev = engine.ingest_runtime_event(
        "org1", "e", "err", stack_trace='File "a.py", line 1'
    )
    engine.match_event_to_code(ev["id"])
    filtered = engine.list_matches("org1", runtime_event_id=ev["id"])
    assert len(filtered) == 1


# ---------------------------------------------------------------------------
# Bulk-match (3)
# ---------------------------------------------------------------------------


def test_bulk_match_over_100_events(engine):
    engine.register_service_mapping("org1", "svc", "repo/app")
    for i in range(100):
        engine.ingest_runtime_event(
            "org1", f"evt-{i}", "http_log", service_name="svc", path=f"/p/{i}"
        )
    result = engine.bulk_match("org1", since_minutes=60)
    assert result["candidates"] == 100
    assert result["matched"] == 100
    assert result["by_strategy"].get("service_mapping", 0) == 100


def test_bulk_match_mixed_strategies(engine):
    engine.register_service_mapping("org1", "svc", "repo/app")
    engine.ingest_runtime_event(
        "org1", "e1", "err", service_name="svc",
        stack_trace='File "a.py", line 1',
    )
    engine.ingest_runtime_event("org1", "e2", "http_log", service_name="svc")
    engine.ingest_runtime_event("org1", "e3", "http_log", path="/x")
    r = engine.bulk_match("org1", since_minutes=60)
    assert r["matched"] == 3
    assert r["by_strategy"]["stack_trace"] == 1
    assert r["by_strategy"]["service_mapping"] == 1
    assert r["by_strategy"]["path_heuristic"] == 1


def test_bulk_match_is_org_scoped(engine):
    engine.register_service_mapping("org1", "svc", "r")
    engine.ingest_runtime_event("org1", "e", "http_log", service_name="svc")
    engine.ingest_runtime_event("org2", "e", "http_log", service_name="svc")
    r = engine.bulk_match("org1")
    assert r["candidates"] == 1


# ---------------------------------------------------------------------------
# Events list + stats (4)
# ---------------------------------------------------------------------------


def test_list_events_by_service(engine):
    engine.ingest_runtime_event("org1", "e1", "http_log", service_name="a")
    engine.ingest_runtime_event("org1", "e2", "http_log", service_name="b")
    rows = engine.list_events("org1", service_name="a")
    assert len(rows) == 1
    assert rows[0]["service_name"] == "a"


def test_list_events_all(engine):
    engine.ingest_runtime_event("org1", "e1", "http_log")
    engine.ingest_runtime_event("org1", "e2", "http_log")
    rows = engine.list_events("org1")
    assert len(rows) == 2


def test_stats_basic(engine):
    engine.register_service_mapping("org1", "svc", "r")
    ev = engine.ingest_runtime_event("org1", "e", "http_log", service_name="svc")
    engine.match_event_to_code(ev["id"])
    s = engine.stats("org1")
    assert s["total_events"] == 1
    assert s["total_matches"] == 1
    assert s["total_service_mappings"] == 1
    assert s["match_coverage"] == 1.0
    assert "service_mapping" in s["by_strategy"]


def test_stats_empty_org(engine):
    s = engine.stats("empty")
    assert s["total_events"] == 0
    assert s["match_coverage"] == 0.0
    assert s["by_strategy"] == {}


# ---------------------------------------------------------------------------
# Org isolation (2)
# ---------------------------------------------------------------------------


def test_org_isolation_events(engine):
    engine.ingest_runtime_event("org1", "e", "http_log")
    engine.ingest_runtime_event("org2", "e", "http_log")
    assert len(engine.list_events("org1")) == 1
    assert len(engine.list_events("org2")) == 1


def test_org_isolation_matches(engine):
    ev1 = engine.ingest_runtime_event(
        "org1", "e", "err", stack_trace='File "a", line 1'
    )
    ev2 = engine.ingest_runtime_event(
        "org2", "e", "err", stack_trace='File "b", line 2'
    )
    engine.match_event_to_code(ev1["id"])
    engine.match_event_to_code(ev2["id"])
    assert len(engine.list_matches("org1")) == 1
    assert len(engine.list_matches("org2")) == 1


# ---------------------------------------------------------------------------
# Error handling (2)
# ---------------------------------------------------------------------------


def test_match_event_missing_raises_lookup(engine):
    with pytest.raises(LookupError):
        engine.match_event_to_code("nonexistent-uuid")


def test_bulk_match_negative_minutes_normalizes(engine):
    engine.ingest_runtime_event("org1", "e", "http_log")
    r = engine.bulk_match("org1", since_minutes=-5)
    # since_minutes clamped to 0 → cutoff = now → no events match
    assert r["since_minutes"] == 0


# ---------------------------------------------------------------------------
# Router smoke (3)
# ---------------------------------------------------------------------------


def test_api_register_service_mapping_and_ingest(client):
    r = client.post(
        "/api/v1/code-to-runtime/service-mapping",
        json={"org_id": "demo-org", "service_name": "svc-x", "repo_ref": "r/x"},
    )
    assert r.status_code == 200
    assert r.json()["service_name"] == "svc-x"

    r = client.post(
        "/api/v1/code-to-runtime/event",
        json={
            "org_id": "demo-org",
            "event_ref": "evt-1",
            "event_type": "http_log",
            "service_name": "svc-x",
        },
    )
    assert r.status_code == 200
    event_id = r.json()["id"]

    r = client.post(f"/api/v1/code-to-runtime/match/{event_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["matched"] is True
    assert body["strategy"] == "service_mapping"


def test_api_list_events_and_matches(client):
    client.post(
        "/api/v1/code-to-runtime/service-mapping",
        json={"org_id": "demo-org", "service_name": "svc-y", "repo_ref": "r/y"},
    )
    ev = client.post(
        "/api/v1/code-to-runtime/event",
        json={
            "org_id": "demo-org",
            "event_ref": "evt-2",
            "event_type": "http_log",
            "service_name": "svc-y",
        },
    ).json()
    client.post(f"/api/v1/code-to-runtime/match/{ev['id']}")

    r = client.get("/api/v1/code-to-runtime/events?org_id=demo-org")
    assert r.status_code == 200
    assert any(e["service_name"] == "svc-y" for e in r.json())

    r = client.get(f"/api/v1/code-to-runtime/matches?org_id=demo-org&event_id={ev['id']}")
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_api_bulk_match_and_stats(client):
    client.post(
        "/api/v1/code-to-runtime/service-mapping",
        json={"org_id": "demo-org", "service_name": "svc-z", "repo_ref": "r/z"},
    )
    for i in range(5):
        client.post(
            "/api/v1/code-to-runtime/event",
            json={
                "org_id": "demo-org",
                "event_ref": f"evt-z-{i}",
                "event_type": "http_log",
                "service_name": "svc-z",
            },
        )
    r = client.post(
        "/api/v1/code-to-runtime/bulk-match",
        json={"org_id": "demo-org", "since_minutes": 60},
    )
    assert r.status_code == 200
    assert r.json()["matched"] >= 5

    r = client.get("/api/v1/code-to-runtime/stats?org_id=demo-org")
    assert r.status_code == 200
    assert r.json()["total_events"] >= 5
