"""Router-level regression tests for the endpoints added 2026-06-02 to fix the
tab-panel sweep findings (real engines, no mocks):

  GET/PUT /api/v1/policy-enforcement/hooks/policy  -> DevSecOpsEngine hook policy
  GET     /api/v1/policy-enforcement/hooks/status  -> derived from active policy
  GET     /api/v1/autofix/fixes                    -> AutoFixEngine.list_fixes()

These had zero coverage; without them a path/shape regression would silently
re-break the /comply/policies/authoring and /developer hub tabs.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.auth_deps import api_key_auth


def _pe_client(tmp_path, monkeypatch):
    """policy-enforcement router with auth bypassed + an isolated DevSecOps engine."""
    import apps.api.policy_enforcement_router as mod
    from core.devsecops_engine import DevSecOpsEngine

    eng = DevSecOpsEngine(db_path=str(tmp_path / "hooks_router_test.db"))
    monkeypatch.setattr(mod, "_devsecops", lambda: eng)

    app = FastAPI()
    app.include_router(mod.router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app), eng


def _af_client(monkeypatch):
    """autofix router with auth bypassed + a fresh (empty) AutoFix engine."""
    import apps.api.autofix_router as mod
    from core.autofix_engine import AutoFixEngine

    eng = AutoFixEngine()
    monkeypatch.setattr(mod, "_get_engine", lambda: eng)

    app = FastAPI()
    app.include_router(mod.router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app), eng


# ---------------------------------------------------------------------------
# hooks/policy + hooks/status
# ---------------------------------------------------------------------------


def test_hooks_policy_empty_returns_object(tmp_path, monkeypatch):
    client, _ = _pe_client(tmp_path, monkeypatch)
    r = client.get("/api/v1/policy-enforcement/hooks/policy", params={"org_id": "default"})
    assert r.status_code == 200
    assert r.json() == {}  # honest-empty when no policy configured


def test_hooks_status_empty_returns_list(tmp_path, monkeypatch):
    client, _ = _pe_client(tmp_path, monkeypatch)
    r = client.get("/api/v1/policy-enforcement/hooks/status", params={"org_id": "default"})
    assert r.status_code == 200
    assert r.json() == []


def test_hooks_policy_put_then_get_roundtrip(tmp_path, monkeypatch):
    client, _ = _pe_client(tmp_path, monkeypatch)
    policy = {"pre-commit": {"enabled": True}, "pr-gate": {"enabled": False}}

    put = client.put(
        "/api/v1/policy-enforcement/hooks/policy",
        params={"org_id": "default"},
        json=policy,
    )
    assert put.status_code == 200

    got = client.get("/api/v1/policy-enforcement/hooks/policy", params={"org_id": "default"})
    assert got.status_code == 200
    assert got.json() == policy  # round-trips the real persisted hook policy

    status = client.get("/api/v1/policy-enforcement/hooks/status", params={"org_id": "default"})
    assert status.status_code == 200
    rows = status.json()
    stages = {row["stage"]: row["status"] for row in rows}
    assert stages.get("pre-commit") == "idle"      # configured + enabled
    assert stages.get("pr-gate") == "disabled"     # configured + disabled
    # never fabricates runtime health/metrics
    assert all(row["trigger_count"] == 0 and row["error_count"] == 0 for row in rows)


def test_hooks_policy_put_rejects_empty_body(tmp_path, monkeypatch):
    client, _ = _pe_client(tmp_path, monkeypatch)
    r = client.put("/api/v1/policy-enforcement/hooks/policy", params={"org_id": "default"}, json={})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# autofix/fixes
# ---------------------------------------------------------------------------


def test_autofix_fixes_shape(monkeypatch):
    client, _ = _af_client(monkeypatch)
    r = client.get("/api/v1/autofix/fixes", params={"org_id": "default"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body.get("fixes"), list)
    assert isinstance(body.get("items"), list)
    assert body["total"] == len(body["fixes"])
    # Every row is normalised to the FixHelper shape the /developer tab consumes
    # (the panel keyed/displayed these; a raw engine dict would blank the table).
    for fx in body["fixes"]:
        for k in ("id", "title", "file", "repo", "fix_snippet", "rule_id", "finding_id", "fix_type", "status"):
            assert k in fx, f"missing key {k} in autofix fix row"
