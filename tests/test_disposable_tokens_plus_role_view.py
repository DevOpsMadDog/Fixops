"""
GAP-039 + GAP-050 — Disposable scoped tokens + role-view switcher.

Tests rbac_engine methods and auth_router endpoints.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from core.rbac_engine import RBACEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    db = tmp_path / "rbac_disposable.db"
    return RBACEngine(db_path=str(db))


# ---------------------------------------------------------------------------
# GAP-039 — Disposable token engine-level tests
# ---------------------------------------------------------------------------


def test_mint_returns_raw_token_once(engine: RBACEngine):
    r = engine.mint_disposable_token("org1", "alice", ["read:findings"], 60, "demo")
    assert r["token_id"]
    assert r["raw_token"]
    assert len(r["raw_token"]) >= 32
    assert r["scope"] == ["read:findings"]
    assert r["expires_at"]


def test_mint_stores_only_hash_not_raw_token(engine: RBACEngine):
    r = engine.mint_disposable_token("org1", "alice", ["read:*"], 60, "demo")
    # list must never include raw_token or token_hash
    listed = engine.list_disposable_tokens("org1", active_only=False)
    assert len(listed) == 1
    row = listed[0]
    assert "raw_token" not in row
    assert "token_hash" not in row
    assert row["id"] == r["token_id"]


def test_verify_succeeds_within_ttl(engine: RBACEngine):
    r = engine.mint_disposable_token("org1", "alice", ["read:findings"], 60, "demo")
    v = engine.verify_disposable_token(r["raw_token"])
    assert v is not None
    assert v["org_id"] == "org1"
    assert v["scope"] == ["read:findings"]
    assert v["purpose"] == "demo"
    assert v["minted_by"] == "alice"


def test_verify_fails_after_expires_at(engine: RBACEngine, monkeypatch):
    r = engine.mint_disposable_token("org1", "alice", ["read:*"], 60, "demo")
    # Rewind the stored expires_at to the past
    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    with engine._get_conn() as conn:
        conn.execute(
            "UPDATE disposable_tokens SET expires_at=? WHERE id=?",
            (past_iso, r["token_id"]),
        )
    assert engine.verify_disposable_token(r["raw_token"]) is None


def test_verify_fails_for_bogus_token(engine: RBACEngine):
    assert engine.verify_disposable_token("not-a-real-token") is None


def test_verify_fails_for_empty_token(engine: RBACEngine):
    assert engine.verify_disposable_token("") is None
    assert engine.verify_disposable_token(None) is None  # type: ignore[arg-type]


def test_revoke_makes_verify_fail(engine: RBACEngine):
    r = engine.mint_disposable_token("org1", "alice", ["read:*"], 60, "demo")
    assert engine.verify_disposable_token(r["raw_token"]) is not None
    assert engine.revoke_disposable_token("org1", r["token_id"], "admin") is True
    assert engine.verify_disposable_token(r["raw_token"]) is None


def test_revoke_is_idempotent_returns_false_second_time(engine: RBACEngine):
    r = engine.mint_disposable_token("org1", "alice", ["read:*"], 60, "demo")
    assert engine.revoke_disposable_token("org1", r["token_id"], "admin") is True
    assert engine.revoke_disposable_token("org1", r["token_id"], "admin") is False


def test_revoke_cross_org_blocked(engine: RBACEngine):
    r = engine.mint_disposable_token("orgA", "alice", ["read:*"], 60, "demo")
    # Attempt to revoke from orgB — must fail
    assert engine.revoke_disposable_token("orgB", r["token_id"], "admin") is False
    # Token is still valid
    assert engine.verify_disposable_token(r["raw_token"]) is not None


def test_list_never_returns_raw_token_or_hash(engine: RBACEngine):
    for i in range(3):
        engine.mint_disposable_token("org1", f"u{i}", ["read:*"], 60, f"p{i}")
    listed = engine.list_disposable_tokens("org1", active_only=True)
    assert len(listed) == 3
    for row in listed:
        assert "raw_token" not in row
        assert "token_hash" not in row
        assert "scope" in row


def test_list_active_only_excludes_revoked(engine: RBACEngine):
    r1 = engine.mint_disposable_token("org1", "u1", ["read:*"], 60, "a")
    r2 = engine.mint_disposable_token("org1", "u2", ["read:*"], 60, "b")
    engine.revoke_disposable_token("org1", r1["token_id"], "admin")
    active = engine.list_disposable_tokens("org1", active_only=True)
    all_tokens = engine.list_disposable_tokens("org1", active_only=False)
    active_ids = {t["id"] for t in active}
    all_ids = {t["id"] for t in all_tokens}
    assert r2["token_id"] in active_ids
    assert r1["token_id"] not in active_ids
    assert r1["token_id"] in all_ids


def test_list_org_isolation(engine: RBACEngine):
    engine.mint_disposable_token("orgA", "a", ["read:*"], 60, "pa")
    engine.mint_disposable_token("orgB", "b", ["read:*"], 60, "pb")
    a = engine.list_disposable_tokens("orgA")
    b = engine.list_disposable_tokens("orgB")
    assert len(a) == 1 and a[0]["org_id"] == "orgA"
    assert len(b) == 1 and b[0]["org_id"] == "orgB"


def test_mint_validates_scope_list(engine: RBACEngine):
    with pytest.raises(ValueError):
        engine.mint_disposable_token("org1", "u", "not-a-list", 60, "p")  # type: ignore[arg-type]


def test_mint_validates_ttl_positive(engine: RBACEngine):
    with pytest.raises(ValueError):
        engine.mint_disposable_token("org1", "u", ["read:*"], 0, "p")
    with pytest.raises(ValueError):
        engine.mint_disposable_token("org1", "u", ["read:*"], -1, "p")


def test_mint_validates_purpose_nonempty(engine: RBACEngine):
    with pytest.raises(ValueError):
        engine.mint_disposable_token("org1", "u", ["read:*"], 60, "")


def test_two_tokens_have_different_raw_values(engine: RBACEngine):
    r1 = engine.mint_disposable_token("org1", "u", ["read:*"], 60, "p1")
    r2 = engine.mint_disposable_token("org1", "u", ["read:*"], 60, "p2")
    assert r1["raw_token"] != r2["raw_token"]
    assert r1["token_id"] != r2["token_id"]


def test_verify_after_many_tokens_still_hits_right_one(engine: RBACEngine):
    tokens = [
        engine.mint_disposable_token("org1", f"u{i}", ["read:*"], 60, f"p{i}")
        for i in range(10)
    ]
    # Verify a specific one (middle of the pile)
    target = tokens[4]
    v = engine.verify_disposable_token(target["raw_token"])
    assert v is not None
    assert v["token_id"] == target["token_id"]
    assert v["minted_by"] == "u4"


# ---------------------------------------------------------------------------
# GAP-050 — Role-view switcher engine-level tests
# ---------------------------------------------------------------------------


def test_role_view_override_persists(engine: RBACEngine):
    ov = engine.switch_role_view("org1", "alice", "analyst", duration_seconds=60)
    assert ov["override_id"]
    assert ov["target_role"] == "analyst"
    active = engine.get_active_role_view("org1", "alice")
    assert active is not None
    assert active["target_role"] == "analyst"
    assert active["ended_at"] is None


def test_get_active_returns_none_when_no_override(engine: RBACEngine):
    assert engine.get_active_role_view("org1", "alice") is None


def test_get_active_returns_none_after_expires(engine: RBACEngine):
    ov = engine.switch_role_view("org1", "alice", "viewer", duration_seconds=60)
    # Rewind stored expires_at into the past
    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    with engine._get_conn() as conn:
        conn.execute(
            "UPDATE role_view_overrides SET expires_at=? WHERE id=?",
            (past_iso, ov["override_id"]),
        )
    assert engine.get_active_role_view("org1", "alice") is None


def test_end_role_view_ends_it(engine: RBACEngine):
    ov = engine.switch_role_view("org1", "alice", "viewer", 60)
    assert engine.end_role_view("org1", ov["override_id"], "alice") is True
    assert engine.get_active_role_view("org1", "alice") is None


def test_end_role_view_is_idempotent_returns_false_second_time(engine: RBACEngine):
    ov = engine.switch_role_view("org1", "alice", "viewer", 60)
    assert engine.end_role_view("org1", ov["override_id"], "alice") is True
    assert engine.end_role_view("org1", ov["override_id"], "alice") is False


def test_switch_role_view_invalid_role_raises(engine: RBACEngine):
    with pytest.raises(ValueError):
        engine.switch_role_view("org1", "alice", "not_a_role", 60)


def test_switch_role_view_invalid_duration_raises(engine: RBACEngine):
    with pytest.raises(ValueError):
        engine.switch_role_view("org1", "alice", "analyst", 0)
    with pytest.raises(ValueError):
        engine.switch_role_view("org1", "alice", "analyst", -10)


def test_switch_role_view_replaces_prior_active(engine: RBACEngine):
    ov1 = engine.switch_role_view("org1", "alice", "analyst", 60)
    ov2 = engine.switch_role_view("org1", "alice", "viewer", 60)
    active = engine.get_active_role_view("org1", "alice")
    assert active is not None
    assert active["target_role"] == "viewer"
    assert active["id"] == ov2["override_id"]
    # The prior one was ended
    assert ov1["override_id"] != ov2["override_id"]


def test_role_view_org_isolation(engine: RBACEngine):
    engine.switch_role_view("orgA", "alice", "analyst", 60)
    # Same user in a different org has no active override
    assert engine.get_active_role_view("orgB", "alice") is None


def test_role_view_per_user_isolation(engine: RBACEngine):
    engine.switch_role_view("org1", "alice", "analyst", 60)
    # Different user in same org has no override
    assert engine.get_active_role_view("org1", "bob") is None


def test_end_role_view_cross_user_blocked(engine: RBACEngine):
    ov = engine.switch_role_view("org1", "alice", "analyst", 60)
    # Bob cannot end Alice's override
    assert engine.end_role_view("org1", ov["override_id"], "bob") is False
    assert engine.get_active_role_view("org1", "alice") is not None


def test_end_role_view_cross_org_blocked(engine: RBACEngine):
    ov = engine.switch_role_view("orgA", "alice", "analyst", 60)
    # Wrong org cannot end
    assert engine.end_role_view("orgB", ov["override_id"], "alice") is False
    assert engine.get_active_role_view("orgA", "alice") is not None


# ---------------------------------------------------------------------------
# Endpoint smoke tests — auth_router
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    """Build a FastAPI TestClient with auth_router mounted and RBAC bound to tmp db."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Point RBACEngine default path to a tmp file so endpoint handlers pick it up.
    db = tmp_path / "router_rbac.db"

    import core.rbac_engine as rbac_mod

    original_init = rbac_mod.RBACEngine.__init__

    def patched_init(self, db_path: str = str(db)):
        original_init(self, db_path=str(db))

    monkeypatch.setattr(rbac_mod.RBACEngine, "__init__", patched_init)

    # Bypass api_key_auth entirely for these smoke tests
    from apps.api import auth_deps
    from apps.api import auth_router as auth_router_mod

    async def _noop_auth():
        return None

    app = FastAPI()
    app.dependency_overrides[auth_deps.api_key_auth] = _noop_auth
    app.include_router(auth_router_mod.router)

    # Mock request.state so the identity helpers work
    from starlette.middleware.base import BaseHTTPMiddleware

    class IdentMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.org_id = "test-org"
            request.state.user_id = "test-user"
            request.state.user_scopes = ["admin:all"]
            request.state.user_role = "super_admin"
            return await call_next(request)

    app.add_middleware(IdentMiddleware)
    return TestClient(app)


def test_endpoint_mint_and_verify_lifecycle(api_client):
    resp = api_client.post(
        "/api/v1/auth/disposable-token",
        json={"scope": ["read:findings"], "ttl_seconds": 60, "purpose": "e2e-test"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["raw_token"]
    assert body["token_id"]

    # list
    list_resp = api_client.get("/api/v1/auth/disposable-tokens")
    assert list_resp.status_code == 200
    list_body = list_resp.json()
    assert list_body["count"] >= 1
    for t in list_body["tokens"]:
        assert "raw_token" not in t
        assert "token_hash" not in t

    # revoke
    rev = api_client.delete(f"/api/v1/auth/disposable-token/{body['token_id']}")
    assert rev.status_code == 200
    assert rev.json()["status"] == "revoked"

    # double revoke -> 404
    rev2 = api_client.delete(f"/api/v1/auth/disposable-token/{body['token_id']}")
    assert rev2.status_code == 404


def test_endpoint_mint_rejects_bad_input(api_client):
    # ttl_seconds=0 fails Pydantic gt=0 -> 422
    resp = api_client.post(
        "/api/v1/auth/disposable-token",
        json={"scope": ["read:*"], "ttl_seconds": 0, "purpose": "bad"},
    )
    assert resp.status_code == 422


def test_endpoint_role_view_lifecycle(api_client):
    # switch
    resp = api_client.post(
        "/api/v1/auth/role-view",
        json={"target_role": "analyst", "duration_seconds": 60},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["target_role"] == "analyst"
    override_id = body["override_id"]

    # get
    cur = api_client.get("/api/v1/auth/role-view")
    assert cur.status_code == 200
    assert cur.json()["active_override"] is not None
    assert cur.json()["active_override"]["target_role"] == "analyst"

    # end
    end = api_client.delete(f"/api/v1/auth/role-view/{override_id}")
    assert end.status_code == 200
    assert end.json()["status"] == "ended"

    # get after end -> null
    cur2 = api_client.get("/api/v1/auth/role-view")
    assert cur2.status_code == 200
    assert cur2.json()["active_override"] is None

    # end again -> 404
    end2 = api_client.delete(f"/api/v1/auth/role-view/{override_id}")
    assert end2.status_code == 404


def test_endpoint_role_view_invalid_role_returns_400(api_client):
    resp = api_client.post(
        "/api/v1/auth/role-view",
        json={"target_role": "not_a_role", "duration_seconds": 60},
    )
    assert resp.status_code == 400
