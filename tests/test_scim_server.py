"""
Tests for SCIM 2.0 server (suite-api/apps/api/scim_router.py).

Coverage:
- ServiceProviderConfig returns correct schema
- Schemas endpoint
- Create user, get user, list users
- Update user via PUT and PATCH (active=false deactivation)
- Filter by userName, active, externalId
- Groups CRUD
- Bearer token auth (valid + missing + invalid)
- SCIM ListResponse envelope format
- Pagination (startIndex, count)
- 409 conflict on duplicate userName
- 404 on missing user/group
- DELETE deactivates user
"""
from __future__ import annotations

import os
import tempfile
import pytest

# Ensure suite paths on sys.path (mirrors sitecustomize.py)
import sys
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ["suite-api", "suite-core", "suite-feeds", "suite-evidence-risk",
           "suite-attack", "suite-integrations"]:
    _p = os.path.join(_REPO, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi.testclient import TestClient
from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def scim_app(tmp_path, monkeypatch):
    """Return a TestClient with the SCIM router mounted, using a temp DB."""
    # Point the router's DB at a temp file
    monkeypatch.setenv("SCIM_BEARER_TOKEN", "")  # auth disabled by default
    import apps.api.scim_router as scim_module
    monkeypatch.setattr(
        scim_module,
        "_DB_PATH",
        str(tmp_path / "scim.db"),
    )
    app = FastAPI()
    # Re-import to get a fresh router bound to the monkeypatched path
    from importlib import reload
    reload(scim_module)
    app.include_router(scim_module.router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def authed_app(tmp_path, monkeypatch):
    """TestClient with SCIM_BEARER_TOKEN=secret-token set."""
    monkeypatch.setenv("SCIM_BEARER_TOKEN", "secret-token")
    import apps.api.scim_router as scim_module
    monkeypatch.setattr(
        scim_module,
        "_DB_PATH",
        str(tmp_path / "scim_authed.db"),
    )
    from importlib import reload
    reload(scim_module)
    app = FastAPI()
    app.include_router(scim_module.router)
    client = TestClient(app, raise_server_exceptions=True)
    return client


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_user(client, *, user_name="jdoe@example.com", given="John", family="Doe",
               external_id=None, active=True):
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": user_name,
        "name": {"givenName": given, "familyName": family},
        "emails": [{"value": user_name, "type": "work", "primary": True}],
        "active": active,
    }
    if external_id:
        payload["externalId"] = external_id
    r = client.post("/scim/v2/Users", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


# ===========================================================================
# 1. ServiceProviderConfig
# ===========================================================================

def test_service_provider_config_schema(scim_app):
    r = scim_app.get("/scim/v2/ServiceProviderConfig")
    assert r.status_code == 200
    data = r.json()
    assert "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig" in data["schemas"]
    assert data["patch"]["supported"] is True
    assert data["filter"]["supported"] is True
    assert data["bulk"]["supported"] is False


def test_service_provider_config_content_type(scim_app):
    r = scim_app.get("/scim/v2/ServiceProviderConfig")
    assert "scim" in r.headers.get("content-type", "")


# ===========================================================================
# 2. Schemas
# ===========================================================================

def test_schemas_returns_list_response(scim_app):
    r = scim_app.get("/scim/v2/Schemas")
    assert r.status_code == 200
    data = r.json()
    assert data["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert data["totalResults"] == 2
    ids = [s["id"] for s in data["Resources"]]
    assert "urn:ietf:params:scim:schemas:core:2.0:User" in ids
    assert "urn:ietf:params:scim:schemas:core:2.0:Group" in ids


# ===========================================================================
# 3. Create user
# ===========================================================================

def test_create_user_returns_201(scim_app):
    user = _make_user(scim_app)
    assert user["userName"] == "jdoe@example.com"
    assert user["name"]["givenName"] == "John"
    assert user["name"]["familyName"] == "Doe"
    assert user["active"] is True
    assert "id" in user
    assert user["meta"]["resourceType"] == "User"


def test_create_user_missing_username_returns_400(scim_app):
    r = scim_app.post("/scim/v2/Users", json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"]})
    assert r.status_code == 400


def test_create_user_duplicate_returns_409(scim_app):
    _make_user(scim_app, user_name="dup@example.com")
    r = scim_app.post("/scim/v2/Users", json={"userName": "dup@example.com"})
    assert r.status_code == 409


def test_create_user_with_external_id(scim_app):
    user = _make_user(scim_app, user_name="ext@example.com", external_id="okta-abc-123")
    assert user["externalId"] == "okta-abc-123"


# ===========================================================================
# 4. Get user
# ===========================================================================

def test_get_user_by_id(scim_app):
    created = _make_user(scim_app, user_name="get@example.com")
    user_id = created["id"]
    r = scim_app.get(f"/scim/v2/Users/{user_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == user_id
    assert data["userName"] == "get@example.com"


def test_get_user_not_found(scim_app):
    r = scim_app.get("/scim/v2/Users/nonexistent-id")
    assert r.status_code == 404


# ===========================================================================
# 5. List users — envelope format
# ===========================================================================

def test_list_users_envelope(scim_app):
    _make_user(scim_app, user_name="list1@example.com")
    _make_user(scim_app, user_name="list2@example.com")
    r = scim_app.get("/scim/v2/Users")
    assert r.status_code == 200
    data = r.json()
    assert data["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert data["totalResults"] >= 2
    assert "startIndex" in data
    assert "itemsPerPage" in data
    assert "Resources" in data


def test_list_users_pagination(scim_app):
    for i in range(5):
        _make_user(scim_app, user_name=f"page{i}@example.com")
    r = scim_app.get("/scim/v2/Users?startIndex=1&count=2")
    assert r.status_code == 200
    data = r.json()
    assert data["itemsPerPage"] == 2
    assert data["totalResults"] >= 5


# ===========================================================================
# 6. Filter by userName
# ===========================================================================

def test_filter_by_username(scim_app):
    _make_user(scim_app, user_name="filter-me@example.com")
    _make_user(scim_app, user_name="other@example.com")
    r = scim_app.get('/scim/v2/Users?filter=userName eq "filter-me@example.com"')
    assert r.status_code == 200
    data = r.json()
    assert data["totalResults"] == 1
    assert data["Resources"][0]["userName"] == "filter-me@example.com"


def test_filter_by_active_false(scim_app):
    _make_user(scim_app, user_name="active@example.com", active=True)
    _make_user(scim_app, user_name="inactive@example.com", active=False)
    r = scim_app.get('/scim/v2/Users?filter=active eq false')
    assert r.status_code == 200
    data = r.json()
    assert data["totalResults"] == 1
    assert data["Resources"][0]["active"] is False


def test_filter_by_external_id(scim_app):
    _make_user(scim_app, user_name="extfilter@example.com", external_id="azure-uid-999")
    _make_user(scim_app, user_name="noext@example.com")
    r = scim_app.get('/scim/v2/Users?filter=externalId eq "azure-uid-999"')
    assert r.status_code == 200
    data = r.json()
    assert data["totalResults"] == 1
    assert data["Resources"][0]["externalId"] == "azure-uid-999"


# ===========================================================================
# 7. PUT — full replace
# ===========================================================================

def test_put_user_updates_fields(scim_app):
    user = _make_user(scim_app, user_name="put@example.com", given="Old", family="Name")
    user_id = user["id"]
    r = scim_app.put(f"/scim/v2/Users/{user_id}", json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "put@example.com",
        "name": {"givenName": "New", "familyName": "Name"},
        "active": True,
    })
    assert r.status_code == 200
    data = r.json()
    assert data["name"]["givenName"] == "New"


def test_put_user_not_found(scim_app):
    r = scim_app.put("/scim/v2/Users/ghost-id", json={"userName": "x@example.com"})
    assert r.status_code == 404


# ===========================================================================
# 8. PATCH — partial update
# ===========================================================================

def test_patch_user_deactivate(scim_app):
    user = _make_user(scim_app, user_name="deactivate@example.com")
    user_id = user["id"]
    r = scim_app.patch(f"/scim/v2/Users/{user_id}", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is False


def test_patch_user_replace_display_name(scim_app):
    user = _make_user(scim_app, user_name="patch-dn@example.com")
    user_id = user["id"]
    r = scim_app.patch(f"/scim/v2/Users/{user_id}", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": "Updated Display"}],
    })
    assert r.status_code == 200
    assert r.json()["displayName"] == "Updated Display"


def test_patch_user_no_path_value_dict(scim_app):
    """PATCH with no path and value as dict (Okta format)."""
    user = _make_user(scim_app, user_name="patch-nopath@example.com")
    user_id = user["id"]
    r = scim_app.patch(f"/scim/v2/Users/{user_id}", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "value": {"active": False, "displayName": "Patched"}}],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is False
    assert data["displayName"] == "Patched"


def test_patch_user_not_found(scim_app):
    r = scim_app.patch("/scim/v2/Users/no-such-id", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [],
    })
    assert r.status_code == 404


# ===========================================================================
# 9. DELETE — deactivates user
# ===========================================================================

def test_delete_user_deactivates(scim_app):
    user = _make_user(scim_app, user_name="todelete@example.com")
    user_id = user["id"]
    r = scim_app.delete(f"/scim/v2/Users/{user_id}")
    assert r.status_code == 204
    # Verify deactivated
    r2 = scim_app.get(f"/scim/v2/Users/{user_id}")
    assert r2.status_code == 200
    assert r2.json()["active"] is False


def test_delete_user_not_found(scim_app):
    r = scim_app.delete("/scim/v2/Users/no-such-user")
    assert r.status_code == 404


# ===========================================================================
# 10. Groups CRUD
# ===========================================================================

def test_create_group(scim_app):
    r = scim_app.post("/scim/v2/Groups", json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Engineering",
    })
    assert r.status_code == 201
    data = r.json()
    assert data["displayName"] == "Engineering"
    assert "id" in data
    assert data["meta"]["resourceType"] == "Group"


def test_create_group_missing_display_name(scim_app):
    r = scim_app.post("/scim/v2/Groups", json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]})
    assert r.status_code == 400


def test_list_groups_envelope(scim_app):
    scim_app.post("/scim/v2/Groups", json={"displayName": "GroupA"})
    scim_app.post("/scim/v2/Groups", json={"displayName": "GroupB"})
    r = scim_app.get("/scim/v2/Groups")
    assert r.status_code == 200
    data = r.json()
    assert data["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert data["totalResults"] >= 2


def test_patch_group_add_member(scim_app):
    user = _make_user(scim_app, user_name="member@example.com")
    group_r = scim_app.post("/scim/v2/Groups", json={"displayName": "PatchGroup"})
    group_id = group_r.json()["id"]
    r = scim_app.patch(f"/scim/v2/Groups/{group_id}", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "members",
            "value": [{"value": user["id"], "display": "member@example.com"}],
        }],
    })
    assert r.status_code == 200
    data = r.json()
    member_ids = [m["value"] for m in data["members"]]
    assert user["id"] in member_ids


def test_patch_group_remove_member(scim_app):
    user = _make_user(scim_app, user_name="removeme@example.com")
    group_r = scim_app.post("/scim/v2/Groups", json={
        "displayName": "RemoveGroup",
        "members": [{"value": user["id"]}],
    })
    group_id = group_r.json()["id"]
    r = scim_app.patch(f"/scim/v2/Groups/{group_id}", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "remove",
            "path": "members",
            "value": [{"value": user["id"]}],
        }],
    })
    assert r.status_code == 200
    assert r.json()["members"] == []


def test_patch_group_not_found(scim_app):
    r = scim_app.patch("/scim/v2/Groups/no-group", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [],
    })
    assert r.status_code == 404


# ===========================================================================
# 11. Auth — Bearer token
# ===========================================================================

def test_auth_valid_token(authed_app):
    r = authed_app.get(
        "/scim/v2/ServiceProviderConfig",
        headers={"Authorization": "Bearer secret-token"},
    )
    assert r.status_code == 200


def test_auth_missing_token_returns_401(authed_app):
    r = authed_app.get("/scim/v2/ServiceProviderConfig")
    assert r.status_code == 401


def test_auth_wrong_token_returns_401(authed_app):
    r = authed_app.get(
        "/scim/v2/ServiceProviderConfig",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401


def test_auth_disabled_when_env_var_empty(scim_app):
    """When SCIM_BEARER_TOKEN is empty, auth is skipped."""
    r = scim_app.get("/scim/v2/ServiceProviderConfig")
    assert r.status_code == 200


def test_auth_create_user_with_valid_token(authed_app):
    r = authed_app.post(
        "/scim/v2/Users",
        json={"userName": "auth@example.com"},
        headers={"Authorization": "Bearer secret-token"},
    )
    assert r.status_code == 201


def test_auth_create_user_without_token_returns_401(authed_app):
    r = authed_app.post("/scim/v2/Users", json={"userName": "noauth@example.com"})
    assert r.status_code == 401


# ===========================================================================
# 12. User groups membership reflected in GET /Users/{id}
# ===========================================================================

def test_user_shows_group_membership(scim_app):
    user = _make_user(scim_app, user_name="grouped@example.com")
    group_r = scim_app.post("/scim/v2/Groups", json={"displayName": "MyTeam"})
    group_id = group_r.json()["id"]
    scim_app.patch(f"/scim/v2/Groups/{group_id}", json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": user["id"]}]}],
    })
    r = scim_app.get(f"/scim/v2/Users/{user['id']}")
    assert r.status_code == 200
    group_ids = [g["value"] for g in r.json()["groups"]]
    assert group_id in group_ids
