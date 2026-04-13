"""Tests for SSOBridge — SAML 2.0 and OIDC authentication bridge."""
import base64
import json
import sys
import time

import pytest

sys.path.insert(0, "suite-core")

from core.sso_bridge import SSOBridge, SSOUser, _b64_decode, _parse_jwt


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def bridge(tmp_path):
    db_path = str(tmp_path / "sso_test.db")
    return SSOBridge(db_path=db_path)


def _make_jwt(payload: dict) -> str:
    """Build a minimal unsigned JWT (alg=none)."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    )
    return f"{header}.{body}."


def _make_saml(name_id: str, email: str = "", roles: list = None, org_id: str = "") -> str:
    """Build a minimal SAML assertion XML string."""
    role_attrs = ""
    if roles:
        values = "".join(f"<AttributeValue>{r}</AttributeValue>" for r in roles)
        role_attrs = f'<Attribute Name="roles">{values}</Attribute>'
    email_attr = ""
    if email:
        email_attr = f'<Attribute Name="email"><AttributeValue>{email}</AttributeValue></Attribute>'
    org_attr = ""
    if org_id:
        org_attr = f'<Attribute Name="org_id"><AttributeValue>{org_id}</AttributeValue></Attribute>'
    return f"""<Response>
  <Assertion>
    <Subject><NameID>{name_id}</NameID></Subject>
    <AttributeStatement>
      {email_attr}
      {role_attrs}
      {org_attr}
    </AttributeStatement>
  </Assertion>
</Response>"""


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------


def test_bridge_instantiates_with_tmp_path(tmp_path):
    db = str(tmp_path / "sso.db")
    b = SSOBridge(db_path=db)
    assert b is not None


def test_bridge_creates_db_file(tmp_path):
    db = str(tmp_path / "sub" / "sso.db")
    SSOBridge(db_path=db)
    import os
    assert os.path.exists(db)


# ---------------------------------------------------------------------------
# Provider management
# ---------------------------------------------------------------------------


def test_register_provider_returns_dict(bridge):
    result = bridge.register_provider("okta", "oidc", {"client_id": "abc"})
    assert isinstance(result, dict)
    assert result["name"] == "okta"
    assert result["type"] == "oidc"


def test_register_provider_stores_config(bridge):
    bridge.register_provider("azure_ad", "saml", {"metadata_url": "https://login.microsoftonline.com"})
    cfg = bridge.get_provider_config("azure_ad")
    assert cfg is not None
    assert cfg["type"] == "saml"
    assert cfg["config"]["metadata_url"] == "https://login.microsoftonline.com"


def test_register_provider_invalid_type_raises(bridge):
    with pytest.raises(ValueError, match="Unsupported provider_type"):
        bridge.register_provider("bad", "oauth1", {})


def test_register_provider_both_types(bridge):
    bridge.register_provider("p_oidc", "oidc", {})
    bridge.register_provider("p_saml", "saml", {})
    providers = bridge.list_providers()
    names = [p["name"] for p in providers]
    assert "p_oidc" in names
    assert "p_saml" in names


def test_get_provider_config_unknown_returns_none(bridge):
    result = bridge.get_provider_config("nonexistent_provider")
    assert result is None


def test_list_providers_empty_initially(bridge):
    providers = bridge.list_providers()
    assert isinstance(providers, list)
    assert len(providers) == 0


def test_list_providers_returns_registered(bridge):
    bridge.register_provider("auth0", "oidc", {"domain": "myapp.auth0.com"})
    providers = bridge.list_providers()
    assert len(providers) == 1
    assert providers[0]["name"] == "auth0"


def test_register_provider_overwrites_existing(bridge):
    bridge.register_provider("okta", "oidc", {"v": 1})
    bridge.register_provider("okta", "oidc", {"v": 2})
    cfg = bridge.get_provider_config("okta")
    assert cfg["config"]["v"] == 2


# ---------------------------------------------------------------------------
# OIDC token validation
# ---------------------------------------------------------------------------


def test_validate_oidc_token_returns_sso_user(bridge):
    payload = {
        "sub": "user123",
        "email": "user@example.com",
        "exp": int(time.time()) + 3600,
    }
    jwt = _make_jwt(payload)
    user = bridge.validate_oidc_token(jwt, provider="okta")
    assert isinstance(user, SSOUser)
    assert user.user_id == "user123"
    assert user.email == "user@example.com"
    assert user.provider == "okta"


def test_validate_oidc_token_parses_roles_list(bridge):
    payload = {
        "sub": "u1",
        "roles": ["admin", "viewer"],
        "exp": int(time.time()) + 3600,
    }
    user = bridge.validate_oidc_token(_make_jwt(payload))
    assert "admin" in user.roles
    assert "viewer" in user.roles


def test_validate_oidc_token_parses_roles_comma_string(bridge):
    payload = {"sub": "u2", "roles": "soc,analyst", "exp": int(time.time()) + 3600}
    user = bridge.validate_oidc_token(_make_jwt(payload))
    assert "soc" in user.roles
    assert "analyst" in user.roles


def test_validate_oidc_token_uses_groups_fallback(bridge):
    payload = {"sub": "u3", "groups": ["devops"], "exp": int(time.time()) + 3600}
    user = bridge.validate_oidc_token(_make_jwt(payload))
    assert "devops" in user.roles


def test_validate_oidc_token_expired_raises(bridge):
    payload = {"sub": "u4", "exp": int(time.time()) - 1}
    with pytest.raises(ValueError, match="expired"):
        bridge.validate_oidc_token(_make_jwt(payload))


def test_validate_oidc_token_missing_sub_raises(bridge):
    payload = {"email": "no-sub@example.com", "exp": int(time.time()) + 3600}
    with pytest.raises(ValueError, match="sub"):
        bridge.validate_oidc_token(_make_jwt(payload))


def test_validate_oidc_token_malformed_string_raises(bridge):
    with pytest.raises(ValueError):
        bridge.validate_oidc_token("not.a.valid.jwt.string.extra")


def test_validate_oidc_token_empty_string_raises(bridge):
    with pytest.raises(ValueError):
        bridge.validate_oidc_token("")


def test_validate_oidc_token_org_id_from_tenant_id(bridge):
    payload = {"sub": "u5", "tenant_id": "acme", "exp": int(time.time()) + 3600}
    user = bridge.validate_oidc_token(_make_jwt(payload))
    assert user.org_id == "acme"


# ---------------------------------------------------------------------------
# SAML assertion validation
# ---------------------------------------------------------------------------


def test_validate_saml_assertion_returns_sso_user(bridge):
    xml = _make_saml("alice@corp.com", email="alice@corp.com")
    user = bridge.validate_saml_assertion(xml)
    assert isinstance(user, SSOUser)
    assert user.user_id == "alice@corp.com"
    assert user.provider == "saml"


def test_validate_saml_assertion_extracts_email(bridge):
    xml = _make_saml("uid-999", email="uid999@corp.com")
    user = bridge.validate_saml_assertion(xml)
    assert user.email == "uid999@corp.com"


def test_validate_saml_assertion_extracts_roles(bridge):
    xml = _make_saml("uid-bob", roles=["admin", "soc"])
    user = bridge.validate_saml_assertion(xml)
    assert "admin" in user.roles
    assert "soc" in user.roles


def test_validate_saml_assertion_extracts_org_id(bridge):
    xml = _make_saml("uid-carl", org_id="acme-corp")
    user = bridge.validate_saml_assertion(xml)
    assert user.org_id == "acme-corp"


def test_validate_saml_assertion_empty_string_raises(bridge):
    with pytest.raises(ValueError, match="empty"):
        bridge.validate_saml_assertion("")


def test_validate_saml_assertion_whitespace_only_raises(bridge):
    with pytest.raises(ValueError, match="empty"):
        bridge.validate_saml_assertion("   ")


def test_validate_saml_assertion_invalid_xml_raises(bridge):
    with pytest.raises(ValueError, match="Invalid SAML XML"):
        bridge.validate_saml_assertion("<unclosed>")


def test_validate_saml_assertion_missing_name_id_raises(bridge):
    xml = "<Response><Assertion><Subject></Subject></Assertion></Response>"
    with pytest.raises(ValueError, match="NameID"):
        bridge.validate_saml_assertion(xml)


def test_validate_saml_assertion_default_email_fallback(bridge):
    xml = _make_saml("plain-user-id")
    user = bridge.validate_saml_assertion(xml)
    assert "@saml" in user.email


# ---------------------------------------------------------------------------
# exchange_code_for_token
# ---------------------------------------------------------------------------


def test_exchange_code_returns_dict(bridge):
    result = bridge.exchange_code_for_token("code123", "okta")
    assert isinstance(result, dict)


def test_exchange_code_has_access_token(bridge):
    result = bridge.exchange_code_for_token("code456", "azure")
    assert "access_token" in result
    assert result["access_token"]


def test_exchange_code_has_id_token(bridge):
    result = bridge.exchange_code_for_token("code789", "okta")
    assert "id_token" in result


def test_exchange_code_has_token_type(bridge):
    result = bridge.exchange_code_for_token("code_abc", "okta")
    assert result.get("token_type") == "Bearer"


def test_exchange_code_different_codes_different_tokens(bridge):
    r1 = bridge.exchange_code_for_token("code_aaa", "okta")
    r2 = bridge.exchange_code_for_token("code_bbb", "okta")
    assert r1["access_token"] != r2["access_token"]


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------


def test_create_session_returns_nonempty_string(bridge):
    user = SSOUser("u1", "u1@test.com", ["viewer"], "org1", "oidc")
    token = bridge.create_session(user)
    assert isinstance(token, str)
    assert len(token) > 0


def test_create_session_token_starts_with_sso(bridge):
    user = SSOUser("u2", "u2@test.com", [], "org2", "saml")
    token = bridge.create_session(user)
    assert token.startswith("sso_")


def test_create_session_unique_tokens(bridge):
    user = SSOUser("u3", "u3@test.com", [], "org3", "oidc")
    t1 = bridge.create_session(user)
    t2 = bridge.create_session(user)
    assert t1 != t2


def test_validate_session_valid_token_returns_sso_user(bridge):
    user = SSOUser("u4", "u4@test.com", ["admin"], "org4", "oidc")
    token = bridge.create_session(user)
    result = bridge.validate_session(token)
    assert result is not None
    assert isinstance(result, SSOUser)
    assert result.user_id == "u4"
    assert result.email == "u4@test.com"


def test_validate_session_preserves_roles(bridge):
    user = SSOUser("u5", "u5@test.com", ["soc", "analyst"], "org5", "saml")
    token = bridge.create_session(user)
    result = bridge.validate_session(token)
    assert result is not None
    assert "soc" in result.roles
    assert "analyst" in result.roles


def test_validate_session_invalid_token_returns_none(bridge):
    result = bridge.validate_session("totally_invalid_token_xyz")
    assert result is None


def test_validate_session_empty_string_returns_none(bridge):
    result = bridge.validate_session("")
    assert result is None


def test_validate_session_expired_session_returns_none(bridge):
    """Directly insert an expired session row and confirm it returns None."""
    import sqlite3

    user = SSOUser("u6", "u6@test.com", [], "org6", "oidc")
    token = bridge.create_session(user)

    # Manually expire the session in the DB
    conn = sqlite3.connect(bridge._db_path)
    conn.execute(
        "UPDATE sso_sessions SET expires_at = ? WHERE token = ?",
        (time.time() - 1, token),
    )
    conn.commit()
    conn.close()

    # Force a new connection on the bridge's thread-local
    bridge._local.__dict__.clear()

    result = bridge.validate_session(token)
    assert result is None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_parse_jwt_valid():
    payload = {"sub": "x", "exp": 9999999999}
    jwt = _make_jwt(payload)
    result = _parse_jwt(jwt)
    assert result["sub"] == "x"


def test_parse_jwt_malformed_raises():
    with pytest.raises(ValueError, match="Malformed JWT"):
        _parse_jwt("only.two")


def test_parse_jwt_empty_raises():
    with pytest.raises(ValueError):
        _parse_jwt("")


def test_b64_decode_with_padding():
    raw = b"hello world"
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    assert _b64_decode(encoded) == raw
