"""
Tests for Enterprise SSO — SAML 2.0 and OIDC provider module.

Coverage:
- SSOConfig model validation for each provider type
- OIDCProvider: auth URL, code exchange, token validation, refresh, userinfo
- SAMLProvider: login URL, response processing, metadata generation
- UserInfo model validation
- Role mapping from IdP groups to ALDECI roles
- Allowed domain filtering
- create_sso_jwt / validate_sso_jwt helpers
- Auth middleware SSO JWT acceptance

All external HTTP calls are mocked — no real IdP required.

Run:
    pytest tests/test_sso_provider.py -x --tb=short --timeout=10 -q
"""
from __future__ import annotations

import base64
import json
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import jwt
import pytest

# Ensure suite-core is importable
_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from core.exceptions import AuthorizationError, ValidationError
from core.sso_provider import (
    OIDCProvider,
    SAMLProvider,
    SSOConfig,
    TokenResponse,
    UserInfo,
    check_allowed_domain,
    create_sso_jwt,
    map_groups_to_roles,
    validate_sso_jwt,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OKTA_ISSUER = "https://example.okta.com"
_DISCOVERY_DOC = {
    "issuer": _OKTA_ISSUER,
    "authorization_endpoint": f"{_OKTA_ISSUER}/oauth2/v1/authorize",
    "token_endpoint": f"{_OKTA_ISSUER}/oauth2/v1/token",
    "userinfo_endpoint": f"{_OKTA_ISSUER}/oauth2/v1/userinfo",
    "jwks_uri": f"{_OKTA_ISSUER}/oauth2/v1/keys",
}

_JWT_SECRET = "fixops-dev-secret-change-in-production-x32"  # 42 chars — above 32-byte PyJWT minimum


def _make_id_token(
    email: str = "alice@company.com",
    groups: list | None = None,
    exp_offset: int = 3600,
) -> str:
    """Create a minimal signed id_token for testing."""
    now = int(time.time())
    payload = {
        "sub": "user-123",
        "email": email,
        "name": "Alice Smith",
        "groups": groups or [],
        "iat": now,
        "exp": now + exp_offset,
    }
    return jwt.encode(payload, _JWT_SECRET, algorithm="HS256")


def _make_saml_response(
    email: str = "bob@corp.com",
    name: str = "Bob Jones",
    groups: list | None = None,
    status_value: str = "urn:oasis:names:tc:SAML:2.0:status:Success",
) -> str:
    """Build a base64-encoded minimal SAML Response XML."""
    groups_xml = "".join(
        f'<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"'
        f' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        f' xsi:type="xs:string">{g}</saml:AttributeValue>'
        for g in (groups or [])
    )
    xml = f"""<?xml version="1.0"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_resp123"
    Version="2.0"
    IssueInstant="2024-01-01T00:00:00Z">
  <samlp:Status>
    <samlp:StatusCode Value="{status_value}"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="displayName">
        <saml:AttributeValue>{name}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="groups">
        {groups_xml}
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
    return base64.b64encode(xml.encode()).decode()


def _okta_config(**overrides) -> SSOConfig:
    defaults = dict(
        provider="okta",
        client_id="my-client-id",
        client_secret="my-client-secret",
        issuer_url=_OKTA_ISSUER,
    )
    defaults.update(overrides)
    return SSOConfig(**defaults)


def _saml_config(**overrides) -> SSOConfig:
    defaults = dict(
        provider="generic_saml",
        idp_metadata_url="https://idp.example.com/metadata",
        sp_entity_id="https://aldeci.example.com/sso/sp",
    )
    defaults.update(overrides)
    return SSOConfig(**defaults)


# ---------------------------------------------------------------------------
# SSOConfig validation
# ---------------------------------------------------------------------------


class TestSSOConfig:
    def test_okta_config_valid(self):
        cfg = _okta_config()
        assert cfg.provider == "okta"
        assert cfg.enabled is True
        assert cfg.client_id == "my-client-id"

    def test_azure_ad_config_valid(self):
        cfg = SSOConfig(
            provider="azure_ad",
            client_id="az-client",
            client_secret="az-secret",
            issuer_url="https://login.microsoftonline.com/tenant123/v2.0",
        )
        assert cfg.provider == "azure_ad"

    def test_google_config_valid(self):
        cfg = SSOConfig(
            provider="google",
            client_id="google-client",
            client_secret="google-secret",
            # issuer_url not required for google
        )
        assert cfg.provider == "google"

    def test_generic_oidc_config_valid(self):
        cfg = SSOConfig(
            provider="generic_oidc",
            client_id="oidc-client",
            client_secret="oidc-secret",
            issuer_url="https://sso.internal.example.com",
        )
        assert cfg.provider == "generic_oidc"

    def test_saml_config_valid(self):
        cfg = _saml_config()
        assert cfg.provider == "generic_saml"
        assert cfg.sp_entity_id == "https://aldeci.example.com/sso/sp"

    def test_oidc_missing_client_id_raises(self):
        with pytest.raises(Exception):
            SSOConfig(
                provider="okta",
                client_secret="secret",
                issuer_url=_OKTA_ISSUER,
            )

    def test_oidc_missing_client_secret_raises(self):
        with pytest.raises(Exception):
            SSOConfig(
                provider="okta",
                client_id="cid",
                issuer_url=_OKTA_ISSUER,
            )

    def test_allowed_domains_string_parsed(self):
        cfg = _okta_config(allowed_domains="company.com,subsidiary.com")
        assert cfg.allowed_domains == ["company.com", "subsidiary.com"]

    def test_allowed_domains_list_passed_through(self):
        cfg = _okta_config(allowed_domains=["corp.io"])
        assert cfg.allowed_domains == ["corp.io"]

    def test_role_mapping_string_parsed(self):
        cfg = _okta_config(role_mapping='{"SecurityTeam":"security_analyst"}')
        assert cfg.role_mapping == {"SecurityTeam": "security_analyst"}

    def test_role_mapping_dict_passed_through(self):
        cfg = _okta_config(role_mapping={"Admins": "admin"})
        assert cfg.role_mapping["Admins"] == "admin"

    def test_disabled_config(self):
        cfg = _okta_config(enabled=False)
        assert cfg.enabled is False

    def test_from_env_disabled_returns_none(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_SSO_ENABLED", raising=False)
        assert SSOConfig.from_env() is None

    def test_from_env_enabled(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_SSO_ENABLED", "1")
        monkeypatch.setenv("FIXOPS_SSO_PROVIDER", "okta")
        monkeypatch.setenv("FIXOPS_OIDC_CLIENT_ID", "env-client")
        monkeypatch.setenv("FIXOPS_OIDC_CLIENT_SECRET", "env-secret")
        monkeypatch.setenv("FIXOPS_OIDC_ISSUER_URL", _OKTA_ISSUER)
        cfg = SSOConfig.from_env()
        assert cfg is not None
        assert cfg.provider == "okta"
        assert cfg.client_id == "env-client"


# ---------------------------------------------------------------------------
# UserInfo model
# ---------------------------------------------------------------------------


class TestUserInfo:
    def test_valid_user_info(self):
        u = UserInfo(email="alice@example.com", name="Alice", provider="okta", sub="u1")
        assert u.email == "alice@example.com"

    def test_email_normalised_to_lowercase(self):
        u = UserInfo(email="ALICE@EXAMPLE.COM")
        assert u.email == "alice@example.com"

    def test_email_missing_at_raises(self):
        with pytest.raises(Exception):
            UserInfo(email="not-an-email")

    def test_groups_and_roles_default_empty(self):
        u = UserInfo(email="x@y.com")
        assert u.groups == []
        assert u.roles == []

    def test_raw_claims_stored(self):
        u = UserInfo(email="x@y.com", raw_claims={"custom": "value"})
        assert u.raw_claims["custom"] == "value"


# ---------------------------------------------------------------------------
# Domain filtering
# ---------------------------------------------------------------------------


class TestDomainFiltering:
    def test_empty_allowed_list_permits_all(self):
        assert check_allowed_domain("alice@anywhere.io", []) is True

    def test_matching_domain_allowed(self):
        assert check_allowed_domain("alice@company.com", ["company.com"]) is True

    def test_non_matching_domain_blocked(self):
        assert check_allowed_domain("alice@evil.com", ["company.com"]) is False

    def test_subdomain_not_matched(self):
        assert check_allowed_domain("alice@sub.company.com", ["company.com"]) is False

    def test_case_insensitive_match(self):
        assert check_allowed_domain("alice@COMPANY.COM", ["company.com"]) is True

    def test_multiple_allowed_domains(self):
        assert check_allowed_domain("alice@subsidiary.com", ["company.com", "subsidiary.com"]) is True


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------


class TestRoleMapping:
    _mapping = {
        "SecurityTeam": "security_analyst",
        "ComplianceTeam": "compliance_officer",
        "Admins": "admin",
    }

    def test_single_group_mapped(self):
        roles = map_groups_to_roles(["SecurityTeam"], self._mapping)
        assert roles == ["security_analyst"]

    def test_multiple_groups_mapped(self):
        roles = map_groups_to_roles(["SecurityTeam", "ComplianceTeam"], self._mapping)
        assert "security_analyst" in roles
        assert "compliance_officer" in roles

    def test_unmapped_group_ignored(self):
        roles = map_groups_to_roles(["RandomGroup"], self._mapping)
        assert roles == []

    def test_empty_groups_returns_empty(self):
        roles = map_groups_to_roles([], self._mapping)
        assert roles == []

    def test_no_duplicates_in_roles(self):
        roles = map_groups_to_roles(["SecurityTeam", "SecurityTeam"], self._mapping)
        assert roles.count("security_analyst") == 1


# ---------------------------------------------------------------------------
# OIDCProvider
# ---------------------------------------------------------------------------


class TestOIDCProvider:
    def _provider(self, **cfg_overrides) -> OIDCProvider:
        cfg = _okta_config(**cfg_overrides)
        p = OIDCProvider(cfg)
        p._discovery = _DISCOVERY_DOC.copy()
        return p

    def test_rejects_saml_provider(self):
        with pytest.raises(ValueError):
            OIDCProvider(_saml_config())

    def test_get_authorization_url_contains_client_id(self):
        p = self._provider()
        url = p.get_authorization_url(state="s1", nonce="n1", redirect_uri="https://app.example.com/cb")
        assert "client_id=my-client-id" in url

    def test_get_authorization_url_contains_state(self):
        p = self._provider()
        url = p.get_authorization_url(state="mystate", nonce="n1", redirect_uri="https://app.example.com/cb")
        assert "state=mystate" in url

    def test_get_authorization_url_contains_redirect_uri(self):
        p = self._provider()
        url = p.get_authorization_url(state="s", nonce="n", redirect_uri="https://app.example.com/callback")
        assert "redirect_uri=" in url

    def test_get_authorization_url_contains_openid_scope(self):
        p = self._provider()
        url = p.get_authorization_url(state="s", nonce="n", redirect_uri="https://cb")
        assert "openid" in url

    def test_get_authorization_url_custom_scopes(self):
        p = self._provider()
        url = p.get_authorization_url(state="s", nonce="n", redirect_uri="https://cb", scopes=["openid", "email", "groups"])
        assert "groups" in url

    def test_exchange_code_success(self):
        p = self._provider()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "access_token": "acc_tok",
            "id_token": "id_tok",
            "refresh_token": "ref_tok",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp

        tokens = p.exchange_code(code="auth_code", redirect_uri="https://cb", http_client=mock_client)
        assert tokens.access_token == "acc_tok"
        assert tokens.refresh_token == "ref_tok"

    def test_exchange_code_error_response_raises(self):
        p = self._provider()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"error": "invalid_grant", "error_description": "code expired"}
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp

        with pytest.raises(AuthorizationError, match="invalid_grant"):
            p.exchange_code(code="bad_code", redirect_uri="https://cb", http_client=mock_client)

    def _make_jwks_mock(self, id_token: str):
        """Return a mock PyJWKClient that produces a key which makes jwt.decode
        succeed by patching jwt.decode directly in the call path."""
        mock_client = MagicMock()
        mock_key = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value.key = mock_key
        return mock_client, mock_key

    def test_validate_token_extracts_email(self):
        p = self._provider()
        id_token = _make_id_token(email="alice@company.com")
        mock_client, mock_key = self._make_jwks_mock(id_token)
        with patch("core.sso_provider.PyJWKClient", return_value=mock_client), \
             patch("core.sso_provider.jwt.decode") as mock_decode:
            mock_decode.return_value = {
                "sub": "user-123",
                "email": "alice@company.com",
                "name": "Alice Smith",
                "groups": [],
                "exp": int(__import__("time").time()) + 3600,
            }
            user_info = p.validate_token(id_token)
        assert user_info.email == "alice@company.com"

    def test_validate_token_extracts_groups(self):
        p = self._provider(role_mapping={"SecurityTeam": "security_analyst"})
        id_token = _make_id_token(groups=["SecurityTeam"])
        mock_client, mock_key = self._make_jwks_mock(id_token)
        with patch("core.sso_provider.PyJWKClient", return_value=mock_client), \
             patch("core.sso_provider.jwt.decode") as mock_decode:
            mock_decode.return_value = {
                "sub": "user-123",
                "email": "alice@company.com",
                "name": "Alice Smith",
                "groups": ["SecurityTeam"],
                "exp": int(__import__("time").time()) + 3600,
            }
            user_info = p.validate_token(id_token)
        assert "SecurityTeam" in user_info.groups
        assert "security_analyst" in user_info.roles

    def test_validate_expired_token_raises(self):
        p = self._provider()
        id_token = _make_id_token(exp_offset=-10)
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value.key = MagicMock()
        with patch("core.sso_provider.PyJWKClient", return_value=mock_client), \
             patch("core.sso_provider.jwt.decode") as mock_decode:
            mock_decode.side_effect = jwt.ExpiredSignatureError("Signature has expired")
            with pytest.raises(AuthorizationError, match="expired"):
                p.validate_token(id_token)

    def test_validate_malformed_token_raises(self):
        p = self._provider()
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.side_effect = Exception("Invalid token")
        with patch("core.sso_provider.PyJWKClient", return_value=mock_client):
            with pytest.raises(AuthorizationError):
                p.validate_token("not.a.jwt")

    def test_refresh_token_success(self):
        p = self._provider()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "access_token": "new_acc",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_client = MagicMock()
        mock_client.post.return_value = mock_resp
        tokens = p.refresh_token("old_refresh", http_client=mock_client)
        assert tokens.access_token == "new_acc"

    def test_get_userinfo_success(self):
        p = self._provider()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "sub": "u42",
            "email": "bob@company.com",
            "name": "Bob Smith",
            "groups": [],
        }
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        user_info = p.get_userinfo("access_token_xyz", http_client=mock_client)
        assert user_info.email == "bob@company.com"
        assert user_info.sub == "u42"

    def test_get_userinfo_missing_email_raises(self):
        p = self._provider()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"sub": "u99"}  # no email
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with pytest.raises(AuthorizationError, match="email"):
            p.get_userinfo("tok", http_client=mock_client)

    def test_fetch_discovery_caches_result(self):
        cfg = _okta_config()
        p = OIDCProvider(cfg)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _DISCOVERY_DOC
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        p.fetch_discovery(http_client=mock_client)
        p.fetch_discovery(http_client=mock_client)  # second call — should not hit HTTP
        assert mock_client.get.call_count == 1

    def test_google_uses_fixed_discovery_url(self):
        cfg = SSOConfig(provider="google", client_id="g-cid", client_secret="g-sec")
        p = OIDCProvider(cfg)
        assert "accounts.google.com" in p._discovery_url()


# ---------------------------------------------------------------------------
# SAMLProvider
# ---------------------------------------------------------------------------


class TestSAMLProvider:
    def _provider(self, **cfg_overrides) -> SAMLProvider:
        return SAMLProvider(_saml_config(**cfg_overrides))

    def test_rejects_oidc_provider(self):
        with pytest.raises(ValueError):
            SAMLProvider(_okta_config())

    def test_get_login_url_contains_saml_request(self):
        p = self._provider()
        url = p.get_login_url(relay_state="/dashboard", sso_url="https://idp.example.com/sso")
        assert "SAMLRequest=" in url
        assert "RelayState=" in url

    def test_get_login_url_without_sso_url_raises(self):
        p = self._provider()
        with pytest.raises(AuthorizationError):
            p.get_login_url(relay_state="/")  # No sso_url, no fetched metadata

    def test_process_response_extracts_email(self):
        p = self._provider()
        resp = _make_saml_response(email="bob@corp.com")
        user_info = p.process_response(resp)
        assert user_info.email == "bob@corp.com"

    def test_process_response_extracts_name(self):
        p = self._provider()
        resp = _make_saml_response(name="Bob Jones")
        user_info = p.process_response(resp)
        assert user_info.name == "Bob Jones"

    def test_process_response_extracts_groups(self):
        p = self._provider(role_mapping={"SecurityTeam": "security_analyst"})
        resp = _make_saml_response(groups=["SecurityTeam", "All"])
        user_info = p.process_response(resp)
        assert "SecurityTeam" in user_info.groups
        assert "security_analyst" in user_info.roles

    def test_process_response_failure_status_raises(self):
        p = self._provider()
        resp = _make_saml_response(
            status_value="urn:oasis:names:tc:SAML:2.0:status:Requester"
        )
        with pytest.raises(AuthorizationError, match="not Success"):
            p.process_response(resp)

    def test_process_response_invalid_base64_raises(self):
        p = self._provider()
        with pytest.raises(ValidationError):
            p.process_response("!!!not-base64!!!")

    def test_process_response_bad_xml_raises(self):
        p = self._provider()
        bad = base64.b64encode(b"<broken xml").decode()
        with pytest.raises(ValidationError):
            p.process_response(bad)

    def test_get_metadata_contains_entity_id(self):
        p = self._provider()
        xml = p.get_metadata()
        assert "aldeci.example.com/sso/sp" in xml

    def test_get_metadata_contains_acs_url(self):
        p = self._provider()
        xml = p.get_metadata()
        assert "/acs" in xml

    def test_get_metadata_contains_slo_url(self):
        p = self._provider()
        xml = p.get_metadata()
        assert "/slo" in xml

    def test_get_metadata_is_valid_xml(self):
        import xml.etree.ElementTree as ET
        p = self._provider()
        xml_str = p.get_metadata()
        # Should not raise
        ET.fromstring(xml_str)

    def test_fetch_idp_metadata_parses_sso_url(self):
        p = self._provider()
        meta_xml = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <md:IDPSSODescriptor>
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp.example.com/sso/redirect"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.text = meta_xml
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        meta = p.fetch_idp_metadata(http_client=mock_client)
        assert meta["sso_url"] == "https://idp.example.com/sso/redirect"


# ---------------------------------------------------------------------------
# SSO JWT helpers
# ---------------------------------------------------------------------------


_LONG_SECRET = "fixops-test-secret-long-enough-for-hs256-minimum-32-bytes"

# Patch the module-level secret to a suitably long value for all SSO JWT tests
@pytest.fixture(autouse=False)
def _patch_sso_secret(monkeypatch):
    monkeypatch.setattr("core.sso_provider._SSO_JWT_SECRET", _LONG_SECRET)


class TestSSOJWT:
    """SSO JWT round-trip tests using a patched 58-byte secret."""

    @pytest.fixture(autouse=True)
    def patch_secret(self, monkeypatch):
        monkeypatch.setattr("core.sso_provider._SSO_JWT_SECRET", _LONG_SECRET)

    def _user_info(self) -> UserInfo:
        return UserInfo(
            email="alice@company.com",
            name="Alice Smith",
            groups=["SecurityTeam"],
            roles=["security_analyst"],
            provider="okta",
            sub="user-123",
        )

    def test_create_and_validate_round_trip(self):
        user_info = self._user_info()
        token = create_sso_jwt(user_info)
        claims = validate_sso_jwt(token)
        assert claims["email"] == "alice@company.com"
        assert claims["sso"] is True

    def test_token_contains_provider(self):
        token = create_sso_jwt(self._user_info())
        claims = validate_sso_jwt(token)
        assert claims["provider"] == "okta"

    def test_token_contains_roles(self):
        token = create_sso_jwt(self._user_info())
        claims = validate_sso_jwt(token)
        assert "security_analyst" in claims["roles"]

    def test_token_contains_groups(self):
        token = create_sso_jwt(self._user_info())
        claims = validate_sso_jwt(token)
        assert "SecurityTeam" in claims["groups"]

    def test_role_defaults_to_viewer_when_no_roles(self):
        u = UserInfo(email="nobody@example.com", roles=[])
        token = create_sso_jwt(u)
        claims = validate_sso_jwt(token)
        assert claims["role"] == "viewer"

    def test_expired_token_raises(self):
        user_info = self._user_info()
        with patch("core.sso_provider._SSO_JWT_EXPIRY_HOURS", -1):
            token = create_sso_jwt(user_info)
        with pytest.raises(AuthorizationError, match="expired"):
            validate_sso_jwt(token)

    def test_tampered_token_raises(self):
        token = create_sso_jwt(self._user_info())
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(AuthorizationError):
            validate_sso_jwt(tampered)
