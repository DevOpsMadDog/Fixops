"""
Multica #4145 — SAML 2.0 SSO smoke tests.

Two tests:
  1. POST /api/v1/auth/saml/{idp_name}/initiate returns a redirect_url containing
     the configured SSO URL and a SAMLRequest query param.
  2. GET  /api/v1/auth/saml/{idp_name}/callback with a mock SAMLResponse returns a
     JWT pair (access_token + refresh_token).

Both tests mock the IdP config via env vars and bypass user DB + JWT secret deps.
"""
import base64
import os
import sys
import uuid
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

IDP_NAME = "testcorp"
IDP_ENTITY_ID = "https://idp.testcorp.example/saml"
IDP_SSO_URL = "https://idp.testcorp.example/sso/saml"

_ENV_PATCH = {
    f"FIXOPS_SAML_IDP_{IDP_NAME.upper()}_ENTITY_ID": IDP_ENTITY_ID,
    f"FIXOPS_SAML_IDP_{IDP_NAME.upper()}_SSO_URL": IDP_SSO_URL,
    f"FIXOPS_SAML_IDP_{IDP_NAME.upper()}_X509_CERT": "",  # no cert → dev-mode skip
    "FIXOPS_DEV_MODE": "true",
    "FIXOPS_JWT_SECRET": "test-secret-for-saml-smoke-tests-32ch",
}


def _make_saml_response(email: str = "alice@testcorp.example") -> str:
    """Build a minimal, unsigned SAMLResponse XML and base64-encode it."""
    resp_id = "_" + uuid.uuid4().hex
    now = "2026-05-05T00:00:00Z"
    xml = f"""<samlp:Response
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="{resp_id}" Version="2.0" IssueInstant="{now}"
        InResponseTo="_req">
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      </samlp:Status>
      <saml:Assertion ID="{uuid.uuid4().hex}" Version="2.0" IssueInstant="{now}">
        <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
        </saml:Subject>
        <saml:AttributeStatement>
          <saml:Attribute Name="email">
            <saml:AttributeValue>{email}</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>"""
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def saml_client():
    """FastAPI TestClient with SAML env vars and mocked user/JWT deps."""
    with patch.dict(os.environ, _ENV_PATCH):
        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        # Build a mock user returned by get_user_by_email (existing user path)
        mock_user = MagicMock()
        mock_user.id = "user-saml-001"
        mock_user.email = "alice@testcorp.example"
        mock_user.org_id = "default"
        # Make status comparisons pass the ACTIVE check
        from core.user_models import UserStatus
        mock_user.status = UserStatus.ACTIVE
        mock_user.role = MagicMock()
        mock_user.role.value = "viewer"

        mock_user_db = MagicMock()
        mock_user_db.get_user_by_email.return_value = mock_user  # existing user — skip create
        mock_user_db.create_user.return_value = mock_user

        import apps.api.auth_router as ar
        app = FastAPI()
        with patch.object(ar, "_user_db", mock_user_db):
            app.include_router(ar.router)
            with TestClient(app, raise_server_exceptions=True) as client:
                yield client, mock_user_db


# ---------------------------------------------------------------------------
# Test 1 — Initiation returns correct redirect URL
# ---------------------------------------------------------------------------

def test_saml_initiate_returns_redirect_url(saml_client):
    """POST /saml/{idp}/initiate must return redirect_url pointing at the IdP SSO URL."""
    client, _ = saml_client
    resp = client.post(f"/api/v1/auth/saml/{IDP_NAME}/initiate")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "redirect_url" in body
    assert body["idp_name"] == IDP_NAME
    assert IDP_SSO_URL in body["redirect_url"], f"SSO URL not in redirect: {body['redirect_url']}"
    assert "SAMLRequest" in body["redirect_url"], "SAMLRequest missing from redirect URL"


# ---------------------------------------------------------------------------
# Test 2 — Callback with mock SAMLResponse returns JWT pair
# ---------------------------------------------------------------------------

def test_saml_callback_returns_jwt_pair(saml_client):
    """GET /saml/{idp}/callback with a valid (unsigned) SAMLResponse returns access+refresh tokens."""
    client, mock_user_db = saml_client

    saml_response = _make_saml_response("alice@testcorp.example")

    resp = client.get(
        f"/api/v1/auth/saml/{IDP_NAME}/callback",
        params={"SAMLResponse": saml_response},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "access_token" in body, f"No access_token in response: {body}"
    assert "refresh_token" in body, f"No refresh_token in response: {body}"
    assert body["token_type"] == "bearer"
    assert body["idp_name"] == IDP_NAME
    assert body["email"] == "alice@testcorp.example"
    # Verify user lookup was attempted
    mock_user_db.get_user_by_email.assert_called_once_with("alice@testcorp.example")
