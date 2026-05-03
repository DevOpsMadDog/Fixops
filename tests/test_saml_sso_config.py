"""
Tests for GET /api/v1/auth/sso/saml/config — SAML SP runtime config endpoint.

Coverage:
- 200 with valid SAML env → correct sp_entity_id, acs_url, slo_url, metadata_xml
- metadata_xml is well-formed XML containing SP entity ID
- 503 when SSO is disabled (FIXOPS_SSO_ENABLED not set)
- 400 when active provider is OIDC, not generic_saml
- allowed_domains forwarded from env
- idp_metadata_url forwarded from env

Run:
    pytest tests/test_saml_sso_config.py -x --tb=short --timeout=10 -q
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Ensure suite paths are importable
_suite_core = str(Path(__file__).parent.parent / "suite-core")
_suite_api = str(Path(__file__).parent.parent / "suite-api")
for _p in (_suite_core, _suite_api):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from apps.api.sso_router import router
from fastapi import FastAPI

# ---------------------------------------------------------------------------
# App fixture — mount only the SSO router to keep tests isolated
# ---------------------------------------------------------------------------

_app = FastAPI()
_app.include_router(router)
_client = TestClient(_app, raise_server_exceptions=True)

_SAML_ENV = {
    "FIXOPS_SSO_ENABLED": "1",
    "FIXOPS_SSO_PROVIDER": "generic_saml",
    "FIXOPS_SP_ENTITY_ID": "https://aldeci.test/sso/sp",
    "FIXOPS_SAML_IDP_METADATA_URL": "https://idp.test/metadata",
    "FIXOPS_SSO_ALLOWED_DOMAINS": "corp.test,sub.corp.test",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSAMLSPConfigEndpoint:
    def test_returns_200_with_correct_sp_entity_id(self, monkeypatch):
        for k, v in _SAML_ENV.items():
            monkeypatch.setenv(k, v)
        resp = _client.get("/api/v1/auth/sso/saml/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["sp_entity_id"] == "https://aldeci.test/sso/sp"

    def test_acs_and_slo_urls_derived_from_entity_id(self, monkeypatch):
        for k, v in _SAML_ENV.items():
            monkeypatch.setenv(k, v)
        data = _client.get("/api/v1/auth/sso/saml/config").json()
        assert data["acs_url"] == "https://aldeci.test/sso/sp/acs"
        assert data["slo_url"] == "https://aldeci.test/sso/sp/slo"

    def test_metadata_xml_is_valid_xml_containing_entity_id(self, monkeypatch):
        for k, v in _SAML_ENV.items():
            monkeypatch.setenv(k, v)
        data = _client.get("/api/v1/auth/sso/saml/config").json()
        xml_str = data["metadata_xml"]
        # Must be parseable
        root = ET.fromstring(xml_str)
        # Entity ID must appear in the XML
        assert "aldeci.test/sso/sp" in xml_str

    def test_503_when_sso_disabled(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_SSO_ENABLED", raising=False)
        resp = _client.get("/api/v1/auth/sso/saml/config")
        assert resp.status_code == 503
        assert "not enabled" in resp.json()["detail"].lower()

    def test_400_when_active_provider_is_oidc(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_SSO_ENABLED", "1")
        monkeypatch.setenv("FIXOPS_SSO_PROVIDER", "okta")
        monkeypatch.setenv("FIXOPS_OIDC_CLIENT_ID", "cid")
        monkeypatch.setenv("FIXOPS_OIDC_CLIENT_SECRET", "csec")
        monkeypatch.setenv("FIXOPS_OIDC_ISSUER_URL", "https://example.okta.com")
        resp = _client.get("/api/v1/auth/sso/saml/config")
        assert resp.status_code == 400
        assert "generic_saml" in resp.json()["detail"]

    def test_allowed_domains_forwarded(self, monkeypatch):
        for k, v in _SAML_ENV.items():
            monkeypatch.setenv(k, v)
        data = _client.get("/api/v1/auth/sso/saml/config").json()
        assert "corp.test" in data["allowed_domains"]
        assert "sub.corp.test" in data["allowed_domains"]

    def test_idp_metadata_url_forwarded(self, monkeypatch):
        for k, v in _SAML_ENV.items():
            monkeypatch.setenv(k, v)
        data = _client.get("/api/v1/auth/sso/saml/config").json()
        assert data["idp_metadata_url"] == "https://idp.test/metadata"
