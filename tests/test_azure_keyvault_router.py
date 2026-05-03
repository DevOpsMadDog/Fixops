"""Tests for azure_keyvault_router (Azure Key Vault REST proxy).

Covers:
- GET /                                              capability summary (unavailable + ok)
- GET /vaults                                        503 when unconfigured + live-stubbed shape
- GET /vaults/{name}/secrets                         live-stubbed shape
- GET /vaults/{name}/secrets/{secret}                live-stubbed shape
- GET /vaults/{name}/secrets/{secret}/versions       live-stubbed shape
- GET /vaults/{name}/keys                            live-stubbed shape
- GET /vaults/{name}/keys/{key}                      live-stubbed shape
- GET /vaults/{name}/certificates                    live-stubbed shape
- GET /vaults/{name}/certificates/{cert}             live-stubbed shape
- two scoped tokens cached independently

Usage:
    pytest tests/test_azure_keyvault_router.py -x --tb=short -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api on path.
for _p in ("suite-core", "suite-api"):
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def kv_env(monkeypatch):
    """Configure AZURE_* env for the engine."""
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-uuid-aaa")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-uuid-bbb")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-ccc")
    from core.azure_keyvault_engine import reset_azure_keyvault_engine
    reset_azure_keyvault_engine()
    yield
    reset_azure_keyvault_engine()


@pytest.fixture()
def no_kv_env(monkeypatch):
    """Ensure env is unset (NO MOCKS — must surface 503)."""
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    from core.azure_keyvault_engine import reset_azure_keyvault_engine
    reset_azure_keyvault_engine()
    yield
    reset_azure_keyvault_engine()


@pytest.fixture()
def app() -> FastAPI:
    from apps.api.azure_keyvault_router import router
    a = FastAPI()
    a.include_router(router)
    return a


@pytest.fixture()
def client(app) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# httpx stub helpers
# ---------------------------------------------------------------------------


def _install_httpx_stub(monkeypatch, handler):
    """Replace httpx.Client with a transport-mocked instance."""
    import httpx as _httpx

    real_client_init = _httpx.Client.__init__

    def _patched_init(self, *args, **kwargs):
        kwargs.pop("verify", None)
        kwargs["transport"] = _httpx.MockTransport(handler)
        real_client_init(self, *args, **kwargs)

    monkeypatch.setattr(_httpx.Client, "__init__", _patched_init)


def _make_handler(routes, token_calls):
    """Build a handler that resolves AAD token + Key Vault paths.

    Token calls are recorded with ``(scope,)`` so the test can assert
    independent caching of ARM-scoped vs vault-scoped tokens.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        path = request.url.path

        # AAD token endpoint (form-encoded body carries the requested scope).
        if "login.microsoftonline.com" in host and path.endswith("/oauth2/v2.0/token"):
            body = (request.content or b"").decode("utf-8", errors="ignore")
            scope = ""
            for chunk in body.split("&"):
                if chunk.startswith("scope="):
                    scope = chunk[len("scope=") :]
                    break
            token_calls.append(scope)
            return httpx.Response(
                200,
                json={
                    "token_type": "Bearer",
                    "expires_in": 3599,
                    "access_token": f"live-bearer-token-for-{scope or 'unknown'}",
                },
            )

        # Key Vault / ARM resource paths.
        for matcher, response in routes:
            if matcher(request):
                return response

        return httpx.Response(
            404,
            json={"error": f"no stub for {request.method} {host}{path}"},
        )

    return handler


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(client, no_kv_env):
    resp = client.get("/api/v1/azure-keyvault/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Azure Key Vault"
    assert body["azure_tenant_present"] is False
    assert body["azure_client_present"] is False
    assert body["status"] == "unavailable"
    for ep in (
        "/vaults",
        "/vaults/{name}/secrets",
        "/vaults/{name}/secrets/{secret}",
        "/vaults/{name}/keys",
        "/vaults/{name}/certificates",
    ):
        assert ep in body["endpoints"]


def test_capability_summary_ok_when_configured(client, kv_env):
    resp = client.get("/api/v1/azure-keyvault/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["azure_tenant_present"] is True
    assert body["azure_client_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 503 NO MOCKS path
# ---------------------------------------------------------------------------


def test_vaults_503_when_unconfigured(client, no_kv_env):
    resp = client.get(
        "/api/v1/azure-keyvault/vaults",
        params={"subscriptionId": "sub-1", "resourceGroupName": "rg-1"},
    )
    assert resp.status_code == 503
    assert "azure key vault" in resp.json()["detail"].lower()


def test_secrets_503_when_unconfigured(client, no_kv_env):
    resp = client.get("/api/v1/azure-keyvault/vaults/myvault/secrets")
    assert resp.status_code == 503


def test_get_secret_503_when_unconfigured(client, no_kv_env):
    resp = client.get("/api/v1/azure-keyvault/vaults/myvault/secrets/db-password")
    assert resp.status_code == 503


def test_keys_503_when_unconfigured(client, no_kv_env):
    resp = client.get("/api/v1/azure-keyvault/vaults/myvault/keys")
    assert resp.status_code == 503


def test_certificates_503_when_unconfigured(client, no_kv_env):
    resp = client.get("/api/v1/azure-keyvault/vaults/myvault/certificates")
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Live (stubbed) lookup paths
# ---------------------------------------------------------------------------


def test_list_vaults_live(client, kv_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": (
                    "/subscriptions/sub-1/resourceGroups/rg-1"
                    "/providers/Microsoft.KeyVault/vaults/myvault"
                ),
                "name": "myvault",
                "type": "Microsoft.KeyVault/vaults",
                "location": "eastus",
                "tags": {"env": "prod"},
                "properties": {
                    "tenantId": "tenant-uuid-aaa",
                    "sku": {"family": "A", "name": "standard"},
                    "accessPolicies": [],
                    "enabledForDeployment": False,
                    "enabledForDiskEncryption": False,
                    "enabledForTemplateDeployment": False,
                    "enableSoftDelete": True,
                    "softDeleteRetentionInDays": 90,
                    "enableRbacAuthorization": True,
                    "enablePurgeProtection": True,
                    "vaultUri": "https://myvault.vault.azure.net/",
                    "networkAcls": {},
                    "publicNetworkAccess": "Disabled",
                },
                "systemData": {},
            }
        ],
        "nextLink": None,
    }

    def _is_vaults(req):
        return (
            req.method == "GET"
            and req.url.host == "management.azure.com"
            and req.url.path
            == "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults"
        )

    handler = _make_handler(
        [(_is_vaults, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/azure-keyvault/vaults",
        params={"subscriptionId": "sub-1", "resourceGroupName": "rg-1", "top": 10},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["name"] == "myvault"
    assert body["value"][0]["properties"]["enableRbacAuthorization"] is True
    # Only ARM scope token was needed.
    assert len(token_calls) == 1
    assert "management.azure.com" in token_calls[0]


def test_list_secrets_live(client, kv_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "https://myvault.vault.azure.net/secrets/db-password",
                "attributes": {
                    "enabled": True,
                    "created": 1700000000,
                    "updated": 1700000000,
                    "exp": None,
                    "nbf": None,
                    "recoveryLevel": "Recoverable+Purgeable",
                },
                "contentType": "text/plain",
                "tags": {"app": "billing"},
                "managed": False,
            }
        ],
        "nextLink": None,
    }

    def _is_secrets(req):
        return (
            req.method == "GET"
            and req.url.host == "myvault.vault.azure.net"
            and req.url.path == "/secrets"
        )

    handler = _make_handler(
        [(_is_secrets, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/azure-keyvault/vaults/myvault/secrets",
        params={"maxresults": 25},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["attributes"]["enabled"] is True
    assert "db-password" in body["value"][0]["id"]
    # Only data-plane scope token was needed.
    assert len(token_calls) == 1
    assert "vault.azure.net" in token_calls[0]


def test_get_secret_live(client, kv_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": "s3cret-value",
        "id": "https://myvault.vault.azure.net/secrets/db-password/0123abcd",
        "attributes": {
            "enabled": True,
            "created": 1700000000,
            "updated": 1700000000,
            "recoveryLevel": "Recoverable+Purgeable",
        },
        "contentType": "text/plain",
        "tags": {"app": "billing"},
    }

    def _is_secret(req):
        return (
            req.method == "GET"
            and req.url.host == "myvault.vault.azure.net"
            and req.url.path == "/secrets/db-password"
        )

    handler = _make_handler(
        [(_is_secret, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/azure-keyvault/vaults/myvault/secrets/db-password",
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"] == "s3cret-value"
    assert body["attributes"]["enabled"] is True


def test_list_secret_versions_live(client, kv_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "https://myvault.vault.azure.net/secrets/db-password/v1",
                "attributes": {"enabled": True, "created": 1690000000, "updated": 1690000000},
            },
            {
                "id": "https://myvault.vault.azure.net/secrets/db-password/v2",
                "attributes": {"enabled": True, "created": 1700000000, "updated": 1700000000},
            },
        ],
        "nextLink": None,
    }

    def _is_versions(req):
        return (
            req.method == "GET"
            and req.url.host == "myvault.vault.azure.net"
            and req.url.path == "/secrets/db-password/versions"
        )

    handler = _make_handler(
        [(_is_versions, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get(
        "/api/v1/azure-keyvault/vaults/myvault/secrets/db-password/versions",
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["value"]) == 2


def test_list_keys_live(client, kv_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "kid": "https://myvault.vault.azure.net/keys/signing-key",
                "attributes": {
                    "enabled": True,
                    "created": 1700000000,
                    "updated": 1700000000,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "exportable": False,
                },
                "tags": {"role": "signing"},
                "managed": False,
            }
        ],
        "nextLink": None,
    }

    def _is_keys(req):
        return (
            req.method == "GET"
            and req.url.host == "myvault.vault.azure.net"
            and req.url.path == "/keys"
        )

    handler = _make_handler(
        [(_is_keys, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/azure-keyvault/vaults/myvault/keys")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["attributes"]["exportable"] is False
    assert body["value"][0]["kid"].endswith("/keys/signing-key")


def test_get_key_live(client, kv_env, monkeypatch):
    token_calls: list = []
    payload = {
        "key": {
            "kid": "https://myvault.vault.azure.net/keys/signing-key/0a1b2c",
            "kty": "RSA",
            "key_ops": ["sign", "verify"],
            "n": "modulus-base64url",
            "e": "AQAB",
        },
        "attributes": {
            "enabled": True,
            "created": 1700000000,
            "updated": 1700000000,
            "recoveryLevel": "Recoverable+Purgeable",
            "exportable": False,
        },
        "tags": {"role": "signing"},
        "managed": False,
        "release_policy": {},
    }

    def _is_key(req):
        return (
            req.method == "GET"
            and req.url.host == "myvault.vault.azure.net"
            and req.url.path == "/keys/signing-key"
        )

    handler = _make_handler(
        [(_is_key, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/azure-keyvault/vaults/myvault/keys/signing-key")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["key"]["kty"] == "RSA"
    assert body["key"]["e"] == "AQAB"
    assert "sign" in body["key"]["key_ops"]


def test_list_certificates_live(client, kv_env, monkeypatch):
    token_calls: list = []
    payload = {
        "value": [
            {
                "id": "https://myvault.vault.azure.net/certificates/web-tls",
                "attributes": {
                    "enabled": True,
                    "created": 1700000000,
                    "updated": 1700000000,
                    "recoveryLevel": "Recoverable+Purgeable",
                    "expires": 1900000000,
                    "nbf": 1690000000,
                },
                "tags": {"app": "web"},
                "x5t": "thumbprint-base64url",
            }
        ],
        "nextLink": None,
    }

    def _is_certs(req):
        return (
            req.method == "GET"
            and req.url.host == "myvault.vault.azure.net"
            and req.url.path == "/certificates"
        )

    handler = _make_handler(
        [(_is_certs, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/azure-keyvault/vaults/myvault/certificates")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["value"][0]["attributes"]["enabled"] is True
    assert body["value"][0]["x5t"] == "thumbprint-base64url"


def test_get_certificate_live(client, kv_env, monkeypatch):
    token_calls: list = []
    payload = {
        "id": "https://myvault.vault.azure.net/certificates/web-tls/0a1b",
        "kid": "https://myvault.vault.azure.net/keys/web-tls/0a1b",
        "sid": "https://myvault.vault.azure.net/secrets/web-tls/0a1b",
        "x5t": "thumbprint-base64url",
        "cer": "MIIB...base64-DER...",
        "attributes": {
            "enabled": True,
            "created": 1700000000,
            "updated": 1700000000,
        },
        "policy": {
            "key_props": {
                "exportable": False,
                "kty": "RSA",
                "key_size": 2048,
                "reuse_key": False,
            },
            "secret_props": {"contentType": "application/x-pkcs12"},
            "x509_props": {
                "subject": "CN=web.example.com",
                "sans": ["web.example.com"],
                "ekus": ["1.3.6.1.5.5.7.3.1"],
                "key_usage": ["digitalSignature", "keyEncipherment"],
                "validity_months": 12,
            },
            "lifetime_actions": [
                {
                    "trigger": {"lifetime_percentage": 80, "days_before_expiry": None},
                    "action": {"action_type": "AutoRenew"},
                }
            ],
            "issuer": {"name": "Self", "cert_transparency": False},
        },
        "tags": {"app": "web"},
    }

    def _is_cert(req):
        return (
            req.method == "GET"
            and req.url.host == "myvault.vault.azure.net"
            and req.url.path == "/certificates/web-tls"
        )

    handler = _make_handler(
        [(_is_cert, httpx.Response(200, json=payload))],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    resp = client.get("/api/v1/azure-keyvault/vaults/myvault/certificates/web-tls")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["policy"]["x509_props"]["subject"] == "CN=web.example.com"
    assert body["policy"]["lifetime_actions"][0]["action"]["action_type"] == "AutoRenew"
    assert body["cer"].startswith("MIIB")


# ---------------------------------------------------------------------------
# Token cache — two scopes cached independently
# ---------------------------------------------------------------------------


def test_two_scopes_cached_independently(client, kv_env, monkeypatch):
    """ARM-scope token + KV-scope token should each be fetched exactly once."""
    token_calls: list = []
    vaults_payload = {"value": [], "nextLink": None}
    secrets_payload = {"value": [], "nextLink": None}

    def _is_vaults(req):
        return (
            req.method == "GET"
            and req.url.host == "management.azure.com"
            and req.url.path
            == "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults"
        )

    def _is_secrets(req):
        return (
            req.method == "GET"
            and req.url.host == "myvault.vault.azure.net"
            and req.url.path == "/secrets"
        )

    handler = _make_handler(
        [
            (_is_vaults, httpx.Response(200, json=vaults_payload)),
            (_is_secrets, httpx.Response(200, json=secrets_payload)),
        ],
        token_calls,
    )
    _install_httpx_stub(monkeypatch, handler)

    # 2x ARM call — should issue exactly 1 ARM token.
    for _ in range(2):
        resp = client.get(
            "/api/v1/azure-keyvault/vaults",
            params={"subscriptionId": "sub-1", "resourceGroupName": "rg-1"},
        )
        assert resp.status_code == 200, resp.text

    # 2x data-plane call — should issue exactly 1 KV token.
    for _ in range(2):
        resp = client.get("/api/v1/azure-keyvault/vaults/myvault/secrets")
        assert resp.status_code == 200, resp.text

    # 4 API calls total → exactly 2 token fetches (one per scope).
    assert len(token_calls) == 2
    arm_tokens = [s for s in token_calls if "management.azure.com" in s]
    kv_tokens = [s for s in token_calls if "vault.azure.net" in s]
    assert len(arm_tokens) == 1
    assert len(kv_tokens) == 1


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_vaults_validation_requires_query_params(client, kv_env):
    resp = client.get("/api/v1/azure-keyvault/vaults")
    assert resp.status_code == 422


def test_get_secret_rejects_invalid_vault_name(client, kv_env):
    # Vault name length 3-24; "ab" is too short.
    resp = client.get("/api/v1/azure-keyvault/vaults/ab/secrets/db-password")
    assert resp.status_code == 422
