"""
Smoke test: every patched router prefix must return 200 or 401 on GET /.

Run with:
    pytest tests/test_router_index_routes.py -x --tb=short --timeout=60 -q
"""
from __future__ import annotations

import sys
import os

# Ensure suite paths are importable
for p in ["suite-api", "suite-core", "suite-attack", "suite-feeds", "suite-evidence-risk", "suite-integrations", "."]:
    abs_p = os.path.join(os.path.dirname(__file__), "..", p)
    if abs_p not in sys.path:
        sys.path.insert(0, abs_p)

import pytest
from fastapi.testclient import TestClient

# Boot the app once at module import time so fixture creation is instant
# and does not race against per-test timeouts.
def _build_client() -> TestClient:
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)

_CLIENT: TestClient | None = None


@pytest.fixture(scope="session")
def client() -> TestClient:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = _build_client()
    return _CLIENT


# Prefixes that MUST return 200 or 401 on GET /api/v1/<prefix>/
ROUTER_PREFIXES = [
    "audit",
    "brain",
    "autofix",
    "assets",
    "analytics",
    "attack-paths",
    "webhooks",
    "air-gap",
    "risk",
    "threat-intel",
    "soar",
    "connectors",
    "incidents",
    "phishing",
    "api-security-engine",
    "openclaw",
    "dca",
    "vuln-intel",
    "ml",
    "posture-advisor",
    "exec-reporting",
    "cspm",
    "tip",
    "fail",
    "graph",
    "supply-chain",
    "rules",
    "organizations",
    # compliance already has GET / in compliance_automation_router
    "compliance",
]


@pytest.mark.timeout(60)
@pytest.mark.parametrize("prefix", ROUTER_PREFIXES)
def test_router_index_returns_non_404(client: TestClient, prefix: str) -> None:
    """GET /api/v1/<prefix>/ must not 404 (may be 200 or 401 if auth-gated)."""
    url = f"/api/v1/{prefix}/"
    resp = client.get(url)
    assert resp.status_code != 404, (
        f"GET {url} returned 404 — missing GET / on router '{prefix}'. "
        f"Got: {resp.status_code} {resp.text[:200]}"
    )
    assert resp.status_code in (200, 401, 403, 422), (
        f"GET {url} returned unexpected status {resp.status_code}: {resp.text[:200]}"
    )
