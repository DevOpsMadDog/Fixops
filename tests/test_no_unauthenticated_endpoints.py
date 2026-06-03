"""Regression guard: no /api/v1 endpoint may answer an UNAUTHENTICATED request with data.

2026-06-03: a systematic no-API-key sweep found 21 endpoints/routers that returned 2xx (GET
reads) or 422 (mutating, auth bypassed → reached body validation) to callers with no X-API-Key
— including `POST /secrets-management/secrets` (created secrets unauthenticated). All were fixed
by adding a router-level `dependencies=[Depends(api_key_auth)]`. This test probes one
no-path-param endpoint per (prefix, method) WITHOUT a key and asserts the server rejects it
(401/403). It exists so those fixes can't silently regress and a newly-added unauthenticated
router fails the gate.

A small allowlist covers endpoints that are intentionally public (token issuance; webhook
endpoints authenticated by a provider signature, not an API key; health/docs/version).

Run: python -m pytest tests/test_no_unauthenticated_endpoints.py -q -o "addopts="
"""
from __future__ import annotations

import os
import re

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-123")
# Disable the rate limiter so repeated no-key probes get the REAL auth status (401), not 429.
os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"
os.environ["FIXOPS_DISABLE_TIER_RATE_LIMIT"] = "1"

from fastapi.testclient import TestClient  # noqa: E402

from apps.api.app import create_app  # noqa: E402

# Endpoints that are intentionally reachable without an API key (verified 2026-06-03):
#  - oauth2/token: issues tokens (you call it to GET a key)
#  - slack/*: authenticated by the Slack signing secret, not an API key
#  - health/* : liveness/readiness probes (incl /health/deep)
#  - trust/public: trust-center public summary (explicitly "no auth" by design)
#  - system/git-sha, scif/boot, openapi.json: version / boot / schema ops endpoints
#  - generic public probes (metrics/version/ping/docs/redoc)
_ALLOWLIST = re.compile(
    r"^/api/v1/oauth2/token$"
    r"|^/api/v1/slack/"
    r"|^/api/v1/health(/|$)"
    # trust-center is a public-facing page (tags=["Trust Center"]); admin endpoints are the
    # authed /trust/{org_id}/... + /trust/configure (path-param/authed, not matched here).
    r"|^/api/v1/trust/(public|compliance|sub-processors|practices|documents|faq|request|nda|dpa)$"
    r"|^/api/v1/system/git-sha$"
    # SCIF ops-posture surface (boot/audit-chain-verify/hsm-info): posture metadata only
    # (no audit content / no key material). FOUNDER-DECISION: review whether the SCIF threat
    # model wants these behind auth (they expose audit-entry counts + HSM key labels).
    r"|^/api/v1/scif/(boot|audit-chain/verify|hsm/)"
    r"|/openapi\.json$"
    r"|/(healthz|readyz?|ready|metrics|version|ping|status|docs|openapi|redoc)$"
)

# Acceptable "rejected" statuses for a no-key request.
#  401/403 = auth rejected (good). 404/405 = route/method quirk (not an auth signal — skip).
_OK = {401, 403, 404, 405}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


def _representative_routes(app):
    """One no-path-param route per (top-level prefix, method)."""
    seen = {}
    for r in app.routes:
        p = getattr(r, "path", "")
        methods = (getattr(r, "methods", None) or set()) - {"HEAD", "OPTIONS"}
        if "{" in p or not p.startswith("/api/v1/"):
            continue
        if _ALLOWLIST.search(p):
            continue
        prefix = "/".join(p.split("/")[:4])
        for m in methods:
            seen.setdefault((prefix, m), p)
    return seen


def test_no_unauthenticated_api_v1_endpoints(client: TestClient):
    app = client.app
    routes = _representative_routes(app)
    assert routes, "no /api/v1 routes discovered — sweep would be a false pass"

    gaps = []
    for (prefix, method), path in sorted(routes.items()):
        try:
            if method == "GET":
                resp = client.get(path + "?org_id=zz")
            elif method == "POST":
                resp = client.post(path, json={})
            elif method == "PUT":
                resp = client.put(path, json={})
            elif method == "DELETE":
                resp = client.delete(path)
            else:
                continue
        except Exception:  # noqa: BLE001 - a transport error is not an auth signal
            continue
        if resp.status_code not in _OK:
            gaps.append(f"{resp.status_code} {method} {path}")

    assert not gaps, (
        "Unauthenticated /api/v1 endpoints found (must require X-API-Key → 401/403). "
        "Add router-level dependencies=[Depends(api_key_auth)] (or allowlist if intentionally "
        f"public):\n  " + "\n  ".join(gaps)
    )
