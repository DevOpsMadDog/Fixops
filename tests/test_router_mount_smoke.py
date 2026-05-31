"""Smoke test — verify 5 newly-mounted router prefixes appear in create_app().routes.

Run:
    PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-integrations:suite-evidence-risk:archive/legacy:archive/enterprise_legacy" \
    python -m pytest tests/test_router_mount_smoke.py -p no:cacheprovider --tb=short --timeout=20 -q -o "addopts="
"""
from apps.api.app import create_app
import pytest


@pytest.fixture(scope="module")
def routes():
    return [r.path for r in create_app().routes]


@pytest.mark.parametrize("prefix", [
    "/api/v1/otx",
    "/api/v1/bandit",
    "/api/v1/pyrit",
    "/api/v1/connectors/defender-xdr",
    "/api/v1/helicone",
])
def test_router_mounted(routes, prefix):
    assert any(p.startswith(prefix) for p in routes), f"{prefix} not mounted"
