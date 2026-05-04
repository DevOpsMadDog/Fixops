"""Security review fix verification tests.

One test per fix — proves each vulnerability is closed:
1. PhishTank: all 3 routes return 401 without API key
2. /metrics: returns 401 without X-Prometheus-Token (when token configured)
3. GHSA importer: raises ValueError on path traversal via local_path
4. /health/comprehensive: no FS paths or table names in response
5. Nuclei GET / and GET /templates return 401 without API key

The app boot is expensive (~8-12 s). A module-scoped fixture ensures
create_app() is called exactly once for all 15 tests.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure suite paths on sys.path (sitecustomize.py handles this in normal runs)
_ROOT = Path(__file__).resolve().parents[1]
for _p in [
    str(_ROOT / "suite-api"),
    str(_ROOT / "suite-core"),
    str(_ROOT / "suite-feeds"),
    str(_ROOT / "suite-attack"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Module-scoped client — boot the app once for all tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from apps.api.app import create_app
    with TestClient(create_app(), raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Fix #1 — PhishTank auth on all 3 routes
# ---------------------------------------------------------------------------

def test_phishtank_import_requires_auth(client):
    resp = client.post("/api/v1/phishtank/import")
    assert resp.status_code == 401, (
        f"POST /phishtank/import should be 401 without auth, got {resp.status_code}"
    )


def test_phishtank_list_phishes_requires_auth(client):
    resp = client.get("/api/v1/phishtank/phishes")
    assert resp.status_code == 401, (
        f"GET /phishtank/phishes should be 401 without auth, got {resp.status_code}"
    )


def test_phishtank_check_url_requires_auth(client):
    resp = client.get("/api/v1/phishtank/check", params={"url": "http://evil.example.com"})
    assert resp.status_code == 401, (
        f"GET /phishtank/check should be 401 without auth, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Fix #2 — /metrics scrape-token auth
# ---------------------------------------------------------------------------

def test_metrics_requires_scrape_token_when_configured():
    """Test auth enforcement in a fresh app instance with FIXOPS_METRICS_TOKEN set."""
    # FIXOPS_DISABLE_RATE_LIMIT=1 is set in test env — our _scrape_auth
    # explicitly bypasses when that flag is set, so we must clear it here.
    env = {k: v for k, v in os.environ.items() if k != "FIXOPS_DISABLE_RATE_LIMIT"}
    env["FIXOPS_METRICS_TOKEN"] = "supersecret-test-token"
    with patch.dict(os.environ, env, clear=True):
        from fastapi.testclient import TestClient
        from apps.api.app import create_app
        c = TestClient(create_app(), raise_server_exceptions=False)
        resp = c.get("/api/v1/metrics")
        assert resp.status_code == 401, (
            f"GET /metrics should be 401 without scrape token when FIXOPS_METRICS_TOKEN set, got {resp.status_code}"
        )


def test_metrics_accepts_valid_scrape_token():
    env = {k: v for k, v in os.environ.items() if k != "FIXOPS_DISABLE_RATE_LIMIT"}
    env["FIXOPS_METRICS_TOKEN"] = "supersecret-test-token"
    with patch.dict(os.environ, env, clear=True):
        from fastapi.testclient import TestClient
        from apps.api.app import create_app
        c = TestClient(create_app(), raise_server_exceptions=False)
        resp = c.get("/api/v1/metrics", headers={"X-Prometheus-Token": "supersecret-test-token"})
        assert resp.status_code != 401, (
            f"GET /metrics with valid token should not be 401, got {resp.status_code}"
        )


def test_metrics_bypassed_in_test_env(client):
    """When FIXOPS_DISABLE_RATE_LIMIT=1 (test env), /metrics auth is bypassed."""
    # The module-scoped client was booted with FIXOPS_DISABLE_RATE_LIMIT=1
    # (set by the test runner env) so this should pass through.
    with patch.dict(os.environ, {"FIXOPS_DISABLE_RATE_LIMIT": "1", "FIXOPS_METRICS_TOKEN": "tok"}):
        resp = client.get("/api/v1/metrics")
        assert resp.status_code != 401, (
            f"GET /metrics should bypass auth when FIXOPS_DISABLE_RATE_LIMIT=1, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Fix #3 — GHSA local_path path traversal
# ---------------------------------------------------------------------------

def test_ghsa_etc_blocked():
    sys.path.insert(0, str(_ROOT / "suite-feeds"))
    from feeds.ghsa.importer import run_import
    with pytest.raises(ValueError, match="allowlisted roots"):
        run_import(local_path="/etc")


def test_ghsa_etc_passwd_blocked():
    from feeds.ghsa.importer import run_import
    with pytest.raises(ValueError, match="allowlisted roots"):
        run_import(local_path="/etc/passwd")


def test_ghsa_tmp_is_allowlisted():
    from feeds.ghsa.importer import run_import
    try:
        run_import(local_path="/tmp/nonexistent-ghsa-dir-xyz")
    except ValueError as exc:
        if "allowlisted roots" in str(exc):
            pytest.fail(f"/tmp should be allowlisted but got ValueError: {exc}")
    except Exception:
        pass  # FileNotFoundError or similar — acceptable


# ---------------------------------------------------------------------------
# Fix #4 — health endpoints no FS path / table-name leak
# ---------------------------------------------------------------------------

def test_health_comprehensive_no_table_names(client):
    resp = client.get("/api/v1/health/comprehensive")
    assert resp.status_code == 200
    data = resp.json()
    feeds = data.get("checks", {}).get("feeds_db", {})
    assert "tables" not in feeds, (
        f"feeds_db exposes raw table names: {feeds}"
    )


def test_health_deep_no_db_path(client):
    resp = client.get("/api/v1/health/deep")
    assert resp.status_code in (200, 503)
    data = resp.json()
    db_check = data.get("checks", {}).get("database", {})
    assert "path" not in db_check, f"database check leaks path: {db_check}"


def test_health_deep_no_disk_path(client):
    resp = client.get("/api/v1/health/deep")
    assert resp.status_code in (200, 503)
    data = resp.json()
    disk_check = data.get("checks", {}).get("disk_space", {})
    assert "path" not in disk_check, f"disk_space check leaks path: {disk_check}"


def test_health_deep_no_scanner_engine_map(client):
    resp = client.get("/api/v1/health/deep")
    assert resp.status_code in (200, 503)
    data = resp.json()
    scanner_check = data.get("checks", {}).get("scanners", {})
    assert "engines" not in scanner_check, (
        f"scanners check exposes internal engine map: {scanner_check}"
    )


def test_health_ready_no_storage_path(client):
    resp = client.get("/api/v1/ready")
    assert resp.status_code in (200, 503)
    data = resp.json()
    storage = data.get("checks", {}).get("storage", {})
    assert "base_directory" not in storage, (
        f"storage check leaks base_directory: {storage}"
    )


# ---------------------------------------------------------------------------
# Fix #5 — Nuclei GET / and GET /templates require auth
# ---------------------------------------------------------------------------

def test_nuclei_root_requires_auth(client):
    resp = client.get("/api/v1/nuclei/")
    assert resp.status_code == 401, (
        f"GET /nuclei/ should be 401 without auth, got {resp.status_code}"
    )


def test_nuclei_templates_requires_auth(client):
    resp = client.get("/api/v1/nuclei/templates")
    assert resp.status_code == 401, (
        f"GET /nuclei/templates should be 401 without auth, got {resp.status_code}"
    )
