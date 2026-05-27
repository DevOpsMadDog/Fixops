"""Tests for the Local File Store API router (/api/v1/local-file-store).

Tests:
  - real temp dir with real files -> list returns them (real name/size/mtime)
  - stats counts match actual files
  - empty / absent dir -> honest empty result, no fabrication
  - config endpoint -> 200 with real root_path + settings
  - router -> 200 (not 404) for all 3 paths
"""
from __future__ import annotations

import hashlib
import importlib
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Auth bypass — patch api_key_auth before importing the router
# ---------------------------------------------------------------------------

async def _noop_auth():
    return None


# We need a stable reference to the module so we can reload it per-test
import apps.api.auth_deps as _auth_deps_mod  # noqa: E402

_orig_api_key_auth = _auth_deps_mod.api_key_auth


@pytest.fixture(autouse=True)
def _bypass_auth(monkeypatch):
    """Replace api_key_auth with a no-op dependency."""
    monkeypatch.setattr(_auth_deps_mod, "api_key_auth", _noop_auth)
    yield
    monkeypatch.setattr(_auth_deps_mod, "api_key_auth", _orig_api_key_auth)


# ---------------------------------------------------------------------------
# Client factory — injects env vars and reloads the router module
# ---------------------------------------------------------------------------

def _make_client(store_dir: str, quota: int = 100 * 1024 * 1024) -> TestClient:
    """Create a TestClient with the store dir injected via env + module reload."""
    os.environ["FIXOPS_LOCAL_FILE_STORE_DIR"] = store_dir
    os.environ["FIXOPS_LOCAL_FILE_STORE_QUOTA"] = str(quota)

    # Reload the router so _store_root() and _quota_bytes() pick up fresh env
    import apps.api.local_file_store_api_router as mod  # noqa: PLC0415
    importlib.reload(mod)

    app = FastAPI()
    app.include_router(mod.router)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Tests — real files
# ---------------------------------------------------------------------------

class TestListWithRealFiles:
    def test_list_returns_real_files(self, tmp_path):
        """list endpoint returns actual files, not fabricated ones."""
        f1 = tmp_path / "scan_result.json"
        f1.write_text('{"findings": []}', encoding="utf-8")
        f2 = tmp_path / "sbom_export.cdx"
        f2.write_bytes(b"\x00\x01\x02" * 100)

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200, resp.text
        items = resp.json()
        assert isinstance(items, list)
        names = {i["name"] for i in items}
        assert "scan_result.json" in names
        assert "sbom_export.cdx" in names

    def test_list_real_size(self, tmp_path):
        """size_bytes matches actual file size."""
        content = b"x" * 1234
        (tmp_path / "artifact.bin").write_bytes(content)

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200
        items = resp.json()
        match = next(i for i in items if i["name"] == "artifact.bin")
        assert match["size_bytes"] == 1234

    def test_list_real_sha256(self, tmp_path):
        """sha256 matches actual file content."""
        content = b"hello aldeci"
        (tmp_path / "check.json").write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200
        items = resp.json()
        match = next(i for i in items if i["name"] == "check.json")
        assert match["sha256"] == expected

    def test_list_kind_inference(self, tmp_path):
        """kind is inferred from extension."""
        cases = {
            "report.pdf": "report",
            "bundle.zip": "archive",
            "output.sarif": "sarif",
            "bom.cdx": "sbom",
            "data.json": "json",
            "unknown.xyz": "blob",
        }
        for fname in cases:
            (tmp_path / fname).write_bytes(b"data")

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200
        items = {i["name"]: i["kind"] for i in resp.json()}
        for fname, expected_kind in cases.items():
            assert items.get(fname) == expected_kind, f"{fname}: got {items.get(fname)!r} != {expected_kind!r}"

    def test_list_created_at_is_real_iso(self, tmp_path):
        """created_at is a parseable ISO-8601 timestamp."""
        from datetime import datetime
        (tmp_path / "t.json").write_bytes(b"{}")

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        ts = items[0]["created_at"]
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt.year >= 2024


# ---------------------------------------------------------------------------
# Tests — stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_counts_match_files(self, tmp_path):
        """total_files and total_size_bytes reflect actual disk state."""
        sizes = [100, 200, 300]
        for i, sz in enumerate(sizes):
            (tmp_path / f"file_{i}.json").write_bytes(b"a" * sz)

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_files"] == 3
        assert data["total_size_bytes"] == sum(sizes)

    def test_stats_quota_reflects_env(self, tmp_path):
        """quota_bytes comes from env."""
        client = _make_client(str(tmp_path), quota=100 * 1024 * 1024)
        resp = client.get("/api/v1/local-file-store/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["quota_bytes"] == 100 * 1024 * 1024

    def test_stats_used_pct(self, tmp_path):
        """used_pct is total_size / quota * 100."""
        quota = 100 * 1024 * 1024
        size = 1024 * 1024  # 1 MiB
        (tmp_path / "f.bin").write_bytes(b"x" * size)

        client = _make_client(str(tmp_path), quota=quota)
        resp = client.get("/api/v1/local-file-store/stats")
        assert resp.status_code == 200
        data = resp.json()
        expected_pct = round((size / quota) * 100, 2)
        assert abs(data["used_pct"] - expected_pct) < 0.01

    def test_stats_latest_is_set_when_files_exist(self, tmp_path):
        """latest field is non-null when files exist."""
        (tmp_path / "f.json").write_bytes(b"{}")

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["latest"] is not None


# ---------------------------------------------------------------------------
# Tests — empty / absent store
# ---------------------------------------------------------------------------

class TestEmptyStore:
    def test_list_empty_dir(self, tmp_path):
        """Empty real dir -> empty list, not fabricated files."""
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_absent_dir(self, tmp_path):
        """Non-existent dir -> empty list (no crash)."""
        absent = str(tmp_path / "does_not_exist")
        client = _make_client(absent)
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_stats_absent_dir(self, tmp_path):
        """Non-existent dir -> zeros in stats, no crash."""
        absent = str(tmp_path / "does_not_exist")
        client = _make_client(absent)
        resp = client.get("/api/v1/local-file-store/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_files"] == 0
        assert data["total_size_bytes"] == 0
        assert data["oldest"] is None
        assert data["latest"] is None

    def test_stats_empty_dir(self, tmp_path):
        """Empty real dir -> zeros in stats."""
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_files"] == 0
        assert data["total_size_bytes"] == 0


# ---------------------------------------------------------------------------
# Tests — config endpoint
# ---------------------------------------------------------------------------

class TestConfig:
    def test_config_200(self, tmp_path):
        """/config returns 200 always."""
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/config")
        assert resp.status_code == 200

    def test_config_root_path(self, tmp_path):
        """root_path reflects the configured store dir."""
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["root_path"] == str(tmp_path)

    def test_config_shape(self, tmp_path):
        """Config has the fields the UI expects."""
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/config")
        assert resp.status_code == 200
        data = resp.json()
        expected_keys = {"root_path", "max_size_bytes", "encryption", "retention_days", "compression", "replicas"}
        assert expected_keys.issubset(data.keys()), f"Missing keys: {expected_keys - set(data.keys())}"

    def test_config_max_size_bytes(self, tmp_path):
        """max_size_bytes matches FIXOPS_LOCAL_FILE_STORE_QUOTA env."""
        client = _make_client(str(tmp_path), quota=100 * 1024 * 1024)
        resp = client.get("/api/v1/local-file-store/config")
        assert resp.status_code == 200
        assert resp.json()["max_size_bytes"] == 100 * 1024 * 1024

    def test_config_encryption_default(self, tmp_path, monkeypatch):
        """encryption defaults to 'none' when env not set."""
        monkeypatch.delenv("FIXOPS_LOCAL_FILE_STORE_ENCRYPTION", raising=False)
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/config")
        assert resp.status_code == 200
        assert resp.json()["encryption"] == "none"

    def test_config_replicas_default(self, tmp_path, monkeypatch):
        """replicas defaults to 1 when env not set."""
        monkeypatch.delenv("FIXOPS_LOCAL_FILE_STORE_REPLICAS", raising=False)
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/config")
        assert resp.status_code == 200
        assert resp.json()["replicas"] == 1


# ---------------------------------------------------------------------------
# Tests — subdirectory traversal
# ---------------------------------------------------------------------------

class TestSubdirTraversal:
    def test_list_traverses_subdirs(self, tmp_path):
        """Files in subdirectories are included in list."""
        subdir = tmp_path / "sbom" / "2026"
        subdir.mkdir(parents=True)
        (subdir / "bom.cdx").write_bytes(b"bom data")
        (tmp_path / "root_file.json").write_bytes(b"{}")

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200
        names = {i["name"] for i in resp.json()}
        assert "bom.cdx" in names
        assert "root_file.json" in names

    def test_list_path_is_relative(self, tmp_path):
        """path field is relative to store root, not absolute."""
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "f.json").write_bytes(b"{}")

        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code == 200
        items = resp.json()
        paths = [i["path"] for i in items]
        for p in paths:
            assert not Path(p).is_absolute(), f"path should be relative: {p}"


# ---------------------------------------------------------------------------
# Tests — route existence (not 404)
# ---------------------------------------------------------------------------

class TestRouteExistence:
    def test_stats_not_404(self, tmp_path):
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/stats")
        assert resp.status_code != 404, "stats endpoint missing"

    def test_list_not_404(self, tmp_path):
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/list")
        assert resp.status_code != 404, "list endpoint missing"

    def test_config_not_404(self, tmp_path):
        client = _make_client(str(tmp_path))
        resp = client.get("/api/v1/local-file-store/config")
        assert resp.status_code != 404, "config endpoint missing"
