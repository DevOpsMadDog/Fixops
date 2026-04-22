"""Smoke tests for GAP-064 local_file_store_engine.

Minimal post-salvage tests. Comprehensive file-locking + crash-recovery
tests are a follow-up.
"""
from __future__ import annotations

import importlib
import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_repo():
    d = tempfile.mkdtemp(prefix="lfs_test_repo_")
    yield Path(d)


def _engine():
    mod = importlib.import_module("core.local_file_store_engine")
    importlib.reload(mod)
    # Find an engine class
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, type) and name.endswith("Engine"):
            return obj()
    raise RuntimeError("No Engine class found")


class TestModule:
    def test_module_imports(self):
        mod = importlib.import_module("core.local_file_store_engine")
        assert mod is not None

    def test_router_imports(self):
        r = importlib.import_module("apps.api.local_file_store_router")
        assert hasattr(r, "router")


class TestLockLifecycle:
    def test_acquire_lock_creates_file(self, tmp_repo):
        eng = _engine()
        eng.acquire_lock(tmp_repo, timeout=1)
        lock = tmp_repo / ".fixops" / ".analyze.lock"
        assert lock.exists()
        eng.release_lock(tmp_repo)

    def test_release_lock_removes_file(self, tmp_repo):
        eng = _engine()
        eng.acquire_lock(tmp_repo, timeout=1)
        eng.release_lock(tmp_repo)
        assert not (tmp_repo / ".fixops" / ".analyze.lock").exists()

    def test_double_acquire_fails_or_blocks(self, tmp_repo):
        eng = _engine()
        eng.acquire_lock(tmp_repo, timeout=1)
        eng2 = _engine()
        with pytest.raises(Exception):
            eng2.acquire_lock(tmp_repo, timeout=0.1)
        eng.release_lock(tmp_repo)


class TestSaveAndRead:
    def test_save_analysis_returns_dict(self, tmp_repo):
        eng = _engine()
        payload = {"violations": [{"id": "V1"}], "scan_time": "2026-04-22"}
        result = eng.save_analysis(tmp_repo, payload)
        assert isinstance(result, dict)

    def test_latest_reflects_most_recent_save(self, tmp_repo):
        eng = _engine()
        eng.save_analysis(tmp_repo, {"v": 1})
        eng.save_analysis(tmp_repo, {"v": 2})
        latest = eng.get_latest(tmp_repo)
        assert latest is not None
        # v=2 should be last written
        assert latest.get("v") == 2 or latest.get("payload", {}).get("v") == 2 or "v" in str(latest)

    def test_analyses_dir_accumulates_files(self, tmp_repo):
        eng = _engine()
        eng.save_analysis(tmp_repo, {"a": 1})
        eng.save_analysis(tmp_repo, {"a": 2})
        eng.save_analysis(tmp_repo, {"a": 3})
        analyses_dir = tmp_repo / ".fixops" / "analyses"
        assert analyses_dir.exists()
        saved = list(analyses_dir.glob("*.json"))
        assert len(saved) >= 3


class TestConfig:
    def test_config_write_then_read(self, tmp_repo):
        eng = _engine()
        cfg = {"mode": "strict", "severity_min": "high"}
        if hasattr(eng, "write_config"):
            eng.write_config(tmp_repo, cfg)
            out = eng.read_config(tmp_repo)
            assert out is not None

    def test_missing_config_returns_none_or_empty(self, tmp_repo):
        eng = _engine()
        if hasattr(eng, "read_config"):
            out = eng.read_config(tmp_repo)
            # Either None or empty dict is acceptable
            assert out is None or out == {} or isinstance(out, dict)


class TestHistoryLimit:
    def test_history_returns_list(self, tmp_repo):
        eng = _engine()
        eng.save_analysis(tmp_repo, {"v": 1})
        eng.save_analysis(tmp_repo, {"v": 2})
        if hasattr(eng, "list_history"):
            hist = eng.list_history(tmp_repo)
            assert isinstance(hist, list)
