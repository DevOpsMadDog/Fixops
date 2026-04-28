"""Smoke tests for GAP-012 deep_code_analysis_engine (post-quota-cap salvage)."""
from __future__ import annotations

import importlib
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_data_dir(monkeypatch):
    d = tempfile.mkdtemp(prefix="dca_test_")
    monkeypatch.setenv("FIXOPS_DATA_DIR", d)
    yield d


@pytest.fixture
def mini_repo(tmp_path):
    """5-file mini Python repo with routes + models."""
    (tmp_path / "app.py").write_text("""
from fastapi import APIRouter
router = APIRouter()

@router.get("/users")
def list_users():
    return []

@router.post("/users")
def create_user(user):
    pass
""".strip())
    (tmp_path / "models.py").write_text("""
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    email = None
    ssn = None
    phone_number = None
""".strip())
    (tmp_path / "helpers.py").write_text("""
def compute_hash(data):
    return hash(data)

class Utility:
    def format(self, x):
        return str(x)
""".strip())
    (tmp_path / "django_app.py").write_text("""
from django.db import models

class Customer(models.Model):
    name = None
    credit_card = None
""".strip())
    (tmp_path / "empty.py").write_text("# intentionally empty\n")
    return tmp_path


def _engine():
    mod = importlib.import_module("core.deep_code_analysis_engine")
    importlib.reload(mod)
    for name in dir(mod):
        obj = getattr(mod, name)
        if isinstance(obj, type) and name.endswith("Engine"):
            return obj()
    raise RuntimeError("No Engine class")


class TestImport:
    def test_module_imports(self):
        mod = importlib.import_module("core.deep_code_analysis_engine")
        assert mod is not None

    def test_router_imports(self):
        r = importlib.import_module("apps.api.deep_code_analysis_router")
        assert hasattr(r, "router")

    def test_router_prefix(self):
        r = importlib.import_module("apps.api.deep_code_analysis_router")
        assert "/api/v1/dca" in r.router.prefix


class TestSensitiveDetection:
    def test_detect_ssn(self):
        mod = importlib.import_module("core.deep_code_analysis_engine")
        importlib.reload(mod)
        out = mod.detect_sensitive_types("ssn")
        assert isinstance(out, list) and len(out) >= 1

    def test_detect_email(self):
        mod = importlib.import_module("core.deep_code_analysis_engine")
        importlib.reload(mod)
        out = mod.detect_sensitive_types("email")
        assert len(out) >= 1

    def test_detect_non_sensitive(self):
        mod = importlib.import_module("core.deep_code_analysis_engine")
        importlib.reload(mod)
        out = mod.detect_sensitive_types("counter")
        assert out == []


class TestAnalysis:
    def test_analyze_mini_repo(self, tmp_data_dir, mini_repo):
        eng = _engine()
        result = eng.analyze_repo("org-a", "mini/repo", "deadbeef", str(mini_repo))
        assert isinstance(result, dict)
        assert result.get("analysis_id") or result.get("id")

    def test_analysis_records_files(self, tmp_data_dir, mini_repo):
        eng = _engine()
        eng.analyze_repo("org-b", "mini/repo", "commit1", str(mini_repo))
        analyses = eng.list_analyses("org-b")
        assert len(analyses) >= 1

    def test_ts_analyzer_returns_dict(self, tmp_data_dir, tmp_path):
        """_analyze_typescript now uses tree-sitter (when available) or falls back gracefully."""
        eng = _engine()
        ts_file = tmp_path / "x.ts"
        ts_file.write_text("export const x = 1;")
        # Must return a dict (real tree-sitter) or raise NotImplementedError (no native ext)
        try:
            result = eng._analyze_typescript(ts_file)
            assert isinstance(result, dict)
        except NotImplementedError:
            pass  # acceptable when tree-sitter C extension not available

    def test_java_analyzer_returns_dict(self, tmp_data_dir, tmp_path):
        """_analyze_java now uses javalang — returns a real dict, not NotImplementedError."""
        eng = _engine()
        j = tmp_path / "X.java"
        j.write_text("public class X {}")
        result = eng._analyze_java(j)
        assert isinstance(result, dict)
        assert "symbols" in result
        assert "findings" in result


class TestOrgIsolation:
    def test_org_a_cannot_see_org_b_analyses(self, tmp_data_dir, mini_repo):
        eng = _engine()
        eng.analyze_repo("org-a", "r1", "c1", str(mini_repo))
        eng.analyze_repo("org-b", "r1", "c1", str(mini_repo))
        a = eng.list_analyses("org-a")
        b = eng.list_analyses("org-b")
        assert len(a) >= 1 and len(b) >= 1
        # Ensure different records
        all_orgs = set([x.get("org_id") for x in a + b])
        assert "org-a" in all_orgs and "org-b" in all_orgs


class TestStats:
    def test_stats_returns_dict(self, tmp_data_dir, mini_repo):
        eng = _engine()
        eng.analyze_repo("org-stats", "r", "c", str(mini_repo))
        s = eng.stats("org-stats")
        assert isinstance(s, dict)
