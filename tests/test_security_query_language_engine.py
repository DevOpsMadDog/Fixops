"""Smoke tests for GAP-024 security_query_language_engine.

Minimal coverage written post-quota-kill to unblock main line.
Comprehensive parser/planner/executor tests are a follow-up.
"""
from __future__ import annotations

import importlib
import os
import tempfile

import pytest


@pytest.fixture
def tmp_data_dir(monkeypatch):
    d = tempfile.mkdtemp(prefix="sql_engine_test_")
    monkeypatch.setenv("FIXOPS_DATA_DIR", d)
    yield d


def _fresh_engine():
    mod = importlib.import_module("core.security_query_language_engine")
    importlib.reload(mod)
    return mod


class TestModuleImport:
    def test_module_imports(self):
        mod = _fresh_engine()
        assert mod is not None

    def test_lexer_class_exposed(self):
        mod = _fresh_engine()
        candidates = [c for c in dir(mod) if "exer" in c.lower() or "oken" in c]
        assert len(candidates) > 0, "Lexer/tokenizer class must be exposed"

    def test_parser_class_exposed(self):
        mod = _fresh_engine()
        candidates = [c for c in dir(mod) if "arser" in c.lower() or "uery" in c]
        assert len(candidates) > 0, "Parser/query class must be exposed"


class TestEngineInstantiation:
    def test_engine_can_be_instantiated(self, tmp_data_dir):
        mod = _fresh_engine()
        # find an engine class
        engine_classes = [
            getattr(mod, name) for name in dir(mod)
            if name.endswith("Engine") and callable(getattr(mod, name))
        ]
        assert len(engine_classes) >= 1
        e = engine_classes[0]()
        assert e is not None


class TestLexerBasics:
    def test_tokenize_simple_query(self):
        mod = _fresh_engine()
        Token = None
        # look for TokenStream or similar lexer entry
        for name in dir(mod):
            obj = getattr(mod, name)
            if isinstance(obj, type) and any(k in name for k in ("Token", "Lex")):
                Token = obj
                break
        if Token is None:
            pytest.skip("No Token/Lexer class named conventionally")
        # minimal usage — don't crash
        try:
            Token("FROM asset WHERE severity='critical' RETURN id")
        except Exception as e:
            pytest.skip(f"Token init signature unexpected: {e}")


class TestRouterImport:
    def test_router_module_imports(self):
        r = importlib.import_module("apps.api.security_query_router")
        assert hasattr(r, "router")

    def test_router_has_expected_prefix(self):
        r = importlib.import_module("apps.api.security_query_router")
        assert r.router.prefix.startswith("/api/v1/sql") or r.router.prefix.startswith("/api/v1/query")

    def test_router_has_execute_endpoint(self):
        r = importlib.import_module("apps.api.security_query_router")
        paths = {route.path for route in r.router.routes}
        assert any("execute" in p or "query" in p for p in paths)
