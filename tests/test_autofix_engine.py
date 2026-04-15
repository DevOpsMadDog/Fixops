"""Tests for AutoFixEngine — 27 tests covering all methods + fix lifecycle."""

from __future__ import annotations

import asyncio
import pytest
from core.autofix_engine import (
    AutoFixEngine,
    AutoFixSuggestion,
    AutoFixResult,
    CodePatch,
    DependencyFix,
    FixType,
    FixStatus,
    FixConfidence,
    PatchFormat,
    _infer_language_from_path,
    _cwe_to_category,
)


@pytest.fixture
def engine():
    """Fresh AutoFixEngine instance with in-memory-equivalent stores."""
    e = AutoFixEngine()
    # Clear any hydrated state so each test starts clean
    e._fixes = {}
    e._history = []
    e._stats = {
        "total_generated": 0,
        "total_applied": 0,
        "total_prs_created": 0,
        "total_merged": 0,
        "total_failed": 0,
        "total_rolled_back": 0,
        "by_type": {},
        "by_confidence": {"high": 0, "medium": 0, "low": 0},
        "avg_confidence_score": 0.0,
    }
    return e


def _make_finding(**kwargs):
    base = {
        "id": "find-001",
        "title": "SQL Injection in login endpoint",
        "severity": "high",
        "cwe_id": "CWE-89",
        "cve_ids": [],
        "description": "Unsanitized user input in SQL query",
        "file_path": "app/login.py",
        "category": "injection",
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# _infer_language_from_path (module-level helper)
# ---------------------------------------------------------------------------

def test_infer_language_python():
    assert _infer_language_from_path("app/main.py") == "python"


def test_infer_language_javascript():
    assert _infer_language_from_path("src/index.js") == "javascript"


def test_infer_language_typescript():
    assert _infer_language_from_path("lib/auth.ts") == "typescript"


def test_infer_language_terraform():
    assert _infer_language_from_path("infra/main.tf") == "terraform"


def test_infer_language_dockerfile():
    assert _infer_language_from_path("Dockerfile") == "dockerfile"


def test_infer_language_unknown():
    assert _infer_language_from_path("somefile.xyz") == "unknown"


def test_infer_language_empty():
    assert _infer_language_from_path("") == "unknown"


# ---------------------------------------------------------------------------
# _cwe_to_category
# ---------------------------------------------------------------------------

def test_cwe_to_category_known_cwe():
    assert _cwe_to_category("CWE-89", FixType.CODE_PATCH) == "injection"


def test_cwe_to_category_xss():
    assert _cwe_to_category("CWE-79", FixType.CODE_PATCH) == "xss"


def test_cwe_to_category_fallback_to_fix_type():
    cat = _cwe_to_category("CWE-9999", FixType.DEPENDENCY_UPDATE)
    assert cat == "dependency"


# ---------------------------------------------------------------------------
# _infer_fix_type (static method)
# ---------------------------------------------------------------------------

def test_infer_fix_type_dependency():
    finding = _make_finding(title="Outdated library lodash", category="dependency")
    assert AutoFixEngine._infer_fix_type(finding) == FixType.DEPENDENCY_UPDATE


def test_infer_fix_type_container():
    finding = _make_finding(title="Docker container vulnerability", file_path="Dockerfile")
    assert AutoFixEngine._infer_fix_type(finding) == FixType.CONTAINER_FIX


def test_infer_fix_type_config():
    finding = _make_finding(title="Missing HSTS header misconfiguration")
    assert AutoFixEngine._infer_fix_type(finding) == FixType.CONFIG_HARDENING


def test_infer_fix_type_secret_rotation():
    finding = _make_finding(title="API key exposed in source credential leak")
    assert AutoFixEngine._infer_fix_type(finding) == FixType.SECRET_ROTATION


def test_infer_fix_type_code_patch_fallback():
    # Use a title/description that doesn't match any keyword bucket
    finding = {
        "id": "find-fallback",
        "title": "Buffer overflow in parser",
        "description": "Stack overflow during parsing",
        "category": "memory",
        "file_path": "src/parser.c",
        "cve_ids": [],
        "cwe_id": "CWE-121",
        "severity": "high",
    }
    assert AutoFixEngine._infer_fix_type(finding) == FixType.CODE_PATCH


# ---------------------------------------------------------------------------
# get_fix / list_fixes / get_stats
# ---------------------------------------------------------------------------

def test_list_fixes_empty_initially(engine):
    assert engine.list_fixes() == []


def test_get_fix_returns_none_for_unknown(engine):
    assert engine.get_fix("no-such-fix") is None


def test_get_stats_structure(engine):
    stats = engine.get_stats()
    assert "total_generated" in stats
    assert "total_applied" in stats
    assert "by_type" in stats
    assert "by_confidence" in stats
    assert "avg_confidence_score" in stats
    assert "total_fixes_stored" in stats


def test_get_stats_total_fixes_stored_zero(engine):
    assert engine.get_stats()["total_fixes_stored"] == 0


# ---------------------------------------------------------------------------
# to_dict / _dict_to_suggestion round-trip
# ---------------------------------------------------------------------------

def test_to_dict_serializes_fix(engine):
    suggestion = AutoFixSuggestion(
        fix_id="fix-abc",
        finding_id="find-001",
        finding_title="SQL Injection",
        fix_type=FixType.CODE_PATCH,
        confidence=FixConfidence.HIGH,
        confidence_score=0.9,
        status=FixStatus.GENERATED,
    )
    d = engine.to_dict(suggestion)
    assert d["fix_type"] == "code_patch"
    assert d["status"] == "generated"
    assert d["confidence"] == "high"
    assert d["fix_id"] == "fix-abc"


def test_dict_to_suggestion_round_trip(engine):
    original = AutoFixSuggestion(
        fix_id="fix-round",
        finding_id="find-002",
        finding_title="XSS",
        fix_type=FixType.INPUT_VALIDATION,
        confidence=FixConfidence.MEDIUM,
        confidence_score=0.7,
        status=FixStatus.VALIDATED,
    )
    d = engine.to_dict(original)
    restored = AutoFixEngine._dict_to_suggestion(d)
    assert restored.fix_id == original.fix_id
    assert restored.fix_type == original.fix_type
    assert restored.status == original.status
    assert restored.confidence == original.confidence


# ---------------------------------------------------------------------------
# list_fixes filtering
# ---------------------------------------------------------------------------

def _insert_fix(engine, fix_id, finding_id="f1", fix_type=FixType.CODE_PATCH,
                status=FixStatus.GENERATED):
    s = AutoFixSuggestion(
        fix_id=fix_id,
        finding_id=finding_id,
        fix_type=fix_type,
        status=status,
    )
    engine._fixes[fix_id] = s
    return s


def test_list_fixes_filter_by_finding_id(engine):
    _insert_fix(engine, "fix-1", finding_id="find-A")
    _insert_fix(engine, "fix-2", finding_id="find-B")
    result = engine.list_fixes(finding_id="find-A")
    assert len(result) == 1
    assert result[0].fix_id == "fix-1"


def test_list_fixes_filter_by_status(engine):
    _insert_fix(engine, "fix-gen", status=FixStatus.GENERATED)
    _insert_fix(engine, "fix-app", status=FixStatus.APPLIED)
    result = engine.list_fixes(status=FixStatus.APPLIED)
    assert len(result) == 1
    assert result[0].fix_id == "fix-app"


def test_list_fixes_filter_by_fix_type(engine):
    _insert_fix(engine, "fix-dep", fix_type=FixType.DEPENDENCY_UPDATE)
    _insert_fix(engine, "fix-code", fix_type=FixType.CODE_PATCH)
    result = engine.list_fixes(fix_type=FixType.DEPENDENCY_UPDATE)
    assert len(result) == 1
    assert result[0].fix_id == "fix-dep"


def test_list_fixes_limit(engine):
    for i in range(10):
        _insert_fix(engine, f"fix-{i}")
    result = engine.list_fixes(limit=3)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# get_history
# ---------------------------------------------------------------------------

def test_get_history_empty_initially(engine):
    assert engine.get_history() == []


def test_get_history_returns_entries_after_manual_append(engine):
    engine._history.append({"action": "test", "fix_id": "fix-h1"})
    h = engine.get_history()
    assert len(h) == 1
    assert h[0]["action"] == "test"


# ---------------------------------------------------------------------------
# generate_fix (async — LLM unavailable, tests the non-LLM scaffolding path)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_fix_returns_suggestion(engine):
    finding = _make_finding()
    suggestion = await engine.generate_fix(finding)
    assert isinstance(suggestion, AutoFixSuggestion)
    assert suggestion.fix_id.startswith("fix-")
    assert suggestion.finding_id == "find-001"
    assert suggestion.fix_type in list(FixType)


@pytest.mark.asyncio
async def test_generate_fix_stores_in_fixes(engine):
    finding = _make_finding(id="find-store")
    suggestion = await engine.generate_fix(finding)
    assert suggestion.fix_id in engine._fixes


@pytest.mark.asyncio
async def test_generate_fix_increments_stats(engine):
    finding = _make_finding()
    await engine.generate_fix(finding)
    assert engine.get_stats()["total_generated"] >= 1


@pytest.mark.asyncio
async def test_generate_fix_dependency_type(engine):
    finding = _make_finding(
        title="Outdated package requests 2.0",
        category="dependency",
        cve_ids=["CVE-2023-1234"],
    )
    suggestion = await engine.generate_fix(finding)
    assert suggestion.fix_type == FixType.DEPENDENCY_UPDATE
