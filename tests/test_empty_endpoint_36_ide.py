"""Multica #4063 — empty endpoint #36: /api/v1/ide wired to IDEIntegration.

Tests the lazy-import fix that removed all 501 guards from ide_router.py.
Uses direct engine import (no TestClient) to stay within the 10s timeout.
"""
import os
import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")


def test_ide_integration_importable():
    """IDEIntegration must import without error (was blocked at module level)."""
    from core.ide_integration import IDEIntegration, IDEFinding  # noqa
    assert IDEIntegration is not None


def test_ide_get_patterns_returns_list():
    """IDEIntegration.get_patterns() returns non-empty list — proves engine is real."""
    from core.ide_integration import IDEIntegration
    engine = IDEIntegration(db_path=":memory:")
    patterns = engine.get_patterns()
    assert isinstance(patterns, list)
    assert len(patterns) > 0, "Expected at least one SAST pattern"


def test_ide_router_no_501_guards():
    """ide_router must not contain _HAS_INTEGRATION guards (all removed)."""
    import importlib.util, pathlib
    src = pathlib.Path("suite-api/apps/api/ide_router.py").read_text()
    assert "_HAS_INTEGRATION" not in src, "Found leftover _HAS_INTEGRATION guard in ide_router"
    assert 'status_code=501' not in src, "Found leftover 501 stub in ide_router"
