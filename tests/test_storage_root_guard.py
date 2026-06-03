"""Unit tests for the shared storage-root allowlist guard (SCIF hardening).

Covers the security primitive used by ide_backend / deep_code / dlp-adjacent /
semgrep / bandit / checkov / gitleaks / config-benchmark / compliance-scanner /
function-reachability engines.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from core.storage_root_guard import allowed_roots, assert_path_allowed

_ENV = "FIXOPS_TEST_ALLOWED_ROOTS"


def test_blocks_etc_by_default(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    with pytest.raises(ValueError, match="allowed storage root"):
        assert_path_allowed("/etc/passwd", _ENV)


def test_allows_tempdir_by_default(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    d = tempfile.mkdtemp()
    # Default include_tempdir=True permits the system scratch dir — no raise.
    assert_path_allowed(os.path.join(d, "repo", "a.py"), _ENV)


def test_env_override_allows_custom_root(monkeypatch):
    monkeypatch.setenv(_ENV, "/srv/workspace")
    assert_path_allowed("/srv/workspace/repo/a.py", _ENV)


def test_env_override_blocks_outside(monkeypatch):
    monkeypatch.setenv(_ENV, "/srv/workspace")
    with pytest.raises(ValueError, match="allowed storage root"):
        assert_path_allowed("/etc/passwd", _ENV)


def test_extra_roots_param_allows(monkeypatch):
    monkeypatch.setenv(_ENV, "/srv/workspace")
    assert_path_allowed("/opt/extra/x", _ENV, extra=["/opt/extra"])


def test_path_traversal_escape_blocked(monkeypatch):
    """realpath() must defeat ../-escape out of an allowed root."""
    monkeypatch.setenv(_ENV, "/tmp/fixops-fleet")
    with pytest.raises(ValueError, match="allowed storage root"):
        assert_path_allowed("/tmp/fixops-fleet/../../etc/passwd", _ENV)


def test_include_tempdir_false_blocks_tempdir(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    d = tempfile.mkdtemp()
    with pytest.raises(ValueError, match="allowed storage root"):
        assert_path_allowed(os.path.join(d, "x"), _ENV, include_tempdir=False)


def test_empty_path_raises(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    with pytest.raises(ValueError):
        assert_path_allowed("", _ENV)


def test_allowed_roots_env_parsing(monkeypatch):
    monkeypatch.setenv(_ENV, f"/a{os.pathsep}/b")
    roots = allowed_roots(_ENV)
    assert any(r.endswith("/a") for r in roots)
    assert any(r.endswith("/b") for r in roots)


def test_allowed_roots_default_has_fleet_bases(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    roots = allowed_roots(_ENV)
    assert any("fixops-fleet" in r for r in roots)
