"""Red-Team hardening regression: code-intel repo-path allowlist + traversal rejection.

wave_a_code_intel parses a caller-supplied LOCAL repo path. Without a boundary an
authenticated user could point it at arbitrary server directories. `_safe_local_repo_path`:
  - ALWAYS rejects null bytes and parent-traversal (`..`) segments.
  - When FIXOPS_ALLOWED_REPO_ROOTS (os.pathsep-separated) is set, requires the resolved
    path to live within one of the roots (the SCIF lockdown control).
  - Default (env unset) = passthrough (resolved path), so self-scan/dogfooding still works.

Run: python -m pytest tests/test_code_intel_repo_path_allowlist.py -q -o "addopts="
"""

from __future__ import annotations

import os

import pytest

from apps.api.wave_a_code_intel_router import _safe_local_repo_path as guard


@pytest.fixture(autouse=True)
def _clean_env():
    saved = os.environ.pop("FIXOPS_ALLOWED_REPO_ROOTS", None)
    yield
    os.environ.pop("FIXOPS_ALLOWED_REPO_ROOTS", None)
    if saved is not None:
        os.environ["FIXOPS_ALLOWED_REPO_ROOTS"] = saved


# --- always-on rejections (regardless of allowlist config) ---

def test_rejects_null_byte():
    assert guard("/tmp/repo\x00/etc") is None


def test_rejects_parent_traversal():
    assert guard("/tmp/../etc") is None
    assert guard("/var/data/../../etc/passwd") is None


def test_rejects_empty_or_none():
    assert guard("") is None
    assert guard(None) is None


# --- default (no allowlist configured): passthrough resolved path ---

def test_default_passthrough_resolves(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    out = guard(str(d))
    assert out is not None
    assert out == d.resolve()


# --- allowlist enforced when FIXOPS_ALLOWED_REPO_ROOTS is set ---

def test_allowlist_allows_within_root(tmp_path):
    root = tmp_path / "workspace"
    (root / "repoA").mkdir(parents=True)
    os.environ["FIXOPS_ALLOWED_REPO_ROOTS"] = str(root)
    out = guard(str(root / "repoA"))
    assert out == (root / "repoA").resolve()


def test_allowlist_rejects_outside_root(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    os.environ["FIXOPS_ALLOWED_REPO_ROOTS"] = str(root)
    # a sibling dir outside the configured root must be rejected
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    assert guard(str(outside)) is None
    assert guard("/etc") is None


def test_allowlist_multiple_roots(tmp_path):
    r1 = tmp_path / "r1"; r1.mkdir()
    r2 = tmp_path / "r2"; r2.mkdir()
    os.environ["FIXOPS_ALLOWED_REPO_ROOTS"] = os.pathsep.join([str(r1), str(r2)])
    assert guard(str(r2)) == r2.resolve()
    assert guard(str(tmp_path / "r3")) is None
