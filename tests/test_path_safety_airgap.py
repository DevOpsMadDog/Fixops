"""Regression: shared path-safety primitive + air-gap export/import path guard.

`safe_fs_path` (apps.api._path_safety) backs the code-intel and air-gap path hardening.
`_guard_airgap_path` (airgap_router) wraps it for the operator-supplied export/import
paths (arbitrary write/read risk), enforcing FIXOPS_ALLOWED_AIRGAP_ROOTS when set.

Run: python -m pytest tests/test_path_safety_airgap.py -q -o "addopts="
"""

from __future__ import annotations

import os

import pytest

from apps.api._path_safety import safe_fs_path


@pytest.fixture(autouse=True)
def _clean_env():
    for v in ("FIXOPS_ALLOWED_AIRGAP_ROOTS", "FIXOPS_ALLOWED_REPO_ROOTS"):
        os.environ.pop(v, None)
    yield
    for v in ("FIXOPS_ALLOWED_AIRGAP_ROOTS", "FIXOPS_ALLOWED_REPO_ROOTS"):
        os.environ.pop(v, None)


# --- shared primitive ---

def test_safe_fs_path_rejects_traversal_and_null():
    assert safe_fs_path("/tmp/../etc", "FIXOPS_ALLOWED_AIRGAP_ROOTS") is None
    assert safe_fs_path("/tmp/x\x00", "FIXOPS_ALLOWED_AIRGAP_ROOTS") is None
    assert safe_fs_path("", "FIXOPS_ALLOWED_AIRGAP_ROOTS") is None
    assert safe_fs_path(None, "FIXOPS_ALLOWED_AIRGAP_ROOTS") is None


def test_safe_fs_path_default_passthrough(tmp_path):
    p = tmp_path / "bundle.zip"
    assert safe_fs_path(str(p), "FIXOPS_ALLOWED_AIRGAP_ROOTS") == p.resolve()


def test_safe_fs_path_allowlist_enforced(tmp_path):
    root = tmp_path / "transfer"
    root.mkdir()
    os.environ["FIXOPS_ALLOWED_AIRGAP_ROOTS"] = str(root)
    assert safe_fs_path(str(root / "b.zip"), "FIXOPS_ALLOWED_AIRGAP_ROOTS") == (root / "b.zip").resolve()
    assert safe_fs_path("/etc/passwd", "FIXOPS_ALLOWED_AIRGAP_ROOTS") is None


# --- airgap guard wrapper ---

def test_guard_airgap_path_400_on_disallowed(tmp_path):
    from fastapi import HTTPException
    from apps.api.airgap_router import _guard_airgap_path

    # default: passthrough
    p = tmp_path / "out.zip"
    assert _guard_airgap_path(str(p)) == str(p.resolve())
    # traversal -> 400
    with pytest.raises(HTTPException) as ei:
        _guard_airgap_path("/tmp/../etc/x")
    assert ei.value.status_code == 400
    # allowlist enforced
    os.environ["FIXOPS_ALLOWED_AIRGAP_ROOTS"] = str(tmp_path)
    assert _guard_airgap_path(str(p)) == str(p.resolve())
    with pytest.raises(HTTPException):
        _guard_airgap_path("/etc/passwd")
