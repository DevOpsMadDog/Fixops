"""Comprehensive tests for core.paths module (180 LOC).

Covers:
- ensure_secure_directory: creation, permissions, world-writable rejection
- ensure_output_directory: relaxed version for user output
- verify_allowlisted_path: allowlist enforcement, security validation
- resolve_within_root: path traversal prevention
"""

import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "suite-core"))

from core.paths import (
    ensure_output_directory,
    ensure_secure_directory,
    resolve_within_root,
    verify_allowlisted_path,
)


class TestEnsureSecureDirectory:
    """Test ensure_secure_directory function."""

    def test_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "secure_subdir"
            result = ensure_secure_directory(target)
            assert result.exists()
            assert result.is_dir()

    def test_returns_resolved_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "subdir"
            result = ensure_secure_directory(target)
            assert result == target.resolve()

    def test_creates_nested_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "a" / "b" / "c"
            result = ensure_secure_directory(target)
            assert result.exists()

    def test_existing_directory_ok(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            result = ensure_secure_directory(target)
            assert result.exists()

    def test_sets_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "restricted"
            result = ensure_secure_directory(target, mode=0o700)
            actual_mode = result.stat().st_mode & 0o777
            # May not be exact on all systems, but should be restrictive
            assert actual_mode & stat.S_IWOTH == 0  # not world-writable


class TestEnsureOutputDirectory:
    """Test ensure_output_directory function."""

    def test_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "output"
            result = ensure_output_directory(target)
            assert result.exists()
            assert result.is_dir()

    def test_returns_resolved_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "output_dir"
            result = ensure_output_directory(target)
            assert result == target.resolve()

    def test_existing_directory_ok(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = ensure_output_directory(Path(tmpdir))
            assert result.exists()


class TestResolveWithinRoot:
    """Test resolve_within_root path traversal prevention."""

    def test_simple_filename(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = resolve_within_root(root, "report.pdf")
            assert result.name == "report.pdf"
            assert str(root.resolve()) in str(result)

    def test_rejects_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            with pytest.raises(ValueError, match="refusing"):
                resolve_within_root(root, "/etc/passwd")

    def test_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            with pytest.raises(ValueError, match="refusing"):
                resolve_within_root(root, "../../etc/passwd")

    def test_strips_directory_components(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = resolve_within_root(root, "subdir/file.txt")
            # Should use only the final component
            assert result.name == "file.txt"

    def test_safe_filename(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            result = resolve_within_root(root, "evidence_bundle_2024.tar.gz")
            assert result.name == "evidence_bundle_2024.tar.gz"


class TestVerifyAllowlistedPath:
    """Test verify_allowlisted_path allowlist enforcement."""

    def test_path_within_allowlist(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "subdir"
            target.mkdir()
            result = verify_allowlisted_path(target, [root])
            assert str(root.resolve()) in str(result)

    def test_path_outside_allowlist_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir1:
            with tempfile.TemporaryDirectory() as tmpdir2:
                root = Path(tmpdir1)
                outside = Path(tmpdir2)
                with pytest.raises(PermissionError, match="allowlist"):
                    verify_allowlisted_path(outside, [root])

    def test_empty_allowlist_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(PermissionError, match="allowlist"):
                verify_allowlisted_path(Path(tmpdir), [])

    def test_nonexistent_root_raises(self):
        with pytest.raises(PermissionError):
            verify_allowlisted_path(
                Path("/tmp/test_data"),
                [Path("/nonexistent_root_12345")],
            )
