"""Tests for core.safe_path_ops — safe filesystem operations."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.safe_path_ops import PathContainmentError, _is_under


class TestIsUnder:
    def test_same_path(self):
        assert _is_under("/var/fixops", "/var/fixops") is True

    def test_child_path(self):
        assert _is_under("/var/fixops/scans/file.txt", "/var/fixops") is True

    def test_not_under(self):
        assert _is_under("/tmp/evil", "/var/fixops") is False

    def test_partial_match_false(self):
        # /var/fixops2 should NOT be under /var/fixops
        assert _is_under("/var/fixops2/file", "/var/fixops") is False

    def test_empty_child(self):
        assert _is_under("", "/var/fixops") is False

    def test_nested_deeply(self):
        assert _is_under("/var/fixops/a/b/c/d/e", "/var/fixops") is True


class TestPathContainmentError:
    def test_is_value_error(self):
        err = PathContainmentError("Path escaped")
        assert isinstance(err, ValueError)
        assert str(err) == "Path escaped"
