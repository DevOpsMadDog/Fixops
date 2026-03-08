"""Tests for core.configuration — deep merge, overlay parsing, and validation helpers."""

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.configuration import (  # noqa: E402
    _deep_merge,
    _optional_string,
    _parse_overlay,
    _require_mapping,
    _require_string,
    _string_list,
)


# ---------------------------------------------------------------------------
# _deep_merge
# ---------------------------------------------------------------------------


class TestDeepMerge:
    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"nested": {"x": 1, "y": 2}}
        override = {"nested": {"y": 3, "z": 4}}
        result = _deep_merge(base, override)
        assert result == {"nested": {"x": 1, "y": 3, "z": 4}}

    def test_does_not_mutate_base(self):
        base = {"a": {"b": 1}}
        override = {"a": {"c": 2}}
        result = _deep_merge(base, override)
        assert "c" not in base["a"]  # base not mutated
        assert result["a"]["c"] == 2

    def test_override_replaces_non_dict(self):
        base = {"a": "string"}
        override = {"a": {"nested": True}}
        result = _deep_merge(base, override)
        assert result["a"] == {"nested": True}

    def test_empty_override(self):
        base = {"a": 1}
        result = _deep_merge(base, {})
        assert result == {"a": 1}

    def test_empty_base(self):
        result = _deep_merge({}, {"a": 1})
        assert result == {"a": 1}

    def test_deeply_nested(self):
        base = {"l1": {"l2": {"l3": {"val": "old"}}}}
        override = {"l1": {"l2": {"l3": {"val": "new", "extra": True}}}}
        result = _deep_merge(base, override)
        assert result["l1"]["l2"]["l3"]["val"] == "new"
        assert result["l1"]["l2"]["l3"]["extra"] is True


# ---------------------------------------------------------------------------
# _parse_overlay
# ---------------------------------------------------------------------------


class TestParseOverlay:
    def test_empty_string(self):
        assert _parse_overlay("") == {}
        assert _parse_overlay("   ") == {}

    def test_json_input(self):
        text = json.dumps({"mode": "enterprise", "toggles": {"feature_x": True}})
        result = _parse_overlay(text)
        assert result["mode"] == "enterprise"
        assert result["toggles"]["feature_x"] is True

    def test_yaml_input(self):
        try:
            import yaml  # noqa: F401
            text = "mode: enterprise\ntoggle: true\n"
            result = _parse_overlay(text)
            assert result["mode"] == "enterprise"
        except ImportError:
            pytest.skip("PyYAML not available")

    def test_yaml_none_returns_empty(self):
        try:
            import yaml  # noqa: F401
            result = _parse_overlay("# just a comment\n")
            assert result == {}
        except ImportError:
            pytest.skip("PyYAML not available")


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


class TestRequireMapping:
    def test_valid_mapping(self):
        result = _require_mapping({"key": "val"}, "test")
        assert result == {"key": "val"}

    def test_non_mapping_raises(self):
        with pytest.raises(ValueError, match="must be a mapping"):
            _require_mapping("string", "test_field")
        with pytest.raises(ValueError, match="must be a mapping"):
            _require_mapping(42, "test_field")
        with pytest.raises(ValueError, match="must be a mapping"):
            _require_mapping(None, "test_field")


class TestRequireString:
    def test_valid_string(self):
        assert _require_string("hello", "field") == "hello"
        assert _require_string("  padded  ", "field") == "padded"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _require_string("", "field")
        with pytest.raises(ValueError, match="cannot be empty"):
            _require_string("   ", "field")

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _require_string(42, "field")
        with pytest.raises(ValueError, match="must be a string"):
            _require_string(None, "field")


class TestOptionalString:
    def test_valid_string(self):
        assert _optional_string("value", "field") == "value"

    def test_none_returns_none(self):
        assert _optional_string(None, "field") is None

    def test_empty_string_returns_none(self):
        assert _optional_string("", "field") is None
        assert _optional_string("   ", "field") is None

    def test_non_string_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _optional_string(42, "field")


class TestStringList:
    def test_valid_list(self):
        assert _string_list(["a", "b", "c"], "field") == ["a", "b", "c"]

    def test_none_returns_empty(self):
        assert _string_list(None, "field") == []

    def test_strips_whitespace(self):
        assert _string_list(["  x  ", " y "], "field") == ["x", "y"]

    def test_non_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            _string_list("not a list", "field")

    def test_non_string_item_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _string_list(["valid", 42], "field")

    def test_empty_item_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _string_list(["valid", ""], "field")
