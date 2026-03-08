"""Tests for enterprise FeedsService — feed path helpers and data reading."""
from pathlib import Path

from core.services.enterprise.feeds_service import (
    FeedStatus,
    FeedsService,
    _resolve_feeds_dir,
)


class TestResolveFedsDir:
    def test_returns_path(self):
        result = _resolve_feeds_dir()
        assert isinstance(result, Path)

    def test_custom_dir(self, monkeypatch, tmp_path):
        custom = str(tmp_path / "feeds")
        monkeypatch.setenv("FIXOPS_FEEDS_DIR", custom)
        result = _resolve_feeds_dir()
        assert result == Path(custom)


class TestFeedStatus:
    def test_create(self):
        status = FeedStatus(
            enabled_epss=True,
            enabled_kev=True,
            last_updated_epss="2024-01-01T00:00:00Z",
            last_updated_kev="2024-01-01T00:00:00Z",
            epss_count=100,
            kev_count=50,
        )
        assert status.enabled_epss is True
        assert status.epss_count == 100

    def test_disabled(self):
        status = FeedStatus(
            enabled_epss=False,
            enabled_kev=False,
            last_updated_epss=None,
            last_updated_kev=None,
            epss_count=0,
            kev_count=0,
        )
        assert status.enabled_epss is False
        assert status.last_updated_epss is None


class TestFeedsServiceHelpers:
    def test_path_with_json_extension(self):
        path = FeedsService._path("epss.json")
        assert str(path).endswith("epss.json")

    def test_path_without_extension(self):
        path = FeedsService._path("kev")
        assert str(path).endswith("kev.json")

    def test_write_and_read(self, tmp_path):
        test_file = tmp_path / "test.json"
        FeedsService._write(test_file, {"key": "value"})
        result = FeedsService._read(test_file)
        assert result == {"key": "value"}

    def test_read_nonexistent(self, tmp_path):
        result = FeedsService._read(tmp_path / "missing.json")
        assert result is None

    def test_read_invalid_json(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json", encoding="utf-8")
        result = FeedsService._read(bad_file)
        assert result is None

    def test_write_complex_data(self, tmp_path):
        test_file = tmp_path / "complex.json"
        data = {
            "nested": {"deep": True},
            "list": [1, 2, 3],
            "count": 42,
        }
        FeedsService._write(test_file, data)
        result = FeedsService._read(test_file)
        assert result == data
