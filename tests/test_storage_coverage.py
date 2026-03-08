"""Coverage tests for core.storage — ArtefactArchive."""
import os
import sys
import tempfile
from pathlib import Path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.storage import ArtefactArchive


class TestArtefactArchive:
    def test_persist_and_summarise(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = ArtefactArchive(base_directory=Path(tmpdir))
            data = {"findings": [{"id": "CVE-2024-001", "severity": "high"}]}
            result = archive.persist("test-scan", data)
            assert result is not None
            assert isinstance(result, dict)

    def test_persist_empty_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = ArtefactArchive(base_directory=Path(tmpdir))
            result = archive.persist("empty-scan", {})
            assert result is not None

    def test_persist_large_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = ArtefactArchive(base_directory=Path(tmpdir))
            data = {"items": [{"id": i, "val": f"item-{i}"} for i in range(100)]}
            result = archive.persist("large-scan", data)
            assert result is not None

    def test_persist_with_original_filename(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = ArtefactArchive(base_directory=Path(tmpdir))
            result = archive.persist("scan-x", {"a": 1}, original_filename="report.json")
            assert result is not None

    def test_summarise_static(self):
        records = {
            "scan-1": {"stage": "ingest", "size": 100},
            "scan-2": {"stage": "analyze", "size": 200},
        }
        summary = ArtefactArchive.summarise(records)
        assert isinstance(summary, dict)

    def test_summarise_empty(self):
        summary = ArtefactArchive.summarise({})
        assert isinstance(summary, dict)
