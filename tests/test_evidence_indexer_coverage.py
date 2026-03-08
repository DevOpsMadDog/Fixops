"""Coverage tests for core.evidence_indexer — vector store."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.evidence_indexer import VectorRecord, VectorMatch

# Try to import and instantiate ChromaVectorStore
try:
    from core.evidence_indexer import ChromaVectorStore
    # Verify it can actually instantiate (chromadb deps may be missing)
    ChromaVectorStore(collection_name="__probe__")
    HAS_CHROMA = True
except Exception:
    HAS_CHROMA = False


class TestVectorRecord:
    def test_creation(self):
        record = VectorRecord(
            identifier="REC-001",
            text="SQL injection vulnerability in login form",
            metadata={"severity": "critical", "cve": "CVE-2024-001"},
        )
        assert record.identifier == "REC-001"
        assert "SQL injection" in record.text

    def test_no_embedding(self):
        record = VectorRecord(
            identifier="REC-002",
            text="XSS vulnerability",
            metadata={},
        )
        assert record.embedding is None


class TestVectorMatch:
    def test_creation(self):
        match = VectorMatch(
            identifier="REC-001",
            similarity=0.95,
            metadata={"severity": "critical"},
        )
        assert match.similarity == 0.95
        assert match.identifier == "REC-001"


@pytest.mark.skipif(not HAS_CHROMA, reason="chromadb not installed")
class TestChromaVectorStore:
    def test_instantiation(self, tmp_path):
        store = ChromaVectorStore(
            collection_name="test-collection",
            persist_directory=tmp_path,
        )
        assert store is not None

    def test_index_and_search(self, tmp_path):
        store = ChromaVectorStore(
            collection_name="test-search",
            persist_directory=tmp_path,
        )
        records = [
            VectorRecord(identifier="R1", text="XSS in user profile page", metadata={"severity": "high"}),
            VectorRecord(identifier="R2", text="SQL injection in search endpoint", metadata={"severity": "critical"}),
        ]
        store.index(records)
        results = store.search("SQL injection", top_k=2)
        assert isinstance(results, list)
