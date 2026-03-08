"""Coverage tests for core.zero_gravity — Content Addressable Store."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.zero_gravity import Compressor, ContentAddressableStore, DataCategory, DataTier


class TestCompressor:
    def test_compress_and_decompress(self):
        data = b"Hello, this is a test of compression " * 100
        compressed = Compressor.compress(data)
        assert len(compressed) < len(data)
        decompressed = Compressor.decompress(compressed)
        assert decompressed == data

    def test_compress_empty(self):
        compressed = Compressor.compress(b"")
        decompressed = Compressor.decompress(compressed)
        assert decompressed == b""

    def test_ratio(self):
        original = b"AAAA" * 1000
        compressed = Compressor.compress(original)
        ratio = Compressor.ratio(original, compressed)
        assert isinstance(ratio, float)
        assert ratio > 0


class TestContentAddressableStore:
    def test_store_and_retrieve(self, tmp_path):
        store = ContentAddressableStore(base_dir=tmp_path)
        data = b"vulnerability finding data"
        digest = store.store(data)
        assert isinstance(digest, str)
        assert len(digest) > 0
        retrieved = store.retrieve(digest)
        assert retrieved == data

    def test_exists(self, tmp_path):
        store = ContentAddressableStore(base_dir=tmp_path)
        data = b"test data"
        digest = store.store(data)
        assert store.exists(digest) is True
        assert store.exists("nonexistent-hash") is False

    def test_store_with_compression(self, tmp_path):
        store = ContentAddressableStore(base_dir=tmp_path)
        data = b"repeated data " * 500
        digest = store.store(data, compress=True)
        retrieved = store.retrieve(digest)
        assert retrieved == data

    def test_block_count(self, tmp_path):
        store = ContentAddressableStore(base_dir=tmp_path)
        assert store.block_count() == 0
        store.store(b"block1")
        assert store.block_count() >= 1

    def test_size_bytes(self, tmp_path):
        store = ContentAddressableStore(base_dir=tmp_path)
        store.store(b"some data here")
        size = store.size_bytes()
        assert isinstance(size, int)
        assert size > 0

    def test_retrieve_nonexistent(self, tmp_path):
        store = ContentAddressableStore(base_dir=tmp_path)
        result = store.retrieve("sha256-nonexistent")
        assert result is None


class TestDataCategory:
    def test_has_values(self):
        assert len(DataCategory) > 0


class TestDataTier:
    def test_has_values(self):
        assert len(DataTier) > 0
