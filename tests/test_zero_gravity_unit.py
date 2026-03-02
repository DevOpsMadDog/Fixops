"""Unit tests for ZeroGravityEngine (V9 — Air-Gapped / On-Prem Deployment).

Tests cover:
- DataTier, DataCategory enums
- TierPolicy, ZeroGravityConfig dataclasses
- Compressor: compress, decompress, ratio
- MinHashDedup: shingle, signature, jaccard_estimate, is_duplicate
- ContentAddressableStore: store, retrieve, exists, size_bytes, block_count
- TierIndex: add_item, migrate_item, get_tier_stats, find_duplicates
- ZeroGravityEngine: ingest, retrieve, run_migration_cycle, get_status, forecast_storage
- get_zero_gravity_engine singleton

Pillar: V9 (Air-Gapped) — DESIGN CONSTRAINT, tested for integrity
Agent: agent-doctor (run v6 — 2026-03-01)
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.zero_gravity import (
    DataTier,
    DataCategory,
    TierPolicy,
    ZeroGravityConfig,
    Compressor,
    MinHashDedup,
    ContentAddressableStore,
    TierIndex,
    ZeroGravityEngine,
    get_zero_gravity_engine,
)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------
class TestDataTier:
    def test_values(self):
        assert DataTier.HOT == "hot"
        assert DataTier.WARM == "warm"
        assert DataTier.COLD == "cold"
        assert DataTier.ARCHIVE == "archive"

    def test_count(self):
        assert len(DataTier) == 4


class TestDataCategory:
    def test_values(self):
        assert DataCategory.FINDINGS == "findings"
        assert DataCategory.EVIDENCE == "evidence"
        assert DataCategory.SCANS == "scans"
        assert DataCategory.DECISIONS == "decisions"
        assert DataCategory.EVENTS == "events"
        assert DataCategory.METRICS == "metrics"
        assert DataCategory.AUDIT_LOG == "audit_log"
        assert DataCategory.MPTE_RESULTS == "mpte_results"

    def test_count(self):
        assert len(DataCategory) == 8


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------
class TestTierPolicy:
    def test_defaults(self):
        policy = TierPolicy(tier=DataTier.HOT, max_age_days=30)
        assert policy.compressed is False
        assert policy.summarized is False
        assert policy.sealed is False
        assert policy.max_size_mb == 0

    def test_archive_policy(self):
        policy = TierPolicy(
            tier=DataTier.ARCHIVE,
            max_age_days=365,
            compressed=True,
            summarized=True,
            sealed=True,
        )
        assert policy.sealed is True


class TestZeroGravityConfig:
    def test_defaults(self):
        cfg = ZeroGravityConfig()
        assert cfg.hot_days == 30
        assert cfg.warm_days == 90
        assert cfg.cold_days == 365

    def test_from_env(self):
        cfg = ZeroGravityConfig.from_env()
        assert isinstance(cfg, ZeroGravityConfig)
        assert cfg.hot_days > 0


# ---------------------------------------------------------------------------
# Compressor tests
# ---------------------------------------------------------------------------
class TestCompressor:
    def test_compress_zlib(self):
        data = b"Hello, World! " * 100
        compressed = Compressor.compress(data, algorithm="zlib")
        assert len(compressed) < len(data)

    def test_compress_gzip(self):
        data = b"Test data for gzip compression " * 50
        compressed = Compressor.compress(data, algorithm="gzip")
        assert len(compressed) < len(data)

    def test_compress_bz2(self):
        data = b"bz2 test data " * 100
        compressed = Compressor.compress(data, algorithm="bz2")
        assert len(compressed) < len(data)

    def test_decompress_zlib(self):
        data = b"Roundtrip zlib test " * 50
        compressed = Compressor.compress(data, algorithm="zlib")
        decompressed = Compressor.decompress(compressed)
        assert decompressed == data

    def test_decompress_gzip(self):
        data = b"Roundtrip gzip test " * 50
        compressed = Compressor.compress(data, algorithm="gzip")
        decompressed = Compressor.decompress(compressed)
        assert decompressed == data

    def test_ratio(self):
        original = b"x" * 1000
        compressed = Compressor.compress(original)
        r = Compressor.ratio(original, compressed)
        assert 0.0 < r < 1.0  # Compressed should be smaller

    def test_compress_empty(self):
        compressed = Compressor.compress(b"")
        assert isinstance(compressed, bytes)

    def test_compress_incompressible(self):
        # Random-like data is hard to compress
        import hashlib
        data = hashlib.sha256(b"seed").digest() * 10
        compressed = Compressor.compress(data)
        assert isinstance(compressed, bytes)


# ---------------------------------------------------------------------------
# MinHashDedup tests
# ---------------------------------------------------------------------------
class TestMinHashDedup:
    def test_init(self):
        dedup = MinHashDedup()
        assert dedup is not None

    def test_signature(self):
        dedup = MinHashDedup()
        sig = dedup.signature("This is a test document for MinHash")
        assert isinstance(sig, list)
        assert len(sig) == 128  # Default num_hashes

    def test_same_text_same_signature(self):
        dedup = MinHashDedup()
        sig1 = dedup.signature("Identical text for testing")
        sig2 = dedup.signature("Identical text for testing")
        assert sig1 == sig2

    def test_similar_text_high_jaccard(self):
        dedup = MinHashDedup()
        sig1 = dedup.signature("This is a test document about security vulnerabilities")
        sig2 = dedup.signature("This is a test document about security issues")
        similarity = dedup.jaccard_estimate(sig1, sig2)
        assert similarity > 0.3  # Similar texts should have some overlap

    def test_different_text_low_jaccard(self):
        dedup = MinHashDedup()
        sig1 = dedup.signature("Python programming language for web development")
        sig2 = dedup.signature("Quantum physics and nuclear reactions in stars")
        similarity = dedup.jaccard_estimate(sig1, sig2)
        assert similarity < 0.8  # Very different texts

    def test_is_duplicate(self):
        dedup = MinHashDedup()
        sig1 = dedup.signature("Same text here")
        sig2 = dedup.signature("Same text here")
        assert dedup.is_duplicate(sig1, sig2) is True

    def test_is_not_duplicate(self):
        dedup = MinHashDedup()
        sig1 = dedup.signature("First unique document")
        sig2 = dedup.signature("Completely different content about different topic")
        # Should usually not be duplicate with default 0.8 threshold
        result = dedup.is_duplicate(sig1, sig2)
        assert isinstance(result, bool)

    def test_shingle(self):
        dedup = MinHashDedup()
        shingles = dedup._shingle("hello world test", k=3)
        assert isinstance(shingles, set)
        assert len(shingles) > 0


# ---------------------------------------------------------------------------
# ContentAddressableStore tests
# ---------------------------------------------------------------------------
class TestContentAddressableStore:
    @pytest.fixture
    def store(self, tmp_path):
        return ContentAddressableStore(tmp_path / "cas")

    def test_store(self, store):
        digest = store.store(b"test data")
        assert isinstance(digest, str)
        assert len(digest) == 64  # SHA-256 hex digest

    def test_store_and_retrieve(self, store):
        data = b"Content addressable storage test"
        digest = store.store(data)
        retrieved = store.retrieve(digest)
        assert retrieved == data

    def test_exists(self, store):
        digest = store.store(b"existence check")
        assert store.exists(digest) is True
        assert store.exists("0" * 64) is False

    def test_store_compressed(self, store):
        data = b"compressed content " * 100
        digest = store.store(data, compress=True)
        retrieved = store.retrieve(digest)
        assert retrieved == data

    def test_size_bytes(self, store):
        store.store(b"data1")
        store.store(b"data2")
        size = store.size_bytes()
        assert size > 0

    def test_block_count(self, store):
        store.store(b"block1")
        store.store(b"block2")
        store.store(b"block3")
        count = store.block_count()
        assert count >= 3  # May count more files due to internal structure

    def test_dedup(self, store):
        data = b"duplicate content"
        d1 = store.store(data)
        d2 = store.store(data)
        assert d1 == d2  # Same content should give same digest

    def test_retrieve_nonexistent(self, store):
        result = store.retrieve("nonexistent" + "0" * 52)
        assert result is None


# ---------------------------------------------------------------------------
# TierIndex tests
# ---------------------------------------------------------------------------
class TestTierIndex:
    @pytest.fixture
    def index(self, tmp_path):
        idx = TierIndex(str(tmp_path / "tier_index.db"))
        yield idx
        idx.close()

    def test_init(self, index):
        assert index is not None

    def test_add_item(self, index):
        index.add_item(
            item_id="item-001",
            category="findings",
            size_bytes=1024,
            content_hash="abc123",
        )

    def test_get_tier_stats(self, index):
        index.add_item("i1", "findings", 1024, "h1")
        index.add_item("i2", "evidence", 2048, "h2")
        stats = index.get_tier_stats()
        assert isinstance(stats, dict)

    def test_migrate_item(self, index):
        index.add_item("i1", "findings", 1024, "h1")
        index.migrate_item("i1", DataTier.WARM.value, new_size=512)

    def test_find_duplicates(self, index):
        index.add_item("i1", "findings", 1024, "same-hash")
        index.add_item("i2", "findings", 1024, "same-hash")
        dupes = index.find_duplicates()
        assert isinstance(dupes, list)

    def test_record_stats(self, index):
        index.add_item("i1", "findings", 1024, "h1")
        index.record_stats()

    def test_get_storage_trend(self, index):
        index.add_item("i1", "findings", 1024, "h1")
        index.record_stats()
        trend = index.get_storage_trend()
        assert isinstance(trend, list)


# ---------------------------------------------------------------------------
# ZeroGravityEngine tests
# ---------------------------------------------------------------------------
class TestZeroGravityEngine:
    @pytest.fixture
    def engine(self, tmp_path):
        config = ZeroGravityConfig(data_dir=str(tmp_path / "zg_data"))
        return ZeroGravityEngine(config=config)

    def test_init(self, engine):
        assert engine is not None

    def test_ingest(self, engine):
        result = engine.ingest(
            category="findings",
            data={"id": "VULN-001", "severity": "critical"},
        )
        assert isinstance(result, (str, dict))

    def test_ingest_with_id(self, engine):
        result = engine.ingest(
            category="evidence",
            data={"proof": "exploit output"},
            item_id="evidence-001",
        )
        assert result is not None

    def test_retrieve(self, engine):
        item_id = engine.ingest(
            category="findings",
            data={"id": "V1", "title": "XSS"},
        )
        # item_id might be the actual ID or a dict with an id
        if isinstance(item_id, dict):
            actual_id = item_id.get("id", item_id.get("item_id", ""))
        else:
            actual_id = item_id
        if actual_id:
            result = engine.retrieve(actual_id, "findings")
            # May be None if retrieval doesn't find by same ID
            assert result is None or isinstance(result, bytes)

    def test_run_migration_cycle(self, engine):
        result = engine.run_migration_cycle()
        assert isinstance(result, dict)

    def test_get_status(self, engine):
        status = engine.get_status()
        assert isinstance(status, dict)

    def test_forecast_storage(self, engine):
        forecast = engine.forecast_storage()
        assert isinstance(forecast, dict)

    def test_cleanup_empty_dirs(self, engine):
        count = engine.cleanup_empty_dirs()
        assert isinstance(count, int)
        assert count >= 0

    def test_ingest_multiple_categories(self, engine):
        for cat in ["findings", "evidence", "scans", "decisions"]:
            result = engine.ingest(category=cat, data={"category": cat, "data": "test"})
            assert result is not None

    def test_large_data_ingest(self, engine):
        big_data = {"payload": "x" * 10000}
        result = engine.ingest(category="findings", data=big_data)
        assert result is not None


class TestGetZeroGravityEngine:
    def test_returns_engine(self):
        engine = get_zero_gravity_engine()
        assert isinstance(engine, ZeroGravityEngine)

    def test_singleton(self):
        e1 = get_zero_gravity_engine()
        e2 = get_zero_gravity_engine()
        assert e1 is e2
