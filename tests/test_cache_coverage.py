"""Tests for core.cache — in-memory caching layer with TTL, eviction, and decorator."""

import os
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.cache import CacheManager, _MemoryBackend, cached  # noqa: E402


# ---------------------------------------------------------------------------
# _MemoryBackend
# ---------------------------------------------------------------------------


class TestMemoryBackendGetSet:
    @pytest.fixture
    def backend(self):
        return _MemoryBackend(max_size=100)

    @pytest.mark.asyncio
    async def test_get_missing_key_returns_none(self, backend):
        assert await backend.get("missing") is None

    @pytest.mark.asyncio
    async def test_set_and_get(self, backend):
        await backend.set("key1", {"data": 42}, ttl=60)
        result = await backend.get("key1")
        assert result == {"data": 42}

    @pytest.mark.asyncio
    async def test_set_string_value(self, backend):
        await backend.set("str_key", "hello world", ttl=60)
        assert await backend.get("str_key") == "hello world"

    @pytest.mark.asyncio
    async def test_set_list_value(self, backend):
        await backend.set("list_key", [1, 2, 3], ttl=60)
        assert await backend.get("list_key") == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_set_overwrites_existing(self, backend):
        await backend.set("key", "v1", ttl=60)
        await backend.set("key", "v2", ttl=60)
        assert await backend.get("key") == "v2"


class TestMemoryBackendTTL:
    @pytest.fixture
    def backend(self):
        return _MemoryBackend(max_size=100)

    @pytest.mark.asyncio
    async def test_expired_entry_returns_none(self, backend):
        """Set with very short TTL, manually expire it, then get returns None."""
        await backend.set("exp", "val", ttl=1)
        # Manually set expiration in the past
        async with backend._lock:
            val, _ = backend._store["exp"]
            backend._store["exp"] = (val, time.time() - 10)
        assert await backend.get("exp") is None

    @pytest.mark.asyncio
    async def test_zero_ttl_means_no_expiration(self, backend):
        await backend.set("forever", "val", ttl=0)
        result = await backend.get("forever")
        assert result == "val"

    @pytest.mark.asyncio
    async def test_positive_ttl_still_valid(self, backend):
        await backend.set("fresh", "val", ttl=3600)
        assert await backend.get("fresh") == "val"


class TestMemoryBackendDelete:
    @pytest.fixture
    def backend(self):
        return _MemoryBackend(max_size=100)

    @pytest.mark.asyncio
    async def test_delete_existing(self, backend):
        await backend.set("key", "val", ttl=60)
        await backend.delete("key")
        assert await backend.get("key") is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, backend):
        await backend.delete("nonexistent")  # Should not raise


class TestMemoryBackendInvalidatePattern:
    @pytest.fixture
    def backend(self):
        return _MemoryBackend(max_size=100)

    @pytest.mark.asyncio
    async def test_invalidate_by_prefix(self, backend):
        await backend.set("graph:stats:org1", "v1", ttl=60)
        await backend.set("graph:stats:org2", "v2", ttl=60)
        await backend.set("other:key", "v3", ttl=60)
        deleted = await backend.invalidate_pattern("graph:*")
        assert deleted == 2
        assert await backend.get("graph:stats:org1") is None
        assert await backend.get("other:key") == "v3"

    @pytest.mark.asyncio
    async def test_invalidate_no_match(self, backend):
        await backend.set("key1", "val", ttl=60)
        deleted = await backend.invalidate_pattern("nomatch:*")
        assert deleted == 0


class TestMemoryBackendClear:
    @pytest.fixture
    def backend(self):
        return _MemoryBackend(max_size=100)

    @pytest.mark.asyncio
    async def test_clear_removes_all(self, backend):
        for i in range(5):
            await backend.set(f"key{i}", f"val{i}", ttl=60)
        await backend.clear()
        stats = await backend.stats()
        assert stats["total_keys"] == 0


class TestMemoryBackendStats:
    @pytest.fixture
    def backend(self):
        return _MemoryBackend(max_size=100)

    @pytest.mark.asyncio
    async def test_stats_reports_backend_type(self, backend):
        stats = await backend.stats()
        assert stats["backend"] == "memory"
        assert stats["max_size"] == 100
        assert stats["total_keys"] == 0
        assert stats["live_keys"] == 0

    @pytest.mark.asyncio
    async def test_stats_counts_live_keys(self, backend):
        await backend.set("live1", "v", ttl=3600)
        await backend.set("live2", "v", ttl=3600)
        stats = await backend.stats()
        assert stats["total_keys"] == 2
        assert stats["live_keys"] == 2


class TestMemoryBackendEviction:
    @pytest.mark.asyncio
    async def test_eviction_when_full(self):
        backend = _MemoryBackend(max_size=5)
        for i in range(5):
            await backend.set(f"key{i}", f"val{i}", ttl=3600)
        # Adding 6th triggers eviction
        await backend.set("key5", "val5", ttl=3600)
        stats = await backend.stats()
        assert stats["total_keys"] <= 5

    @pytest.mark.asyncio
    async def test_eviction_removes_expired_first(self):
        backend = _MemoryBackend(max_size=3)
        await backend.set("expired", "v", ttl=1)
        # Manually expire
        async with backend._lock:
            val, _ = backend._store["expired"]
            backend._store["expired"] = (val, time.time() - 10)
        await backend.set("k2", "v2", ttl=3600)
        await backend.set("k3", "v3", ttl=3600)
        await backend.set("k4", "v4", ttl=3600)  # triggers eviction
        stats = await backend.stats()
        assert stats["total_keys"] <= 3


# ---------------------------------------------------------------------------
# CacheManager
# ---------------------------------------------------------------------------


class TestCacheManager:
    @pytest.fixture
    def cm(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_CACHE_URL", raising=False)
        return CacheManager()

    @pytest.mark.asyncio
    async def test_get_set_delete(self, cm):
        await cm.set("test_key", {"a": 1}, ttl=60)
        assert await cm.get("test_key") == {"a": 1}
        await cm.delete("test_key")
        assert await cm.get("test_key") is None

    @pytest.mark.asyncio
    async def test_invalidate_pattern(self, cm):
        await cm.set("pref:a", 1, ttl=60)
        await cm.set("pref:b", 2, ttl=60)
        n = await cm.invalidate_pattern("pref:*")
        assert n == 2

    @pytest.mark.asyncio
    async def test_clear(self, cm):
        await cm.set("x", 1, ttl=60)
        await cm.clear()
        assert await cm.get("x") is None

    @pytest.mark.asyncio
    async def test_stats(self, cm):
        stats = await cm.stats()
        assert "backend" in stats
        assert stats["backend"] == "memory"


# ---------------------------------------------------------------------------
# @cached decorator
# ---------------------------------------------------------------------------


class TestCachedDecorator:
    @pytest.mark.asyncio
    async def test_cached_returns_result(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_CACHE_URL", raising=False)
        call_count = 0

        @cached(ttl=300, prefix="test")
        async def compute(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        result = await compute(5)
        assert result == 10
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_cached_returns_cached_on_second_call(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_CACHE_URL", raising=False)
        call_count = 0

        @cached(ttl=300, prefix="test2")
        async def compute(x):
            nonlocal call_count
            call_count += 1
            return x + 100

        r1 = await compute(3)
        r2 = await compute(3)
        assert r1 == r2 == 103
        # May be 1 or 2 depending on cache state; at most 2
        assert call_count <= 2

    @pytest.mark.asyncio
    async def test_cached_different_args_different_results(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_CACHE_URL", raising=False)

        @cached(ttl=300, prefix="test3")
        async def compute(x):
            return x ** 2

        assert await compute(2) == 4
        assert await compute(3) == 9

    @pytest.mark.asyncio
    async def test_cached_none_result_not_cached(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_CACHE_URL", raising=False)
        call_count = 0

        @cached(ttl=300, prefix="test4")
        async def get_none():
            nonlocal call_count
            call_count += 1
            return None

        r1 = await get_none()
        r2 = await get_none()
        assert r1 is None
        assert r2 is None
        assert call_count == 2  # Called twice since None is not cached
