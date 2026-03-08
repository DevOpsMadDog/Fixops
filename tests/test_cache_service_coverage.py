"""Tests for CacheService — in-memory fallback (no Redis required)."""
import pytest

from core.services.enterprise.cache_service import CacheService


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset singleton between tests."""
    old_instance = CacheService._instance
    old_cache = CacheService._in_memory_cache.copy()
    old_client = CacheService._redis_client
    CacheService._instance = None
    CacheService._in_memory_cache = {}
    CacheService._redis_client = None
    yield
    CacheService._instance = old_instance
    CacheService._in_memory_cache = old_cache
    CacheService._redis_client = old_client


class TestCacheServiceSingleton:
    def test_get_instance_returns_same_object(self):
        a = CacheService.get_instance()
        b = CacheService.get_instance()
        assert a is b

    def test_direct_construction_after_singleton_raises(self):
        CacheService.get_instance()
        with pytest.raises(RuntimeError, match="singleton"):
            CacheService()


class TestInMemoryFallback:
    """Without Redis, CacheService falls back to in-memory dict."""

    @pytest.fixture
    def cache(self):
        return CacheService.get_instance()

    @pytest.mark.asyncio
    async def test_set_and_get(self, cache):
        ok = await cache.set("k1", {"hello": "world"})
        assert ok is True
        val = await cache.get("k1")
        assert val == {"hello": "world"}

    @pytest.mark.asyncio
    async def test_get_missing_returns_default(self, cache):
        val = await cache.get("missing", default="fallback")
        assert val == "fallback"

    @pytest.mark.asyncio
    async def test_delete(self, cache):
        await cache.set("k1", "v1")
        deleted = await cache.delete("k1")
        assert deleted is True
        assert await cache.get("k1") is None

    @pytest.mark.asyncio
    async def test_delete_missing(self, cache):
        deleted = await cache.delete("nonexistent")
        assert deleted is False

    @pytest.mark.asyncio
    async def test_exists(self, cache):
        await cache.set("k1", "v1")
        assert await cache.exists("k1") is True
        assert await cache.exists("k2") is False

    @pytest.mark.asyncio
    async def test_set_nx(self, cache):
        ok1 = await cache.set("k1", "first", nx=True)
        assert ok1 is True
        ok2 = await cache.set("k1", "second", nx=True)
        assert ok2 is False
        val = await cache.get("k1")
        assert val == "first"

    @pytest.mark.asyncio
    async def test_ttl_expiry(self, cache):
        # Set with very short TTL
        await cache.set("expiring", "value", ttl=0)
        import time
        time.sleep(0.01)
        val = await cache.get("expiring")
        # TTL=0 means expires_at = now, should be expired after sleep
        assert val is None

    @pytest.mark.asyncio
    async def test_set_string_value(self, cache):
        await cache.set("s1", "hello")
        val = await cache.get("s1")
        assert val == "hello"

    @pytest.mark.asyncio
    async def test_set_list_value(self, cache):
        await cache.set("l1", [1, 2, 3])
        val = await cache.get("l1")
        assert val == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_set_numeric_value(self, cache):
        await cache.set("n1", 42)
        val = await cache.get("n1")
        assert val == "42"  # non-dict/list/str -> str()

    @pytest.mark.asyncio
    async def test_ping(self, cache):
        result = await cache.ping()
        # No redis client, so fallback returns True via hasattr check
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_exists_expired(self, cache):
        await cache.set("exp", "v", ttl=0)
        import time
        time.sleep(0.01)
        assert await cache.exists("exp") is False
