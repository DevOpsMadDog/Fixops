"""Tests for InMemoryVectorStore — hash-based embeddings and cosine search."""
import pytest

from core.services.enterprise.vector_store import (
    VectorRecord,
    InMemoryVectorStore,
)


class TestVectorRecord:
    def test_create(self):
        r = VectorRecord(id="r1", embedding=[0.1, 0.2], metadata={"k": "v"})
        assert r.id == "r1"
        assert r.embedding == [0.1, 0.2]
        assert r.metadata == {"k": "v"}
        assert r.similarity_score == 0.0

    def test_with_score(self):
        r = VectorRecord(id="r2", embedding=[1.0], metadata={}, similarity_score=0.95)
        assert r.similarity_score == 0.95


class TestInMemoryVectorStore:
    @pytest.fixture
    def store(self):
        return InMemoryVectorStore()

    @pytest.mark.asyncio
    async def test_init_not_initialized(self, store):
        assert store._initialized is False
        assert store._memory_store == []

    @pytest.mark.asyncio
    async def test_initialize_loads_baseline(self, store):
        await store.initialize()
        assert store._initialized is True
        assert len(store._memory_store) == 4  # 4 baseline patterns

    @pytest.mark.asyncio
    async def test_initialize_idempotent(self, store):
        await store.initialize()
        count_first = len(store._memory_store)
        await store.initialize()
        assert len(store._memory_store) == count_first

    @pytest.mark.asyncio
    async def test_upsert(self, store):
        r = VectorRecord(id="test1", embedding=[0.5] * 16, metadata={"t": 1})
        await store.upsert([r])
        assert len(store._memory_store) == 1
        assert store._memory_store[0].id == "test1"

    @pytest.mark.asyncio
    async def test_upsert_replaces_existing(self, store):
        r1 = VectorRecord(id="test1", embedding=[0.5] * 16, metadata={"v": 1})
        r2 = VectorRecord(id="test1", embedding=[0.9] * 16, metadata={"v": 2})
        await store.upsert([r1])
        await store.upsert([r2])
        assert len(store._memory_store) == 1
        assert store._memory_store[0].metadata["v"] == 2

    @pytest.mark.asyncio
    async def test_search_empty_store(self, store):
        results = await store.search([0.5] * 16, top_k=5)
        assert results == []

    @pytest.mark.asyncio
    async def test_search_returns_top_k(self, store):
        records = [
            VectorRecord(id=f"r{i}", embedding=[float(i) / 10] * 16, metadata={})
            for i in range(10)
        ]
        await store.upsert(records)
        results = await store.search([0.9] * 16, top_k=3)
        assert len(results) == 3
        # All should have similarity scores
        for r in results:
            assert r.similarity_score > 0

    @pytest.mark.asyncio
    async def test_search_order_by_similarity(self, store):
        await store.initialize()
        results = await store.search([0.5] * 16, top_k=4)
        scores = [r.similarity_score for r in results]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio
    async def test_generate_embedding(self, store):
        emb = await store._generate_embedding("test text")
        assert isinstance(emb, list)
        assert len(emb) == 16
        assert all(0.0 <= v <= 1.0 for v in emb)

    @pytest.mark.asyncio
    async def test_generate_embedding_deterministic(self, store):
        e1 = await store._generate_embedding("same text")
        e2 = await store._generate_embedding("same text")
        assert e1 == e2

    @pytest.mark.asyncio
    async def test_generate_embedding_different_texts(self, store):
        e1 = await store._generate_embedding("text A")
        e2 = await store._generate_embedding("text B")
        assert e1 != e2

    @pytest.mark.asyncio
    async def test_search_security_patterns(self, store):
        await store.initialize()
        results = await store.search_security_patterns("SQL injection attack", top_k=2)
        assert len(results) == 2
        assert all(isinstance(r, VectorRecord) for r in results)

    @pytest.mark.asyncio
    async def test_add_security_patterns(self, store):
        patterns = [
            {"id": "custom1", "text": "Path traversal in file upload"},
            {"id": "custom2", "text": "SSRF vulnerability in proxy"},
        ]
        await store.add_security_patterns(patterns)
        assert len(store._memory_store) == 2
