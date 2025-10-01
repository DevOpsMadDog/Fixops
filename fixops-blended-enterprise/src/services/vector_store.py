"""
Vector store abstraction with pgvector stub and Mongo fallback
- Honors environment constraint by using Mongo fallback by default
- pgvector backend provided as a stub configurable via settings, no active connection here
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any
import structlog

logger = structlog.get_logger()

@dataclass
class VectorRecord:
    id: str
    embedding: List[float]
    metadata: Dict[str, Any]

class VectorStore:
    async def upsert(self, records: List[VectorRecord]):
        raise NotImplementedError

    async def search(self, embedding: List[float], top_k: int = 5) -> List[VectorRecord]:
        raise NotImplementedError

class MongoVectorStore(VectorStore):
    def __init__(self):
        self._mem: List[VectorRecord] = []

    async def upsert(self, records: List[VectorRecord]):
        # In-memory fallback for demo
        self._mem.extend(records)
        logger.info("MongoVectorStore (fallback) upsert", count=len(records))

    async def search(self, embedding: List[float], top_k: int = 5) -> List[VectorRecord]:
        # Dummy cosine similarity over memory; not optimized
        def cosine(a, b):
            import math
            dot = sum(x*y for x, y in zip(a, b))
            na = math.sqrt(sum(x*x for x in a))
            nb = math.sqrt(sum(y*y for y in b))
            return dot / (na*nb + 1e-9)
        scored = [(cosine(embedding, r.embedding), r) for r in self._mem]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [r for _, r in scored[:top_k]]

class PgVectorStore(VectorStore):
    def __init__(self, dsn: str):
        self.dsn = dsn
        # NOTE: No active connection here to respect environment constraints
        logger.info("PgVectorStore configured (stub)")

    async def upsert(self, records: List[VectorRecord]):
        logger.warning("PgVectorStore.upsert called (stub/no-op)")

    async def search(self, embedding: List[float], top_k: int = 5) -> List[VectorRecord]:
        logger.warning("PgVectorStore.search called (stub/no-op)")
        return []

class VectorStoreFactory:
    @staticmethod
    def create(settings):
        if getattr(settings, 'PGVECTOR_ENABLED', False) and getattr(settings, 'PGVECTOR_DSN', None):
            return PgVectorStore(settings.PGVECTOR_DSN)
        return MongoVectorStore()
