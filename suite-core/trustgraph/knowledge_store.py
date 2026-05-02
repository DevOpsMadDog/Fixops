"""
Knowledge Storage Engine for TrustGraph.

Implements SQLite-backed knowledge storage with full-text search, graph traversal,
and multi-tenant support. Provides core statistics and relationship management.

Usage:
    store = KnowledgeStore(db_path="/tmp/trustgraph.db")

    # Ingest an entity
    entity = KnowledgeEntity(
        entity_id="svc_prod_api",
        core_id=1,
        entity_type="Service",
        name="Production API",
        properties={"criticality": "critical", "owner": "backend-team"},
        org_id="org_123"
    )
    store.ingest(entity)

    # Search across a core
    results = store.search(core_id=1, query_text="critical", limit=20)

    # Create relationships
    rel = KnowledgeRelationship(
        rel_id="rel_001",
        source_id="svc_prod_api",
        target_id="team_backend",
        rel_type="owned_by",
        confidence=0.95
    )
    store.add_relationship(rel)

    # Graph traversal
    neighbors = store.get_neighbors(entity_id="svc_prod_api", depth=2)

    # Core statistics
    stats = store.core_stats(core_id=1)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "KnowledgeEntity",
    "KnowledgeRelationship",
    "KnowledgeStore",
]

# TrustGraph event bus — optional, never blocks on failure.
# This module IS part of TrustGraph; emitting here makes the store's own
# ingestion observable in the second-brain (the bus is decoupled from the
# store, so there is no cycle).
try:  # pragma: no cover - bus is optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit an event to the TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio
            import inspect
            if inspect.iscoroutine(result):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class KnowledgeEntity:
    """A knowledge entity in TrustGraph.

    Attributes:
        entity_id: Unique identifier for this entity
        core_id: Knowledge Core this entity belongs to (1-5)
        entity_type: Type of entity (e.g., "Service", "CVE", "Control")
        name: Human-readable name
        properties: Arbitrary properties as dict
        embeddings: Optional embedding vector
        created_at: Creation timestamp
        updated_at: Last update timestamp
        org_id: Organization/tenant ID for multi-tenancy
    """

    entity_id: str
    core_id: int
    entity_type: str
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    embeddings: Optional[List[float]] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    org_id: str = "default"

    def __post_init__(self) -> None:
        """Validate entity."""
        if not 1 <= self.core_id <= 5:
            raise ValueError(f"Invalid core_id {self.core_id}: must be 1-5")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, serializing datetime."""
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        d["updated_at"] = self.updated_at.isoformat()
        return d


@dataclass
class KnowledgeRelationship:
    """A relationship between two knowledge entities.

    Attributes:
        rel_id: Unique identifier for this relationship
        source_id: Source entity ID
        target_id: Target entity ID
        rel_type: Type of relationship (e.g., "depends_on", "related_to")
        properties: Additional relationship properties
        confidence: Confidence score 0-1
        created_at: Creation timestamp
    """

    rel_id: str
    source_id: str
    target_id: str
    rel_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self) -> None:
        """Validate relationship."""
        if not 0 <= self.confidence <= 1:
            raise ValueError(f"Confidence must be 0-1, got {self.confidence}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, serializing datetime."""
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        return d


# ============================================================================
# Knowledge Store
# ============================================================================


class KnowledgeStore:
    """SQLite-backed knowledge storage with FTS5 search and graph traversal.

    Features:
    - Full-text search over entity names and properties
    - Graph relationships with confidence scoring
    - Multi-tenant support via org_id
    - Core statistics and analytics
    - Soft delete support
    - Thread-safe operations
    """

    def __init__(self, db_path: str = "/tmp/trustgraph.db") -> None:  # nosec B108
        """Initialize knowledge store.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()
        logger.info(f"KnowledgeStore initialized at {db_path}")

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_conn()
        cursor = conn.cursor()

        # Entities table with FTS5
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS entities (
                entity_id TEXT PRIMARY KEY,
                core_id INTEGER NOT NULL,
                entity_type TEXT NOT NULL,
                name TEXT NOT NULL,
                properties TEXT NOT NULL,
                embeddings TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                org_id TEXT NOT NULL,
                deleted_at TEXT
            )
            """
        )

        # FTS5 virtual table for search
        cursor.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts
            USING fts5(name, properties, content=entities, content_rowid=entity_id)
            """
        )

        # Relationships table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS relationships (
                rel_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                rel_type TEXT NOT NULL,
                properties TEXT NOT NULL,
                confidence REAL NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (source_id) REFERENCES entities(entity_id),
                FOREIGN KEY (target_id) REFERENCES entities(entity_id)
            )
            """
        )

        # Create indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_core_id ON entities(core_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entities_org_id ON entities(org_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_type ON relationships(rel_type)")

        conn.commit()
        logger.debug("Database schema initialized")

    def ingest(self, entity: KnowledgeEntity) -> None:
        """Add or update an entity.

        Args:
            entity: KnowledgeEntity to ingest
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()

        # Upsert entity
        cursor.execute(
            """
            INSERT OR REPLACE INTO entities
            (entity_id, core_id, entity_type, name, properties, embeddings, created_at, updated_at, org_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity.entity_id,
                entity.core_id,
                entity.entity_type,
                entity.name,
                json.dumps(entity.properties),
                json.dumps(entity.embeddings) if entity.embeddings else None,
                entity.created_at.isoformat(),
                now,
                entity.org_id,
            ),
        )

        # Update FTS index (delete old entry and insert new one)
        try:
            cursor.execute(
                "DELETE FROM entities_fts WHERE rowid IN (SELECT rowid FROM entities_fts WHERE name = ?)",
                (entity.name,),
            )
        except Exception:
            pass  # Ignore errors for non-existent FTS entries

        cursor.execute(
            "INSERT INTO entities_fts(name, properties) VALUES (?, ?)",
            (entity.name, json.dumps(entity.properties)),
        )

        conn.commit()
        logger.debug(f"Ingested entity {entity.entity_id}")
        _emit_event(
            "trustgraph.entity.ingested",
            {
                "entity_id": entity.entity_id,
                "core_id": entity.core_id,
                "entity_type": entity.entity_type,
                "org_id": entity.org_id,
            },
        )

    def search(
        self,
        core_id: int,
        query_text: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 20,
    ) -> List[KnowledgeEntity]:
        """Full-text search over entities in a core.

        Args:
            core_id: Knowledge Core ID to search
            query_text: Search query
            filters: Optional filters (entity_type, org_id, etc.)
            limit: Maximum results to return

        Returns:
            List of matching KnowledgeEntity objects
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Build query
        where_clause = "entities.core_id = ?"
        params: List[Any] = [core_id]

        if filters:
            if "entity_type" in filters:
                where_clause += " AND entities.entity_type = ?"
                params.append(filters["entity_type"])
            if "org_id" in filters:
                where_clause += " AND entities.org_id = ?"
                params.append(filters["org_id"])

        # Add soft delete filter
        where_clause += " AND entities.deleted_at IS NULL"

        # FTS search: search entities_fts first, then join to get full data
        # Note: We use rowid from FTS to join, not entity_id column
        sql = (  # nosec B608 — table/column names hardcoded; query_text bound via ?
            "SELECT entities.* FROM entities"  # nosec B608
            " WHERE entities.entity_id IN ("
            "  SELECT entity_id FROM ("
            "   SELECT entities.entity_id FROM entities"
            "   JOIN entities_fts ON entities.rowid = entities_fts.rowid"
            "   WHERE entities_fts MATCH ?"
            "  )"
            " )"
            f" AND {where_clause}"
            " LIMIT ?"
        )
        params.insert(0, query_text)
        params.append(limit)

        try:
            cursor.execute(sql, params)
            rows = cursor.fetchall()
        except Exception as e:
            logger.warning(f"FTS search failed, falling back to LIKE: {e}")
            # Fallback to LIKE search
            sql_fallback = (  # nosec B608 — table/column names hardcoded; values bound via ?
                "SELECT entities.* FROM entities"  # nosec B608
                " WHERE (entities.name LIKE ? OR entities.properties LIKE ?)"
                f" AND {where_clause}"
                " LIMIT ?"
            )
            like_query = f"%{query_text}%"
            params_fallback = [like_query, like_query] + params[1:]
            cursor.execute(sql_fallback, params_fallback)  # nosec B608
            rows = cursor.fetchall()

        entities = []
        for row in rows:
            entity = self._row_to_entity(row)
            entities.append(entity)

        logger.debug(f"Search for '{query_text}' in core {core_id} returned {len(entities)} results")
        return entities

    def get_entity(self, entity_id: str) -> Optional[KnowledgeEntity]:
        """Get entity by ID.

        Args:
            entity_id: Entity ID to retrieve

        Returns:
            KnowledgeEntity or None if not found
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM entities WHERE entity_id = ? AND deleted_at IS NULL",
            (entity_id,),
        )
        row = cursor.fetchone()

        if not row:
            return None

        return self._row_to_entity(row)

    def add_relationship(self, rel: KnowledgeRelationship) -> None:
        """Add a relationship between entities.

        Args:
            rel: KnowledgeRelationship to add
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO relationships
            (rel_id, source_id, target_id, rel_type, properties, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rel.rel_id,
                rel.source_id,
                rel.target_id,
                rel.rel_type,
                json.dumps(rel.properties),
                rel.confidence,
                rel.created_at.isoformat(),
            ),
        )

        conn.commit()
        logger.debug(f"Added relationship {rel.rel_id}")
        _emit_event(
            "trustgraph.relationship.added",
            {
                "rel_id": rel.rel_id,
                "rel_type": rel.rel_type,
                "source_id": rel.source_id,
                "target_id": rel.target_id,
                "confidence": rel.confidence,
            },
        )

    def get_relationships(
        self,
        entity_id: str,
        rel_type: Optional[str] = None,
    ) -> List[KnowledgeRelationship]:
        """Get relationships for an entity.

        Args:
            entity_id: Entity to get relationships for
            rel_type: Optional filter by relationship type

        Returns:
            List of KnowledgeRelationship objects
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        if rel_type:
            where_clause = "(source_id = ? OR target_id = ?) AND rel_type = ?"
            params: List[Any] = [entity_id, entity_id, rel_type]
        else:
            where_clause = "source_id = ? OR target_id = ?"
            params = [entity_id, entity_id]

        cursor.execute(
            f"SELECT * FROM relationships WHERE {where_clause}",  # nosec B608
            params,
        )
        rows = cursor.fetchall()

        relationships = []
        for row in rows:
            rel = self._row_to_relationship(row)
            relationships.append(rel)

        return relationships

    def get_neighbors(self, entity_id: str, depth: int = 1) -> List[KnowledgeEntity]:
        """Traverse graph to find neighboring entities.

        Args:
            entity_id: Starting entity
            depth: Depth of traversal (1-3)

        Returns:
            List of neighboring entities
        """
        if depth < 1 or depth > 3:
            depth = 1

        conn = self._get_conn()
        cursor = conn.cursor()

        visited = {entity_id}
        neighbors = []

        for _ in range(depth):
            placeholders = ",".join("?" * len(visited))
            neighbor_sql = (  # nosec B608 — table/column names hardcoded; placeholders are ? * len(visited)
                f"SELECT target_id FROM relationships WHERE source_id IN ({placeholders})"  # nosec B608
                f" UNION"
                f" SELECT source_id FROM relationships WHERE target_id IN ({placeholders})"
            )
            cursor.execute(neighbor_sql, list(visited) * 2)  # nosec B608
            next_ids = set(row[0] for row in cursor.fetchall())
            next_ids -= visited

            if not next_ids:
                break

            visited.update(next_ids)

        # Fetch all neighbors
        for nid in visited - {entity_id}:
            entity = self.get_entity(nid)
            if entity:
                neighbors.append(entity)

        return neighbors

    def core_stats(self, core_id: int) -> Dict[str, Any]:
        """Get statistics for a core.

        Args:
            core_id: Knowledge Core ID

        Returns:
            Dictionary with entity_count, relationship_count, last_updated
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Entity count
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM entities WHERE core_id = ? AND deleted_at IS NULL",
            (core_id,),
        )
        entity_count = cursor.fetchone()[0]

        # Relationship count
        cursor.execute(
            """
            SELECT COUNT(*) as cnt FROM relationships
            WHERE source_id IN (
                SELECT entity_id FROM entities WHERE core_id = ? AND deleted_at IS NULL
            )
            """,
            (core_id,),
        )
        rel_count = cursor.fetchone()[0]

        # Last updated
        cursor.execute(
            "SELECT MAX(updated_at) as last_updated FROM entities WHERE core_id = ? AND deleted_at IS NULL",
            (core_id,),
        )
        row = cursor.fetchone()
        last_updated = row[0] if row[0] else None

        # Entity type breakdown
        cursor.execute(
            """
            SELECT entity_type, COUNT(*) as cnt
            FROM entities
            WHERE core_id = ? AND deleted_at IS NULL
            GROUP BY entity_type
            ORDER BY cnt DESC
            """,
            (core_id,),
        )
        type_breakdown = {row[0]: row[1] for row in cursor.fetchall()}

        return {
            "entity_count": entity_count,
            "relationship_count": rel_count,
            "last_updated": last_updated,
            "entity_types": type_breakdown,
            "core_id": core_id,
        }

    def delete_entity(self, entity_id: str) -> None:
        """Soft delete an entity.

        Args:
            entity_id: Entity to delete
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE entities SET deleted_at = ? WHERE entity_id = ?",
            (datetime.utcnow().isoformat(), entity_id),
        )

        conn.commit()
        logger.debug(f"Soft deleted entity {entity_id}")

    def _row_to_entity(self, row: sqlite3.Row) -> KnowledgeEntity:
        """Convert database row to KnowledgeEntity."""
        return KnowledgeEntity(
            entity_id=row["entity_id"],
            core_id=row["core_id"],
            entity_type=row["entity_type"],
            name=row["name"],
            properties=json.loads(row["properties"]),
            embeddings=json.loads(row["embeddings"]) if row["embeddings"] else None,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            org_id=row["org_id"],
        )

    def _row_to_relationship(self, row: sqlite3.Row) -> KnowledgeRelationship:
        """Convert database row to KnowledgeRelationship."""
        return KnowledgeRelationship(
            rel_id=row["rel_id"],
            source_id=row["source_id"],
            target_id=row["target_id"],
            rel_type=row["rel_type"],
            properties=json.loads(row["properties"]),
            confidence=row["confidence"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
