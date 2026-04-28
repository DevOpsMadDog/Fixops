"""Unified Tag Management — cross-entity tagging with hierarchy, auto-rules, and analytics.

Provides tagging for FINDING, ASSET, VENDOR, INCIDENT, SBOM, EVIDENCE, REPORT entities.
SQLite-backed, thread-safe, org-scoped.

Usage:
    from core.tag_manager import TagManager, EntityType, get_tag_manager
    mgr = get_tag_manager()
    tag = mgr.create_tag("critical", "#FF0000", "Critical priority", org_id="default")
    mgr.apply_tag(EntityType.FINDING, "finding-123", tag.id)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_TAG_MANAGER_DB", ".fixops_data/tag_manager.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EntityType(str, Enum):
    FINDING = "finding"
    ASSET = "asset"
    VENDOR = "vendor"
    INCIDENT = "incident"
    SBOM = "sbom"
    EVIDENCE = "evidence"
    REPORT = "report"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class Tag(BaseModel):
    id: str = Field(default_factory=lambda: f"tag-{uuid.uuid4().hex[:12]}")
    name: str
    color: str = Field(default="#6B7280", description="Hex color code")
    description: str = ""
    parent_id: Optional[str] = None
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AutoTagRule(BaseModel):
    id: str = Field(default_factory=lambda: f"atr-{uuid.uuid4().hex[:12]}")
    name: str
    conditions: Dict[str, Any] = Field(default_factory=dict, description="field/op/value conditions")
    tags_to_apply: List[str] = Field(default_factory=list, description="Tag IDs to apply")
    entity_type: EntityType
    enabled: bool = True
    org_id: str = "default"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------

class _TagDB:
    """SQLite persistence for tags, entity-tag mappings, and auto-rules."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        dir_part = os.path.dirname(db_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS tags (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    color TEXT NOT NULL DEFAULT '#6B7280',
                    description TEXT NOT NULL DEFAULT '',
                    parent_id TEXT,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tag_org ON tags(org_id);
                CREATE INDEX IF NOT EXISTS idx_tag_name ON tags(name);
                CREATE INDEX IF NOT EXISTS idx_tag_parent ON tags(parent_id);

                CREATE TABLE IF NOT EXISTS entity_tags (
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    tag_id TEXT NOT NULL,
                    applied_at TEXT NOT NULL,
                    PRIMARY KEY (entity_type, entity_id, tag_id),
                    FOREIGN KEY (tag_id) REFERENCES tags(id)
                );
                CREATE INDEX IF NOT EXISTS idx_et_entity ON entity_tags(entity_type, entity_id);
                CREATE INDEX IF NOT EXISTS idx_et_tag ON entity_tags(tag_id);

                CREATE TABLE IF NOT EXISTS auto_tag_rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    conditions TEXT NOT NULL DEFAULT '{}',
                    tags_to_apply TEXT NOT NULL DEFAULT '[]',
                    entity_type TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    org_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_atr_org ON auto_tag_rules(org_id);
                CREATE INDEX IF NOT EXISTS idx_atr_entity_type ON auto_tag_rules(entity_type);
            """)
            self._conn.commit()

    # ---- Tag CRUD ----

    def insert_tag(self, tag: Tag) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO tags (id, name, color, description, parent_id, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (tag.id, tag.name, tag.color, tag.description, tag.parent_id, tag.org_id, tag.created_at),
            )
            self._conn.commit()

    def get_tag(self, tag_id: str) -> Optional[Tag]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM tags WHERE id = ?", (tag_id,)).fetchone()
        return self._row_to_tag(row) if row else None

    def list_tags(self, org_id: str, parent_id: Optional[str] = None) -> List[Tag]:
        if parent_id is None:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM tags WHERE org_id = ? ORDER BY name", (org_id,)
                ).fetchall()
        else:
            sentinel = parent_id if parent_id != "__root__" else None
            with self._lock:
                if sentinel is None:
                    rows = self._conn.execute(
                        "SELECT * FROM tags WHERE org_id = ? AND parent_id IS NULL ORDER BY name",
                        (org_id,),
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        "SELECT * FROM tags WHERE org_id = ? AND parent_id = ? ORDER BY name",
                        (org_id, sentinel),
                    ).fetchall()
        return [self._row_to_tag(r) for r in rows]

    def update_tag(self, tag_id: str, updates: Dict[str, Any]) -> Optional[Tag]:
        allowed = {"name", "color", "description", "parent_id"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return self.get_tag(tag_id)
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [tag_id]
        with self._lock:
            self._conn.execute(f"UPDATE tags SET {set_clause} WHERE id = ?", values)  # nosemgrep: formatted-sql-query  # nosec B608
            self._conn.commit()
        return self.get_tag(tag_id)

    def delete_tag(self, tag_id: str) -> bool:
        with self._lock:
            self._conn.execute("DELETE FROM entity_tags WHERE tag_id = ?", (tag_id,))
            cur = self._conn.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def search_tags(self, query: str, org_id: str) -> List[Tag]:
        q = f"%{query.lower()}%"
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM tags WHERE org_id = ?
                   AND (lower(name) LIKE ? OR lower(description) LIKE ?)
                   ORDER BY name""",
                (org_id, q, q),
            ).fetchall()
        return [self._row_to_tag(r) for r in rows]

    # ---- Entity-tag mappings ----

    def apply_tag(self, entity_type: str, entity_id: str, tag_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """INSERT OR IGNORE INTO entity_tags (entity_type, entity_id, tag_id, applied_at)
                   VALUES (?, ?, ?, ?)""",
                (entity_type, entity_id, tag_id, now),
            )
            self._conn.commit()

    def remove_tag(self, entity_type: str, entity_id: str, tag_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM entity_tags WHERE entity_type = ? AND entity_id = ? AND tag_id = ?",
                (entity_type, entity_id, tag_id),
            )
            self._conn.commit()

    def get_entity_tags(self, entity_type: str, entity_id: str) -> List[Tag]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT t.* FROM tags t
                   JOIN entity_tags et ON t.id = et.tag_id
                   WHERE et.entity_type = ? AND et.entity_id = ?
                   ORDER BY t.name""",
                (entity_type, entity_id),
            ).fetchall()
        return [self._row_to_tag(r) for r in rows]

    def find_entities_by_tag(self, tag_id: str, entity_type: Optional[str] = None) -> List[str]:
        if entity_type:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT entity_id FROM entity_tags WHERE tag_id = ? AND entity_type = ?",
                    (tag_id, entity_type),
                ).fetchall()
        else:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT entity_id FROM entity_tags WHERE tag_id = ?", (tag_id,)
                ).fetchall()
        return [r[0] for r in rows]

    def bulk_apply(self, entity_type: str, entity_ids: List[str], tag_ids: List[str]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.executemany(
                """INSERT OR IGNORE INTO entity_tags (entity_type, entity_id, tag_id, applied_at)
                   VALUES (?, ?, ?, ?)""",
                [(entity_type, eid, tid, now) for eid in entity_ids for tid in tag_ids],
            )
            self._conn.commit()

    def reassign_tag(self, source_tag_id: str, target_tag_id: str) -> None:
        """Reassign all entity_tags from source to target (for merge)."""
        with self._lock:
            # Insert rows that don't already exist under target
            self._conn.execute(
                """INSERT OR IGNORE INTO entity_tags (entity_type, entity_id, tag_id, applied_at)
                   SELECT entity_type, entity_id, ?, applied_at FROM entity_tags WHERE tag_id = ?""",
                (target_tag_id, source_tag_id),
            )
            self._conn.execute("DELETE FROM entity_tags WHERE tag_id = ?", (source_tag_id,))
            self._conn.commit()

    # ---- Analytics ----

    def get_tag_usage(self, org_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT t.id, t.name, t.color, COUNT(et.tag_id) as usage_count
                   FROM tags t
                   LEFT JOIN entity_tags et ON t.id = et.tag_id
                   WHERE t.org_id = ?
                   GROUP BY t.id
                   ORDER BY usage_count DESC""",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_usage_by_entity_type(self, org_id: str) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT et.entity_type, COUNT(*) as cnt
                   FROM entity_tags et
                   JOIN tags t ON et.tag_id = t.id
                   WHERE t.org_id = ?
                   GROUP BY et.entity_type""",
                (org_id,),
            ).fetchall()
        return {r[0]: r[1] for r in rows}

    # ---- Auto-tag rules ----

    def insert_rule(self, rule: AutoTagRule) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO auto_tag_rules
                   (id, name, conditions, tags_to_apply, entity_type, enabled, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rule.id, rule.name,
                    json.dumps(rule.conditions),
                    json.dumps(rule.tags_to_apply),
                    rule.entity_type.value,
                    1 if rule.enabled else 0,
                    rule.org_id,
                    rule.created_at,
                ),
            )
            self._conn.commit()

    def list_rules(self, org_id: str) -> List[AutoTagRule]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM auto_tag_rules WHERE org_id = ? ORDER BY name",
                (org_id,),
            ).fetchall()
        return [self._row_to_rule(r) for r in rows]

    # ---- Row converters ----

    @staticmethod
    def _row_to_tag(row: sqlite3.Row) -> Tag:
        d = dict(row)
        return Tag(**d)

    @staticmethod
    def _row_to_rule(row: sqlite3.Row) -> AutoTagRule:
        d = dict(row)
        d["conditions"] = json.loads(d["conditions"])
        d["tags_to_apply"] = json.loads(d["tags_to_apply"])
        d["enabled"] = bool(d["enabled"])
        return AutoTagRule(**d)


# ---------------------------------------------------------------------------
# TagManager — public interface
# ---------------------------------------------------------------------------

class TagManager:
    """Universal tag manager for all ALDECI entities.

    Thread-safe, SQLite-backed, org-scoped tagging with hierarchy, auto-rules,
    analytics, and merge support.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _TagDB(db_path)
        logger.info("TagManager initialised", db_path=db_path)

    # ---- Tag CRUD ----

    def create_tag(
        self,
        name: str,
        color: str = "#6B7280",
        description: str = "",
        parent_id: Optional[str] = None,
        org_id: str = "default",
    ) -> Tag:
        tag = Tag(name=name, color=color, description=description, parent_id=parent_id, org_id=org_id)
        self._db.insert_tag(tag)
        logger.info("Tag created", tag_id=tag.id, name=name, org_id=org_id)
        _emit_event("tag_manager.tag_created", {
            "tag_id": tag.id,
            "org_id": org_id,
            "name": name,
        })
        return tag

    def get_tag(self, tag_id: str) -> Optional[Tag]:
        return self._db.get_tag(tag_id)

    def list_tags(self, org_id: str, parent_id: Optional[str] = None) -> List[Tag]:
        return self._db.list_tags(org_id, parent_id)

    def update_tag(self, tag_id: str, updates: Dict[str, Any]) -> Optional[Tag]:
        tag = self._db.update_tag(tag_id, updates)
        if tag:
            logger.info("Tag updated", tag_id=tag_id, fields=list(updates.keys()))
        return tag

    def delete_tag(self, tag_id: str) -> bool:
        """Delete a tag and cascade-remove it from all entities."""
        deleted = self._db.delete_tag(tag_id)
        if deleted:
            logger.info("Tag deleted", tag_id=tag_id)
        return deleted

    # ---- Entity-tag operations ----

    def apply_tag(self, entity_type: EntityType, entity_id: str, tag_id: str) -> None:
        self._db.apply_tag(entity_type.value, entity_id, tag_id)
        logger.debug("Tag applied", entity_type=entity_type.value, entity_id=entity_id, tag_id=tag_id)

    def remove_tag(self, entity_type: EntityType, entity_id: str, tag_id: str) -> None:
        self._db.remove_tag(entity_type.value, entity_id, tag_id)
        logger.debug("Tag removed", entity_type=entity_type.value, entity_id=entity_id, tag_id=tag_id)

    def get_entity_tags(self, entity_type: EntityType, entity_id: str) -> List[Tag]:
        return self._db.get_entity_tags(entity_type.value, entity_id)

    def find_entities_by_tag(self, tag_id: str, entity_type: Optional[EntityType] = None) -> List[str]:
        et = entity_type.value if entity_type else None
        return self._db.find_entities_by_tag(tag_id, et)

    def bulk_apply(self, entity_type: EntityType, entity_ids: List[str], tag_ids: List[str]) -> None:
        self._db.bulk_apply(entity_type.value, entity_ids, tag_ids)
        logger.info(
            "Bulk tag applied",
            entity_type=entity_type.value,
            entity_count=len(entity_ids),
            tag_count=len(tag_ids),
        )

    # ---- Auto-tag rules ----

    def create_auto_rule(self, rule: AutoTagRule) -> AutoTagRule:
        self._db.insert_rule(rule)
        logger.info("AutoTagRule created", rule_id=rule.id, name=rule.name, org_id=rule.org_id)
        return rule

    def list_auto_rules(self, org_id: str) -> List[AutoTagRule]:
        return self._db.list_rules(org_id)

    def evaluate_auto_rules(
        self,
        entity_type: EntityType,
        entity: Dict[str, Any],
        org_id: str,
    ) -> List[str]:
        """Evaluate enabled auto-tag rules for the given entity.

        Each rule's ``conditions`` dict uses the structure::

            {"field": "severity", "op": "eq", "value": "critical"}

        Supported ops: ``eq``, ``ne``, ``contains``, ``gt``, ``lt``, ``in``.

        Returns a deduplicated list of tag IDs that should be applied.
        """
        rules = [
            r for r in self._db.list_rules(org_id)
            if r.enabled and r.entity_type == entity_type
        ]
        tags_to_apply: List[str] = []
        for rule in rules:
            if self._match_conditions(rule.conditions, entity):
                tags_to_apply.extend(rule.tags_to_apply)
        # Deduplicate while preserving order
        seen: set = set()
        result = []
        for t in tags_to_apply:
            if t not in seen:
                seen.add(t)
                result.append(t)
        return result

    @staticmethod
    def _match_conditions(conditions: Dict[str, Any], entity: Dict[str, Any]) -> bool:
        """Return True if the entity satisfies the conditions dict."""
        if not conditions:
            return True
        # Support single condition or list-of-conditions (AND semantics)
        cond_list = conditions if isinstance(conditions, list) else [conditions]
        for cond in cond_list:
            field = cond.get("field", "")
            op = cond.get("op", "eq")
            expected = cond.get("value")
            actual = entity.get(field)
            if op == "eq" and actual != expected:
                return False
            elif op == "ne" and actual == expected:
                return False
            elif op == "contains" and (actual is None or str(expected) not in str(actual)):
                return False
            elif op == "gt":
                try:
                    if not (float(actual) > float(expected)):
                        return False
                except (TypeError, ValueError):
                    return False
            elif op == "lt":
                try:
                    if not (float(actual) < float(expected)):
                        return False
                except (TypeError, ValueError):
                    return False
            elif op == "in":
                if not isinstance(expected, list) or actual not in expected:
                    return False
        return True

    # ---- Hierarchy ----

    def get_tag_hierarchy(self, org_id: str) -> List[Dict[str, Any]]:
        """Return a tree structure of tags for an org.

        Each node has: id, name, color, description, children (list).
        """
        all_tags = self._db.list_tags(org_id)
        by_id = {t.id: {**t.model_dump(), "children": []} for t in all_tags}
        roots: List[Dict[str, Any]] = []
        for tag in all_tags:
            node = by_id[tag.id]
            if tag.parent_id and tag.parent_id in by_id:
                by_id[tag.parent_id]["children"].append(node)
            else:
                roots.append(node)
        return roots

    # ---- Analytics ----

    def get_tag_analytics(self, org_id: str) -> Dict[str, Any]:
        """Return analytics: most used tags, by entity type breakdown."""
        usage = self._db.get_tag_usage(org_id)
        by_entity_type = self._db.get_usage_by_entity_type(org_id)
        most_used = usage[:10]
        trending = usage[:5]  # Top 5 as trending proxy
        return {
            "most_used": most_used,
            "trending": trending,
            "by_entity_type": by_entity_type,
            "total_tags": len(usage),
            "total_applied": sum(r["usage_count"] for r in usage),
        }

    # ---- Search ----

    def search_tags(self, query: str, org_id: str) -> List[Tag]:
        return self._db.search_tags(query, org_id)

    # ---- Merge ----

    def merge_tags(self, source_tag_id: str, target_tag_id: str) -> None:
        """Merge source tag into target: reassign all entity mappings, then delete source."""
        self._db.reassign_tag(source_tag_id, target_tag_id)
        self._db.delete_tag(source_tag_id)
        logger.info("Tags merged", source=source_tag_id, target=target_tag_id)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_tag_manager: Optional[TagManager] = None
_tm_lock = threading.Lock()


def get_tag_manager(db_path: str = _DEFAULT_DB) -> TagManager:
    """Return the process-level TagManager singleton."""
    global _tag_manager
    if _tag_manager is None:
        with _tm_lock:
            if _tag_manager is None:
                _tag_manager = TagManager(db_path)
    return _tag_manager
