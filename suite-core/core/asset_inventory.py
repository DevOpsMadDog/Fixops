"""Asset Inventory and CMDB Integration — Centralized Asset Management.

Provides auto-discovery, lifecycle tracking, ownership management, tagging,
full-text search, and CMDB sync for all managed assets across orgs.

Usage:
    from core.asset_inventory import AssetInventory, get_asset_inventory
    inventory = get_asset_inventory()
    asset = inventory.register_asset(managed_asset)
    stats = inventory.get_inventory_stats("org-1")
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

_DEFAULT_DB = os.getenv("FIXOPS_ASSET_INVENTORY_DB", ".fixops_data/asset_inventory.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AssetLifecycle(str, Enum):
    DISCOVERED = "discovered"
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    DEPRECATED = "deprecated"
    DECOMMISSIONED = "decommissioned"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    DR = "dr"


# Valid lifecycle transitions: from -> set of allowed destinations
_LIFECYCLE_TRANSITIONS: Dict[AssetLifecycle, set] = {
    AssetLifecycle.DISCOVERED: {AssetLifecycle.ACTIVE, AssetLifecycle.DEPRECATED, AssetLifecycle.DECOMMISSIONED},
    AssetLifecycle.ACTIVE: {AssetLifecycle.MAINTENANCE, AssetLifecycle.DEPRECATED, AssetLifecycle.DECOMMISSIONED},
    AssetLifecycle.MAINTENANCE: {AssetLifecycle.ACTIVE, AssetLifecycle.DEPRECATED, AssetLifecycle.DECOMMISSIONED},
    AssetLifecycle.DEPRECATED: {AssetLifecycle.DECOMMISSIONED, AssetLifecycle.ACTIVE},
    AssetLifecycle.DECOMMISSIONED: set(),
}


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class ManagedAsset(BaseModel):
    id: str = Field(default_factory=lambda: f"masset-{uuid.uuid4().hex[:12]}")
    name: str
    asset_type: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    owner_email: Optional[str] = None
    team: Optional[str] = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    environment: Environment = Environment.PRODUCTION
    lifecycle: AssetLifecycle = AssetLifecycle.DISCOVERED
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_discovered: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finding_count: int = 0
    risk_score: float = 0.0
    org_id: str = "default"


class CMDBSyncRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"sync-{uuid.uuid4().hex[:12]}")
    asset_id: str
    external_id: str
    cmdb_system: str
    synced_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sync_status: str = "success"  # "success" | "failed"
    changes: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------

class _InventoryDB:
    """SQLite persistence for managed assets and CMDB sync records."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        dir_part = os.path.dirname(db_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS managed_assets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    hostname TEXT,
                    ip_address TEXT,
                    owner_email TEXT,
                    team TEXT,
                    criticality TEXT NOT NULL DEFAULT 'medium',
                    environment TEXT NOT NULL DEFAULT 'production',
                    lifecycle TEXT NOT NULL DEFAULT 'discovered',
                    tags TEXT NOT NULL DEFAULT '[]',
                    metadata TEXT NOT NULL DEFAULT '{}',
                    first_discovered TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_masset_org ON managed_assets(org_id);
                CREATE INDEX IF NOT EXISTS idx_masset_type ON managed_assets(asset_type);
                CREATE INDEX IF NOT EXISTS idx_masset_criticality ON managed_assets(criticality);
                CREATE INDEX IF NOT EXISTS idx_masset_lifecycle ON managed_assets(lifecycle);
                CREATE INDEX IF NOT EXISTS idx_masset_environment ON managed_assets(environment);
                CREATE INDEX IF NOT EXISTS idx_masset_owner ON managed_assets(owner_email);

                CREATE TABLE IF NOT EXISTS cmdb_sync_records (
                    id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    cmdb_system TEXT NOT NULL,
                    synced_at TEXT NOT NULL,
                    sync_status TEXT NOT NULL DEFAULT 'success',
                    changes TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_sync_asset ON cmdb_sync_records(asset_id);
                CREATE INDEX IF NOT EXISTS idx_sync_system ON cmdb_sync_records(cmdb_system);
            """)
            self._conn.commit()

    # ---- Asset persistence ----

    def upsert_asset(self, asset: ManagedAsset) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO managed_assets
                   (id, name, asset_type, hostname, ip_address, owner_email, team,
                    criticality, environment, lifecycle, tags, metadata,
                    first_discovered, last_seen, finding_count, risk_score, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asset.id, asset.name, asset.asset_type,
                    asset.hostname, asset.ip_address,
                    asset.owner_email, asset.team,
                    asset.criticality.value, asset.environment.value,
                    asset.lifecycle.value,
                    json.dumps(asset.tags), json.dumps(asset.metadata),
                    asset.first_discovered, asset.last_seen,
                    asset.finding_count, asset.risk_score, asset.org_id,
                ),
            )
            self._conn.commit()

    def get_asset(self, asset_id: str) -> Optional[ManagedAsset]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM managed_assets WHERE id = ?", (asset_id,)
            ).fetchone()
        return self._row_to_asset(row) if row else None

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        environment: Optional[str] = None,
        lifecycle: Optional[str] = None,
        owner_email: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[ManagedAsset]:
        query = "SELECT * FROM managed_assets WHERE org_id = ?"
        params: List[Any] = [org_id]
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if criticality:
            query += " AND criticality = ?"
            params.append(criticality)
        if environment:
            query += " AND environment = ?"
            params.append(environment)
        if lifecycle:
            query += " AND lifecycle = ?"
            params.append(lifecycle)
        if owner_email:
            query += " AND owner_email = ?"
            params.append(owner_email)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        assets = [self._row_to_asset(r) for r in rows]
        if tag:
            assets = [a for a in assets if tag in a.tags]
        return assets

    def delete_asset(self, asset_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM managed_assets WHERE id = ?", (asset_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def search_assets(self, query: str, org_id: str) -> List[ManagedAsset]:
        q = f"%{query.lower()}%"
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM managed_assets
                   WHERE org_id = ? AND (
                       lower(name) LIKE ? OR
                       lower(asset_type) LIKE ? OR
                       lower(coalesce(hostname,'')) LIKE ? OR
                       lower(coalesce(ip_address,'')) LIKE ? OR
                       lower(coalesce(owner_email,'')) LIKE ? OR
                       lower(coalesce(team,'')) LIKE ? OR
                       lower(tags) LIKE ? OR
                       lower(metadata) LIKE ?
                   )""",
                (org_id, q, q, q, q, q, q, q, q),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def get_unowned_assets(self, org_id: str) -> List[ManagedAsset]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM managed_assets WHERE org_id = ? AND (owner_email IS NULL OR owner_email = '')",
                (org_id,),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def get_stale_assets(self, org_id: str, days: int) -> List[ManagedAsset]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM managed_assets WHERE org_id = ? AND last_seen < ?",
                (org_id, cutoff),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM managed_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_type = {
                r[0]: r[1]
                for r in self._conn.execute(
                    "SELECT asset_type, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY asset_type",
                    (org_id,),
                ).fetchall()
            }
            by_criticality = {
                r[0]: r[1]
                for r in self._conn.execute(
                    "SELECT criticality, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY criticality",
                    (org_id,),
                ).fetchall()
            }
            by_lifecycle = {
                r[0]: r[1]
                for r in self._conn.execute(
                    "SELECT lifecycle, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY lifecycle",
                    (org_id,),
                ).fetchall()
            }
            by_environment = {
                r[0]: r[1]
                for r in self._conn.execute(
                    "SELECT environment, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY environment",
                    (org_id,),
                ).fetchall()
            }
            unowned = self._conn.execute(
                "SELECT COUNT(*) FROM managed_assets WHERE org_id = ? AND (owner_email IS NULL OR owner_email = '')",
                (org_id,),
            ).fetchone()[0]

        return {
            "total": total,
            "by_type": by_type,
            "by_criticality": by_criticality,
            "by_lifecycle": by_lifecycle,
            "by_environment": by_environment,
            "unowned_count": unowned,
        }

    # ---- CMDB sync persistence ----

    def insert_sync_record(self, record: CMDBSyncRecord) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO cmdb_sync_records
                   (id, asset_id, external_id, cmdb_system, synced_at, sync_status, changes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.id, record.asset_id, record.external_id,
                    record.cmdb_system, record.synced_at,
                    record.sync_status, json.dumps(record.changes),
                ),
            )
            self._conn.commit()

    def get_sync_history(self, asset_id: str) -> List[CMDBSyncRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM cmdb_sync_records WHERE asset_id = ? ORDER BY synced_at DESC",
                (asset_id,),
            ).fetchall()
        return [self._row_to_sync(r) for r in rows]

    # ---- Row converters ----

    @staticmethod
    def _row_to_asset(row: tuple) -> ManagedAsset:
        (
            id_, name, asset_type, hostname, ip_address,
            owner_email, team, criticality, environment,
            lifecycle, tags_json, metadata_json,
            first_discovered, last_seen, finding_count, risk_score, org_id,
        ) = row
        return ManagedAsset(
            id=id_,
            name=name,
            asset_type=asset_type,
            hostname=hostname,
            ip_address=ip_address,
            owner_email=owner_email,
            team=team,
            criticality=AssetCriticality(criticality),
            environment=Environment(environment),
            lifecycle=AssetLifecycle(lifecycle),
            tags=json.loads(tags_json),
            metadata=json.loads(metadata_json),
            first_discovered=first_discovered,
            last_seen=last_seen,
            finding_count=finding_count,
            risk_score=risk_score,
            org_id=org_id,
        )

    @staticmethod
    def _row_to_sync(row: tuple) -> CMDBSyncRecord:
        id_, asset_id, external_id, cmdb_system, synced_at, sync_status, changes_json = row
        return CMDBSyncRecord(
            id=id_,
            asset_id=asset_id,
            external_id=external_id,
            cmdb_system=cmdb_system,
            synced_at=synced_at,
            sync_status=sync_status,
            changes=json.loads(changes_json),
        )


# ---------------------------------------------------------------------------
# AssetInventory — public interface
# ---------------------------------------------------------------------------

class AssetInventory:
    """Centralized asset inventory with lifecycle, ownership, tagging, and CMDB sync."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _InventoryDB(db_path)
        logger.info("AssetInventory initialised", db_path=db_path)

    # ---- CRUD ----

    def register_asset(self, asset: ManagedAsset) -> ManagedAsset:
        """Create or update an asset in the inventory."""
        self._db.upsert_asset(asset)
        logger.info("Asset registered", asset_id=asset.id, name=asset.name, org_id=asset.org_id)
        return asset

    def get_asset(self, asset_id: str) -> Optional[ManagedAsset]:
        """Retrieve a single asset by ID."""
        return self._db.get_asset(asset_id)

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        criticality: Optional[str] = None,
        environment: Optional[str] = None,
        lifecycle: Optional[str] = None,
        owner_email: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[ManagedAsset]:
        """List assets for an org with optional filters."""
        return self._db.list_assets(
            org_id,
            asset_type=asset_type,
            criticality=criticality,
            environment=environment,
            lifecycle=lifecycle,
            owner_email=owner_email,
            tag=tag,
        )

    def update_asset(self, asset_id: str, updates: Dict[str, Any]) -> Optional[ManagedAsset]:
        """Apply a partial update dict to an existing asset."""
        asset = self._db.get_asset(asset_id)
        if not asset:
            return None
        data = asset.model_dump()
        for key, val in updates.items():
            if key in data:
                data[key] = val
        data["last_seen"] = datetime.now(timezone.utc).isoformat()
        updated = ManagedAsset(**data)
        self._db.upsert_asset(updated)
        logger.info("Asset updated", asset_id=asset_id, fields=list(updates.keys()))
        return updated

    def delete_asset(self, asset_id: str) -> bool:
        """Remove an asset from the inventory. Returns True if deleted."""
        deleted = self._db.delete_asset(asset_id)
        if deleted:
            logger.info("Asset deleted", asset_id=asset_id)
        return deleted

    # ---- Discovery ----

    def discover_from_findings(
        self, findings: List[Dict[str, Any]], org_id: str
    ) -> List[ManagedAsset]:
        """Auto-extract and register assets from scan findings.

        Looks for hostname, ip_address, asset_type, url, host, target fields.
        """
        seen_keys: set = set()
        assets: List[ManagedAsset] = []

        for finding in findings:
            hostname = finding.get("hostname") or finding.get("host") or finding.get("target")
            ip_address = finding.get("ip_address") or finding.get("ip")
            asset_type = finding.get("asset_type") or finding.get("type", "unknown")
            name = (
                finding.get("name")
                or finding.get("url")
                or hostname
                or ip_address
                or f"discovered-{uuid.uuid4().hex[:8]}"
            )

            dedup_key = f"{name}:{hostname}:{ip_address}:{org_id}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # Check if an asset with this name+org already exists
            existing = self._db.list_assets(org_id, asset_type=None)
            matched = next((a for a in existing if a.name == name), None)

            if matched:
                # Update finding_count and last_seen
                matched.finding_count += 1
                matched.last_seen = datetime.now(timezone.utc).isoformat()
                self._db.upsert_asset(matched)
                assets.append(matched)
            else:
                asset = ManagedAsset(
                    name=name,
                    asset_type=str(asset_type),
                    hostname=hostname,
                    ip_address=ip_address,
                    org_id=org_id,
                    finding_count=1,
                    lifecycle=AssetLifecycle.DISCOVERED,
                    metadata={k: v for k, v in finding.items() if k not in {
                        "hostname", "host", "target", "ip_address", "ip",
                        "asset_type", "type", "name", "url",
                    }},
                )
                self._db.upsert_asset(asset)
                assets.append(asset)
                logger.info("Asset discovered", asset_id=asset.id, name=name, org_id=org_id)

        return assets

    # ---- Lifecycle ----

    def transition_lifecycle(
        self, asset_id: str, new_state: AssetLifecycle
    ) -> Optional[ManagedAsset]:
        """Transition an asset to a new lifecycle state (validated state machine)."""
        asset = self._db.get_asset(asset_id)
        if not asset:
            raise ValueError(f"Asset '{asset_id}' not found")
        allowed = _LIFECYCLE_TRANSITIONS.get(asset.lifecycle, set())
        if new_state not in allowed:
            raise ValueError(
                f"Invalid lifecycle transition: {asset.lifecycle.value} -> {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        asset.lifecycle = new_state
        asset.last_seen = datetime.now(timezone.utc).isoformat()
        self._db.upsert_asset(asset)
        logger.info("Lifecycle transition", asset_id=asset_id, new_state=new_state.value)
        return asset

    # ---- Ownership ----

    def assign_owner(
        self, asset_id: str, owner_email: str, team: Optional[str] = None
    ) -> Optional[ManagedAsset]:
        """Assign an owner (and optionally a team) to an asset."""
        updates: Dict[str, Any] = {"owner_email": owner_email}
        if team is not None:
            updates["team"] = team
        return self.update_asset(asset_id, updates)

    # ---- Tags ----

    def tag_asset(self, asset_id: str, tags: List[str]) -> Optional[ManagedAsset]:
        """Add tags to an asset (deduplicating)."""
        asset = self._db.get_asset(asset_id)
        if not asset:
            return None
        merged = list(dict.fromkeys(asset.tags + tags))
        return self.update_asset(asset_id, {"tags": merged})

    # ---- Search ----

    def search_assets(self, query: str, org_id: str) -> List[ManagedAsset]:
        """Full-text search across name, type, hostname, ip, owner, team, tags, metadata."""
        return self._db.search_assets(query, org_id)

    # ---- Unowned / Stale ----

    def get_unowned_assets(self, org_id: str) -> List[ManagedAsset]:
        """Return assets with no assigned owner."""
        return self._db.get_unowned_assets(org_id)

    def get_stale_assets(self, org_id: str, days: int = 30) -> List[ManagedAsset]:
        """Return assets not seen in the last N days."""
        return self._db.get_stale_assets(org_id, days)

    # ---- CMDB Sync ----

    def sync_to_cmdb(
        self,
        asset_id: str,
        cmdb_system: str,
        external_id: str,
        changes: Optional[Dict[str, Any]] = None,
    ) -> CMDBSyncRecord:
        """Record a CMDB sync event for an asset."""
        asset = self._db.get_asset(asset_id)
        status = "success" if asset else "failed"
        record = CMDBSyncRecord(
            asset_id=asset_id,
            external_id=external_id,
            cmdb_system=cmdb_system,
            sync_status=status,
            changes=changes or {},
        )
        self._db.insert_sync_record(record)
        logger.info(
            "CMDB sync recorded",
            asset_id=asset_id,
            cmdb_system=cmdb_system,
            status=status,
        )
        return record

    def get_sync_history(self, asset_id: str) -> List[CMDBSyncRecord]:
        """Return all CMDB sync records for an asset (newest first)."""
        return self._db.get_sync_history(asset_id)

    # ---- Stats ----

    def get_inventory_stats(self, org_id: str) -> Dict[str, Any]:
        """Return counts by type, criticality, lifecycle, and environment."""
        return self._db.get_stats(org_id)

    # ---- Bulk import ----

    def bulk_import(self, assets: List[Dict[str, Any]], org_id: str) -> int:
        """Import assets from a list of dicts (e.g. parsed from CSV/JSON).

        Returns the count of successfully imported assets.
        """
        count = 0
        for raw in assets:
            try:
                raw["org_id"] = org_id
                # Coerce enum fields if they are plain strings
                if "criticality" in raw and isinstance(raw["criticality"], str):
                    raw["criticality"] = AssetCriticality(raw["criticality"])
                if "environment" in raw and isinstance(raw["environment"], str):
                    raw["environment"] = Environment(raw["environment"])
                if "lifecycle" in raw and isinstance(raw["lifecycle"], str):
                    raw["lifecycle"] = AssetLifecycle(raw["lifecycle"])
                asset = ManagedAsset(**raw)
                self._db.upsert_asset(asset)
                count += 1
            except Exception as exc:
                logger.warning("bulk_import: skipping invalid asset", error=str(exc), raw=raw)
        logger.info("Bulk import complete", org_id=org_id, count=count)
        return count


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_inventory_instance: Optional[AssetInventory] = None
_inventory_lock = threading.Lock()


def get_asset_inventory(db_path: str = _DEFAULT_DB) -> AssetInventory:
    """Return the process-wide singleton AssetInventory."""
    global _inventory_instance
    if _inventory_instance is None:
        with _inventory_lock:
            if _inventory_instance is None:
                _inventory_instance = AssetInventory(db_path)
    return _inventory_instance
