"""Asset Inventory and CMDB Engine — Unified Configuration Management Database.

Provides auto-discovery, lifecycle tracking, ownership & accountability,
relationship mapping, compliance tagging, full-text search, and CMDB sync
for all managed assets across orgs.

Asset types supported: servers, containers, cloud resources, applications,
databases, APIs, repositories, network devices, users, certificates.

Usage:
    from core.asset_inventory import AssetInventory, get_asset_inventory
    inventory = get_asset_inventory()
    asset = inventory.register_asset(managed_asset)
    stats = inventory.get_inventory_stats("org-1")
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    Hub-level emit so this engine module participates in second-brain coverage.
    Downstream callers are AQUA via blast-radius (depth ≤ 2).
    """
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


# Module-load heartbeat — fires once per process so this file is observable
# in the TrustGraph second-brain, even if no public method is called yet.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

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


class CriticalityTier(str, Enum):
    """Business criticality tier — T1 (most critical) to T4 (least critical)."""
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"


class AssetLifecycle(str, Enum):
    PROVISIONED = "provisioned"
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


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


class ComplianceFramework(str, Enum):
    PCI = "pci"          # PCI-DSS — cardholder data environment
    HIPAA = "hipaa"      # HIPAA — protected health information
    SOX = "sox"          # SOX — financial systems
    ITAR = "itar"        # ITAR — defense / export-controlled
    GDPR = "gdpr"        # GDPR — personal data (EU)
    NIST = "nist"        # NIST CSF
    ISO27001 = "iso27001"


class RelationshipType(str, Enum):
    DEPENDS_ON = "depends_on"           # app depends_on database
    RUNS_ON = "runs_on"                 # service runs_on container
    DEPLOYED_IN = "deployed_in"         # container deployed_in cluster
    EXPOSED_BY = "exposed_by"           # api exposed_by load_balancer
    OWNED_BY = "owned_by"               # resource owned_by team/account
    CONNECTS_TO = "connects_to"         # network connectivity
    BACKS_UP_TO = "backs_up_to"         # backup target
    REPLICATES_TO = "replicates_to"     # replication target
    HOSTED_ON = "hosted_on"             # hosted on cloud provider
    MANAGED_BY = "managed_by"           # managed by orchestrator


# ---------------------------------------------------------------------------
# Compliance auto-scope rules
# data_classification -> implied compliance frameworks
# ---------------------------------------------------------------------------

_CLASSIFICATION_TO_COMPLIANCE: Dict[DataClassification, List[ComplianceFramework]] = {
    DataClassification.RESTRICTED: [ComplianceFramework.PCI, ComplianceFramework.HIPAA, ComplianceFramework.ITAR],
    DataClassification.SECRET: [ComplianceFramework.ITAR, ComplianceFramework.SOX],
    DataClassification.CONFIDENTIAL: [ComplianceFramework.SOX, ComplianceFramework.GDPR],
    DataClassification.INTERNAL: [ComplianceFramework.GDPR],
    DataClassification.PUBLIC: [],
}

# Valid lifecycle transitions: from -> set of allowed destinations
_LIFECYCLE_TRANSITIONS: Dict[AssetLifecycle, set] = {
    AssetLifecycle.PROVISIONED: {AssetLifecycle.ACTIVE, AssetLifecycle.DISCOVERED, AssetLifecycle.DECOMMISSIONED},
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
    """Universal asset model — tracks any asset type with full accountability."""

    id: str = Field(default_factory=lambda: f"masset-{uuid.uuid4().hex[:12]}")
    name: str
    asset_type: str  # server, container, cloud_resource, application, database,
                     # api, repository, network_device, user, certificate, etc.

    # Network identity
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    cloud_provider: Optional[str] = None   # aws, gcp, azure, on-prem
    region: Optional[str] = None
    cloud_resource_id: Optional[str] = None  # ARN, resource ID, etc.

    # Ownership & Accountability
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    team: Optional[str] = None
    business_unit: Optional[str] = None
    cost_center: Optional[str] = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    criticality_tier: CriticalityTier = CriticalityTier.T3

    # Data governance
    data_classification: DataClassification = DataClassification.INTERNAL
    compliance_scope: List[str] = Field(default_factory=list)  # ComplianceFramework values

    # Deployment context
    environment: Environment = Environment.PRODUCTION
    lifecycle: AssetLifecycle = AssetLifecycle.DISCOVERED

    # Discovery source
    discovery_source: Optional[str] = None  # cloud_discovery, k8s_scan, container_scan,
                                             # network_scan, manual, bulk_import

    # Labels / metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Tracking
    first_discovered: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finding_count: int = 0
    risk_score: float = 0.0

    org_id: str = "default"


class AssetRelationship(BaseModel):
    """Directed relationship between two assets."""

    id: str = Field(default_factory=lambda: f"rel-{uuid.uuid4().hex[:12]}")
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
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
    """SQLite persistence for managed assets, relationships, and CMDB sync records."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        dir_part = os.path.dirname(db_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        # FEATURE-5: route through DBAdapter so DATABASE_URL switches to postgres.
        # persistent_connect() returns a sqlite3.Connection with WAL/synchronous PRAGMAs
        # in sqlite mode, or a psycopg2.connection in postgres mode.
        from core.db_adapter import get_adapter
        self._db = get_adapter(db_path)
        self._conn = self._db.persistent_connect()
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
                    cloud_provider TEXT,
                    region TEXT,
                    cloud_resource_id TEXT,
                    owner_email TEXT,
                    owner_name TEXT,
                    team TEXT,
                    business_unit TEXT,
                    cost_center TEXT,
                    criticality TEXT NOT NULL DEFAULT 'medium',
                    criticality_tier TEXT NOT NULL DEFAULT 'T3',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    compliance_scope TEXT NOT NULL DEFAULT '[]',
                    environment TEXT NOT NULL DEFAULT 'production',
                    lifecycle TEXT NOT NULL DEFAULT 'discovered',
                    discovery_source TEXT,
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

                CREATE TABLE IF NOT EXISTS asset_relationships (
                    id TEXT PRIMARY KEY,
                    source_asset_id TEXT NOT NULL,
                    target_asset_id TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    UNIQUE(source_asset_id, target_asset_id, relationship_type)
                );
                CREATE INDEX IF NOT EXISTS idx_rel_source ON asset_relationships(source_asset_id);
                CREATE INDEX IF NOT EXISTS idx_rel_target ON asset_relationships(target_asset_id);
                CREATE INDEX IF NOT EXISTS idx_rel_type ON asset_relationships(relationship_type);
                CREATE INDEX IF NOT EXISTS idx_rel_org ON asset_relationships(org_id);

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
            # Schema migration: add columns introduced after initial schema
            _migrations = [
                ("cloud_provider", "TEXT"),
                ("region", "TEXT"),
                ("cloud_resource_id", "TEXT"),
                ("owner_name", "TEXT"),
                ("business_unit", "TEXT"),
                ("cost_center", "TEXT"),
                ("criticality_tier", "TEXT NOT NULL DEFAULT 'T3'"),
                ("data_classification", "TEXT NOT NULL DEFAULT 'internal'"),
                ("compliance_scope", "TEXT NOT NULL DEFAULT '[]'"),
                ("discovery_source", "TEXT"),
            ]
            existing = {row[1] for row in self._conn.execute("PRAGMA table_info(managed_assets)")}
            for col, col_def in _migrations:
                if col not in existing:
                    self._conn.execute(f"ALTER TABLE managed_assets ADD COLUMN {col} {col_def}")
            # Indexes on migrated columns (safe to run after columns exist)
            self._conn.executescript("""
                CREATE INDEX IF NOT EXISTS idx_masset_tier ON managed_assets(criticality_tier);
                CREATE INDEX IF NOT EXISTS idx_masset_cloud ON managed_assets(cloud_provider);
                CREATE INDEX IF NOT EXISTS idx_masset_bu ON managed_assets(business_unit);
                CREATE INDEX IF NOT EXISTS idx_masset_classification ON managed_assets(data_classification);
            """)
            self._conn.commit()

    # ---- Asset persistence ----

    def upsert_asset(self, asset: ManagedAsset) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO managed_assets
                   (id, name, asset_type, hostname, ip_address, cloud_provider, region,
                    cloud_resource_id, owner_email, owner_name, team, business_unit,
                    cost_center, criticality, criticality_tier, data_classification,
                    compliance_scope, environment, lifecycle, discovery_source,
                    tags, metadata, first_discovered, last_seen,
                    finding_count, risk_score, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asset.id, asset.name, asset.asset_type,
                    asset.hostname, asset.ip_address,
                    asset.cloud_provider, asset.region, asset.cloud_resource_id,
                    asset.owner_email, asset.owner_name, asset.team,
                    asset.business_unit, asset.cost_center,
                    asset.criticality.value, asset.criticality_tier.value,
                    asset.data_classification.value,
                    json.dumps(asset.compliance_scope),
                    asset.environment.value, asset.lifecycle.value,
                    asset.discovery_source,
                    json.dumps(asset.tags), json.dumps(asset.metadata),
                    asset.first_discovered, asset.last_seen,
                    asset.finding_count, asset.risk_score, asset.org_id,
                ),
            )
            self._conn.commit()

    def upsert_assets_batch(self, assets: List[ManagedAsset]) -> None:
        """PERF-FIX-2: Insert/replace multiple assets in a single transaction.

        Replaces N individual upsert_asset() calls (each with its own commit)
        with one executemany + one commit — eliminates per-record fsync overhead.
        """
        rows = [
            (
                a.id, a.name, a.asset_type,
                a.hostname, a.ip_address,
                a.cloud_provider, a.region, a.cloud_resource_id,
                a.owner_email, a.owner_name, a.team,
                a.business_unit, a.cost_center,
                a.criticality.value, a.criticality_tier.value,
                a.data_classification.value,
                json.dumps(a.compliance_scope),
                a.environment.value, a.lifecycle.value,
                a.discovery_source,
                json.dumps(a.tags), json.dumps(a.metadata),
                a.first_discovered, a.last_seen,
                a.finding_count, a.risk_score, a.org_id,
            )
            for a in assets
        ]
        with self._lock:
            self._conn.executemany(
                """INSERT OR REPLACE INTO managed_assets
                   (id, name, asset_type, hostname, ip_address, cloud_provider, region,
                    cloud_resource_id, owner_email, owner_name, team, business_unit,
                    cost_center, criticality, criticality_tier, data_classification,
                    compliance_scope, environment, lifecycle, discovery_source,
                    tags, metadata, first_discovered, last_seen,
                    finding_count, risk_score, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
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
        criticality_tier: Optional[str] = None,
        environment: Optional[str] = None,
        lifecycle: Optional[str] = None,
        owner_email: Optional[str] = None,
        tag: Optional[str] = None,
        business_unit: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        region: Optional[str] = None,
        data_classification: Optional[str] = None,
        compliance_scope: Optional[str] = None,
    ) -> List[ManagedAsset]:
        query = "SELECT * FROM managed_assets WHERE org_id = ?"
        params: List[Any] = [org_id]
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if criticality:
            query += " AND criticality = ?"
            params.append(criticality)
        if criticality_tier:
            query += " AND criticality_tier = ?"
            params.append(criticality_tier)
        if environment:
            query += " AND environment = ?"
            params.append(environment)
        if lifecycle:
            query += " AND lifecycle = ?"
            params.append(lifecycle)
        if owner_email:
            query += " AND owner_email = ?"
            params.append(owner_email)
        if business_unit:
            query += " AND business_unit = ?"
            params.append(business_unit)
        if cloud_provider:
            query += " AND cloud_provider = ?"
            params.append(cloud_provider)
        if region:
            query += " AND region = ?"
            params.append(region)
        if data_classification:
            query += " AND data_classification = ?"
            params.append(data_classification)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        assets = [self._row_to_asset(r) for r in rows]
        if tag:
            assets = [a for a in assets if tag in a.tags]
        if compliance_scope:
            assets = [a for a in assets if compliance_scope in a.compliance_scope]
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
                       lower(coalesce(owner_name,'')) LIKE ? OR
                       lower(coalesce(team,'')) LIKE ? OR
                       lower(coalesce(business_unit,'')) LIKE ? OR
                       lower(coalesce(cost_center,'')) LIKE ? OR
                       lower(coalesce(cloud_provider,'')) LIKE ? OR
                       lower(coalesce(region,'')) LIKE ? OR
                       lower(tags) LIKE ? OR
                       lower(metadata) LIKE ? OR
                       lower(compliance_scope) LIKE ?
                   )""",
                (org_id, q, q, q, q, q, q, q, q, q, q, q, q, q, q),
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
        # PERF-FIX-3: single lock acquisition; all GROUP BY aggregates run in
        # one DB round-trip instead of 8 separate queries.  avg_risk_score and
        # critical_exposed are also computed here via SQL so get_asset_stats()
        # no longer needs a second full list_assets() scan.
        with self._lock:
            total = self._conn.execute(
                "SELECT COUNT(*) FROM managed_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_type = dict(self._conn.execute(
                "SELECT asset_type, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY asset_type",
                (org_id,),
            ).fetchall())
            by_criticality = dict(self._conn.execute(
                "SELECT criticality, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY criticality",
                (org_id,),
            ).fetchall())
            by_tier = dict(self._conn.execute(
                "SELECT criticality_tier, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY criticality_tier",
                (org_id,),
            ).fetchall())
            by_lifecycle = dict(self._conn.execute(
                "SELECT lifecycle, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY lifecycle",
                (org_id,),
            ).fetchall())
            by_environment = dict(self._conn.execute(
                "SELECT environment, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY environment",
                (org_id,),
            ).fetchall())
            by_cloud = dict(self._conn.execute(
                "SELECT cloud_provider, COUNT(*) FROM managed_assets WHERE org_id = ? AND cloud_provider IS NOT NULL GROUP BY cloud_provider",
                (org_id,),
            ).fetchall())
            by_classification = dict(self._conn.execute(
                "SELECT data_classification, COUNT(*) FROM managed_assets WHERE org_id = ? GROUP BY data_classification",
                (org_id,),
            ).fetchall())
            unowned = self._conn.execute(
                "SELECT COUNT(*) FROM managed_assets WHERE org_id = ? AND (owner_email IS NULL OR owner_email = '')",
                (org_id,),
            ).fetchone()[0]
            # Aggregate risk stats in SQL — avoids a second list_assets() full scan in get_asset_stats()
            risk_row = self._conn.execute(
                "SELECT AVG(CASE WHEN risk_score > 0 THEN risk_score END), "
                "COUNT(CASE WHEN criticality IN ('critical','high') AND json_extract(metadata,'$.internet_facing') THEN 1 END) "
                "FROM managed_assets WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_risk_score = round(risk_row[0] or 0.0, 2)
            critical_exposed = risk_row[1] or 0

        return {
            "total": total,
            "by_type": by_type,
            "by_criticality": by_criticality,
            "by_criticality_tier": by_tier,
            "by_lifecycle": by_lifecycle,
            "by_environment": by_environment,
            "by_cloud_provider": by_cloud,
            "by_data_classification": by_classification,
            "unowned_count": unowned,
            # Pre-computed aggregates consumed by get_asset_stats() — no second scan needed
            "_avg_risk_score": avg_risk_score,
            "_critical_exposed": critical_exposed,
        }

    # ---- Relationship persistence ----

    def upsert_relationship(self, rel: AssetRelationship) -> AssetRelationship:
        """Insert or replace a relationship (unique on source+target+type)."""
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO asset_relationships
                   (id, source_asset_id, target_asset_id, relationship_type, metadata, created_at, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    rel.id, rel.source_asset_id, rel.target_asset_id,
                    rel.relationship_type.value,
                    json.dumps(rel.metadata), rel.created_at, rel.org_id,
                ),
            )
            self._conn.commit()
        return rel

    def get_relationships(
        self,
        asset_id: str,
        direction: str = "both",  # "outbound", "inbound", "both"
        relationship_type: Optional[str] = None,
    ) -> List[AssetRelationship]:
        conditions: List[str] = []
        params: List[Any] = []
        if direction == "outbound":
            conditions.append("source_asset_id = ?")
            params.append(asset_id)
        elif direction == "inbound":
            conditions.append("target_asset_id = ?")
            params.append(asset_id)
        else:
            conditions.append("(source_asset_id = ? OR target_asset_id = ?)")
            params.extend([asset_id, asset_id])
        if relationship_type:
            conditions.append("relationship_type = ?")
            params.append(relationship_type)
        where = " AND ".join(conditions)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM asset_relationships WHERE {where}", params  # nosec B608
            ).fetchall()
        return [self._row_to_rel(r) for r in rows]

    def delete_relationship(self, rel_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM asset_relationships WHERE id = ?", (rel_id,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def get_impact_graph(self, asset_id: str, max_depth: int = 3) -> Dict[str, Any]:
        """BFS traversal of the dependency graph starting from asset_id.

        Returns a dict with nodes (asset IDs) and edges visited up to max_depth hops.
        """
        visited: Dict[str, int] = {}   # asset_id -> depth
        edges: List[Tuple[str, str, str]] = []
        queue: List[Tuple[str, int]] = [(asset_id, 0)]

        while queue:
            current_id, depth = queue.pop(0)
            if current_id in visited or depth > max_depth:
                continue
            visited[current_id] = depth
            with self._lock:
                rows = self._conn.execute(
                    "SELECT id, source_asset_id, target_asset_id, relationship_type "
                    "FROM asset_relationships WHERE source_asset_id = ? OR target_asset_id = ?",
                    (current_id, current_id),
                ).fetchall()
            for row in rows:
                rel_id, src, tgt, rel_type = row
                edges.append((src, tgt, rel_type))
                neighbor = tgt if src == current_id else src
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))

        return {
            "root": asset_id,
            "nodes": list(visited.keys()),
            "edges": [{"source": s, "target": t, "type": rt} for s, t, rt in edges],
            "depth": max_depth,
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
    def _row_to_asset(row) -> ManagedAsset:
        return ManagedAsset(
            id=row["id"],
            name=row["name"],
            asset_type=row["asset_type"],
            hostname=row["hostname"],
            ip_address=row["ip_address"],
            cloud_provider=row["cloud_provider"],
            region=row["region"],
            cloud_resource_id=row["cloud_resource_id"],
            owner_email=row["owner_email"],
            owner_name=row["owner_name"],
            team=row["team"],
            business_unit=row["business_unit"],
            cost_center=row["cost_center"],
            criticality=AssetCriticality(row["criticality"]),
            criticality_tier=CriticalityTier(row["criticality_tier"] or "T3"),
            data_classification=DataClassification(row["data_classification"] or "internal"),
            compliance_scope=json.loads(row["compliance_scope"] or "[]"),
            environment=Environment(row["environment"]),
            lifecycle=AssetLifecycle(row["lifecycle"]),
            discovery_source=row["discovery_source"],
            tags=json.loads(row["tags"] or "[]"),
            metadata=json.loads(row["metadata"] or "{}"),
            first_discovered=row["first_discovered"],
            last_seen=row["last_seen"],
            finding_count=row["finding_count"],
            risk_score=row["risk_score"],
            org_id=row["org_id"],
        )

    @staticmethod
    def _row_to_rel(row: tuple) -> AssetRelationship:
        id_, source_asset_id, target_asset_id, relationship_type, metadata_json, created_at, org_id = row
        return AssetRelationship(
            id=id_,
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            relationship_type=RelationshipType(relationship_type),
            metadata=json.loads(metadata_json),
            created_at=created_at,
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
    """Centralized asset inventory with lifecycle, ownership, tagging, relationships,
    compliance tagging, and CMDB sync."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _InventoryDB(db_path)
        logger.info("AssetInventory initialised", db_path=db_path)

    # ---- CRUD ----

    def register_asset(self, asset: ManagedAsset) -> ManagedAsset:
        """Create or update an asset in the inventory.

        Auto-applies compliance scope based on data_classification if
        compliance_scope is not explicitly set.
        """
        if not asset.compliance_scope:
            asset = asset.model_copy(update={
                "compliance_scope": [
                    f.value for f in _CLASSIFICATION_TO_COMPLIANCE.get(
                        asset.data_classification, []
                    )
                ]
            })
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
        criticality_tier: Optional[str] = None,
        environment: Optional[str] = None,
        lifecycle: Optional[str] = None,
        owner_email: Optional[str] = None,
        tag: Optional[str] = None,
        business_unit: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        region: Optional[str] = None,
        data_classification: Optional[str] = None,
        compliance_scope: Optional[str] = None,
    ) -> List[ManagedAsset]:
        """List assets for an org with optional filters."""
        return self._db.list_assets(
            org_id,
            asset_type=asset_type,
            criticality=criticality,
            criticality_tier=criticality_tier,
            environment=environment,
            lifecycle=lifecycle,
            owner_email=owner_email,
            tag=tag,
            business_unit=business_unit,
            cloud_provider=cloud_provider,
            region=region,
            data_classification=data_classification,
            compliance_scope=compliance_scope,
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
        # Re-apply compliance auto-scope if classification changed and scope not explicitly provided
        if "data_classification" in updates and "compliance_scope" not in updates:
            new_scope = [
                f.value for f in _CLASSIFICATION_TO_COMPLIANCE.get(
                    updated.data_classification, []
                )
            ]
            if new_scope:
                updated = updated.model_copy(update={"compliance_scope": new_scope})
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
        self,
        findings: List[Dict[str, Any]],
        org_id: str,
        discovery_source: str = "scanner",
    ) -> List[ManagedAsset]:
        """Auto-extract and register assets from scan findings.

        Supported sources: cloud_discovery, k8s_scan, container_scan,
        network_scan, api_scan, manual, scanner (default).

        De-duplicates by name within the org. Increments finding_count on
        assets already in the inventory.
        """
        seen_keys: set = set()
        assets: List[ManagedAsset] = []

        # PERF-FIX-1: hoist list_assets() outside the loop and build a name→asset
        # dict once.  Previous code called list_assets() + linear scan inside every
        # iteration → O(N·M) DB fetches.  Now O(M) one-time fetch + O(1) lookup.
        existing_by_name: Dict[str, ManagedAsset] = {
            a.name: a for a in self._db.list_assets(org_id)
        }

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

            matched = existing_by_name.get(name)

            if matched:
                matched.finding_count += 1
                matched.last_seen = datetime.now(timezone.utc).isoformat()
                self._db.upsert_asset(matched)
                assets.append(matched)
            else:
                # Extract cloud / k8s fields from finding payload
                cloud_provider = finding.get("cloud_provider") or finding.get("provider")
                region = finding.get("region") or finding.get("availability_zone")
                cloud_resource_id = finding.get("cloud_resource_id") or finding.get("resource_id") or finding.get("arn")

                excluded = {
                    "hostname", "host", "target", "ip_address", "ip",
                    "asset_type", "type", "name", "url",
                    "cloud_provider", "provider", "region", "availability_zone",
                    "cloud_resource_id", "resource_id", "arn",
                }
                asset = ManagedAsset(
                    name=name,
                    asset_type=str(asset_type),
                    hostname=hostname,
                    ip_address=ip_address,
                    cloud_provider=cloud_provider,
                    region=region,
                    cloud_resource_id=cloud_resource_id,
                    org_id=org_id,
                    finding_count=1,
                    lifecycle=AssetLifecycle.DISCOVERED,
                    discovery_source=discovery_source,
                    metadata={k: v for k, v in finding.items() if k not in excluded},
                )
                self._db.upsert_asset(asset)
                assets.append(asset)
                # Keep in-batch cache current so later findings in this call
                # match against newly registered assets without another DB hit.
                existing_by_name[name] = asset
                logger.info("Asset discovered", asset_id=asset.id, name=name,
                            org_id=org_id, source=discovery_source)

        return assets

    # ---- Lifecycle ----

    def transition_lifecycle(
        self, asset_id: str, new_state: AssetLifecycle
    ) -> Optional[ManagedAsset]:
        """Transition an asset to a new lifecycle state (validated state machine).

        Valid paths:
          provisioned -> active | discovered | decommissioned
          discovered  -> active | deprecated | decommissioned
          active      -> maintenance | deprecated | decommissioned
          maintenance -> active | deprecated | decommissioned
          deprecated  -> decommissioned | active
          decommissioned -> (terminal)
        """
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
        self,
        asset_id: str,
        owner_email: str,
        owner_name: Optional[str] = None,
        team: Optional[str] = None,
        business_unit: Optional[str] = None,
        cost_center: Optional[str] = None,
    ) -> Optional[ManagedAsset]:
        """Assign an owner (and optionally team/BU/cost center) to an asset."""
        updates: Dict[str, Any] = {"owner_email": owner_email}
        if owner_name is not None:
            updates["owner_name"] = owner_name
        if team is not None:
            updates["team"] = team
        if business_unit is not None:
            updates["business_unit"] = business_unit
        if cost_center is not None:
            updates["cost_center"] = cost_center
        return self.update_asset(asset_id, updates)

    # ---- Tags ----

    def tag_asset(self, asset_id: str, tags: List[str]) -> Optional[ManagedAsset]:
        """Add tags to an asset (deduplicating)."""
        asset = self._db.get_asset(asset_id)
        if not asset:
            return None
        merged = list(dict.fromkeys(asset.tags + tags))
        return self.update_asset(asset_id, {"tags": merged})

    # ---- Compliance tagging ----

    def apply_compliance_scope(
        self, asset_id: str, frameworks: List[str]
    ) -> Optional[ManagedAsset]:
        """Explicitly set compliance frameworks on an asset (additive merge).

        Validates each framework value against ComplianceFramework enum.
        """
        asset = self._db.get_asset(asset_id)
        if not asset:
            return None
        # Validate each framework string
        valid = {f.value for f in ComplianceFramework}
        for fw in frameworks:
            if fw not in valid:
                raise ValueError(
                    f"Unknown compliance framework: '{fw}'. "
                    f"Valid: {sorted(valid)}"
                )
        merged = list(dict.fromkeys(asset.compliance_scope + frameworks))
        return self.update_asset(asset_id, {"compliance_scope": merged})

    def get_assets_in_compliance_scope(
        self, org_id: str, framework: str
    ) -> List[ManagedAsset]:
        """Return all assets tagged with a specific compliance framework."""
        return self._db.list_assets(org_id, compliance_scope=framework)

    # ---- Relationships ----

    def add_relationship(
        self,
        source_asset_id: str,
        target_asset_id: str,
        relationship_type: RelationshipType,
        org_id: str = "default",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AssetRelationship:
        """Create a directed relationship between two assets.

        Idempotent — upserting the same (source, target, type) triple
        replaces the existing record.
        """
        rel = AssetRelationship(
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            relationship_type=relationship_type,
            org_id=org_id,
            metadata=metadata or {},
        )
        self._db.upsert_relationship(rel)
        logger.info(
            "Relationship added",
            source=source_asset_id,
            target=target_asset_id,
            type=relationship_type.value,
        )
        return rel

    def get_relationships(
        self,
        asset_id: str,
        direction: str = "both",
        relationship_type: Optional[RelationshipType] = None,
    ) -> List[AssetRelationship]:
        """Return relationships for an asset.

        direction: "outbound" | "inbound" | "both" (default)
        """
        rt = relationship_type.value if relationship_type else None
        return self._db.get_relationships(asset_id, direction=direction, relationship_type=rt)

    def delete_relationship(self, rel_id: str) -> bool:
        """Remove a relationship by ID."""
        return self._db.delete_relationship(rel_id)

    def get_impact_graph(self, asset_id: str, max_depth: int = 3) -> Dict[str, Any]:
        """Return the blast-radius dependency graph starting from asset_id.

        Performs BFS up to max_depth hops across all relationship types,
        returning nodes (asset IDs) and edges (source, target, type).
        """
        return self._db.get_impact_graph(asset_id, max_depth=max_depth)

    # ---- Search ----

    def search_assets(self, query: str, org_id: str) -> List[ManagedAsset]:
        """Full-text search across name, type, hostname, ip, owner, team,
        business_unit, cost_center, cloud_provider, region, tags, metadata,
        compliance_scope."""
        return self._db.search_assets(query, org_id)

    # ---- Unowned / Stale ----

    def get_unowned_assets(self, org_id: str) -> List[ManagedAsset]:
        """Return assets with no assigned owner."""
        return self._db.get_unowned_assets(org_id)

    def get_stale_assets(self, org_id: str, days: int = 30) -> List[ManagedAsset]:
        """Return assets not seen in the last N days (staleness alert threshold)."""
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
        """Return counts by type, criticality, tier, lifecycle, environment,
        cloud provider, and data classification."""
        return self._db.get_stats(org_id)

    # ---- Aliases for spec compatibility ----

    def add_asset(self, org_id: str, asset: Dict[str, Any]) -> str:
        """Add an asset and return its asset_id.

        Wraps register_asset() accepting a plain dict. The dict may use
        simplified keys (name, type, ip_address, os, owner, criticality,
        environment, tags, metadata).  'type' is mapped to 'asset_type'.
        """
        raw = dict(asset)
        raw["org_id"] = org_id
        if "type" in raw and "asset_type" not in raw:
            raw["asset_type"] = raw.pop("type")
        if "owner" in raw and "owner_name" not in raw:
            raw["owner_name"] = raw.pop("owner")
        if "os" in raw:
            raw.setdefault("metadata", {})["os"] = raw.pop("os")
        # Coerce enums
        for field, enum_cls in (
            ("criticality", AssetCriticality),
            ("criticality_tier", CriticalityTier),
            ("environment", Environment),
            ("lifecycle", AssetLifecycle),
            ("data_classification", DataClassification),
        ):
            if field in raw and isinstance(raw[field], str):
                raw[field] = enum_cls(raw[field])
        managed = ManagedAsset(**raw)
        result = self.register_asset(managed)
        return result.id

    def get_asset_stats(self, org_id: str) -> Dict[str, Any]:
        """Return asset stats summary.

        Returns total, by_type, by_criticality, avg_risk_score, and
        critical_exposed count (critical/high assets with internet_facing=True
        in metadata).

        PERF-FIX-3: avg_risk_score and critical_exposed are now computed inside
        get_inventory_stats() via SQL aggregates.  The previous implementation
        called list_assets() here for a second full table scan — eliminated.
        """
        stats = self.get_inventory_stats(org_id)
        return {
            "total": stats.get("total", 0),
            "by_type": stats.get("by_type", {}),
            "by_criticality": stats.get("by_criticality", {}),
            "avg_risk_score": stats.get("_avg_risk_score", 0.0),
            "critical_exposed": stats.get("_critical_exposed", 0),
        }

    # ---- Risk scoring ----

    def calculate_risk_score(self, asset_id: str, org_id: str) -> Dict[str, Any]:
        """Compute a 0-10 risk score for an asset.

        Formula:
          base = criticality weight (critical=8, high=6, medium=4, low=2, info=1)
          exposure = +1.5 if internet_facing in metadata, else 0
          vuln_penalty = min(finding_count * 0.2, 2.0)
          patch_age = days since last_seen / 90 capped at 1.0 (proxy for patch lag)
          raw = base + exposure + vuln_penalty + patch_age * 0.5
          score = min(raw, 10.0), rounded to 1 dp

        Returns: {score, factors, risk_level}
        """
        asset = self._db.get_asset(asset_id)
        if not asset or asset.org_id != org_id:
            return {}

        _crit_weight = {
            AssetCriticality.CRITICAL: 8.0,
            AssetCriticality.HIGH: 6.0,
            AssetCriticality.MEDIUM: 4.0,
            AssetCriticality.LOW: 2.0,
            AssetCriticality.INFORMATIONAL: 1.0,
        }
        criticality_weight = _crit_weight.get(asset.criticality, 4.0)
        exposure = 1.5 if asset.metadata.get("internet_facing") else 0.0
        vuln_count = asset.finding_count
        vuln_penalty = min(vuln_count * 0.2, 2.0)

        try:
            last_seen_dt = datetime.fromisoformat(asset.last_seen.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            last_seen_dt = datetime.now(timezone.utc)
        days_stale = max((datetime.now(timezone.utc) - last_seen_dt).days, 0)
        patch_age = min(days_stale / 90.0, 1.0)

        raw = criticality_weight + exposure + vuln_penalty + patch_age * 0.5
        score = round(min(raw, 10.0), 1)

        if score >= 8.0:
            risk_level = "critical"
        elif score >= 6.0:
            risk_level = "high"
        elif score >= 4.0:
            risk_level = "medium"
        else:
            risk_level = "low"

        result = {
            "score": score,
            "factors": {
                "criticality_weight": criticality_weight,
                "exposure": exposure,
                "vuln_count": vuln_count,
                "patch_age": round(patch_age, 3),
            },
            "risk_level": risk_level,
        }
        # Persist the score back onto the asset
        self.update_asset(asset_id, {"risk_score": score})
        return result

    # ---- Exposure detection ----

    def find_exposed_assets(self, org_id: str) -> List[ManagedAsset]:
        """Return internet-facing assets with high or critical risk score.

        An asset is considered exposed when metadata["internet_facing"] is
        truthy. We recalculate risk scores on the fly and return assets whose
        score >= 6.0 (high/critical tier).
        """
        assets = self._db.list_assets(org_id)
        exposed = []
        for asset in assets:
            if not asset.metadata.get("internet_facing"):
                continue
            result = self.calculate_risk_score(asset.id, org_id)
            if result and result.get("score", 0) >= 6.0:
                # Re-fetch with updated risk_score
                updated = self._db.get_asset(asset.id)
                if updated:
                    exposed.append(updated)
        return exposed

    # ---- Timeline ----

    def get_asset_timeline(self, asset_id: str, org_id: str) -> List[Dict[str, Any]]:
        """Return a chronological history of changes and security events for an asset.

        Sources merged into the timeline:
        - CMDB sync records (type=cmdb_sync)
        - finding_count increments inferred from current finding_count (type=finding_update)
        - Lifecycle as recorded in metadata.__lifecycle_history (type=lifecycle_change)

        Returns list of {timestamp, event_type, description, detail} sorted ascending.
        """
        asset = self._db.get_asset(asset_id)
        if not asset or asset.org_id != org_id:
            return []

        timeline: List[Dict[str, Any]] = []

        # Discovery event
        timeline.append({
            "timestamp": asset.first_discovered,
            "event_type": "discovery",
            "description": f"Asset first discovered via {asset.discovery_source or 'unknown'}",
            "detail": {"discovery_source": asset.discovery_source},
        })

        # CMDB sync events
        sync_records = self._db.get_sync_history(asset_id)
        for rec in sync_records:
            timeline.append({
                "timestamp": rec.synced_at,
                "event_type": "cmdb_sync",
                "description": f"CMDB sync to {rec.cmdb_system} — {rec.sync_status}",
                "detail": {"cmdb_system": rec.cmdb_system, "external_id": rec.external_id,
                            "status": rec.sync_status, "changes": rec.changes},
            })

        # Lifecycle history stored in metadata
        for entry in asset.metadata.get("__lifecycle_history", []):
            timeline.append({
                "timestamp": entry.get("timestamp", asset.first_discovered),
                "event_type": "lifecycle_change",
                "description": f"Lifecycle changed to {entry.get('to', '?')}",
                "detail": entry,
            })

        # Current finding summary as a single event if any findings
        if asset.finding_count > 0:
            timeline.append({
                "timestamp": asset.last_seen,
                "event_type": "finding_update",
                "description": f"{asset.finding_count} security finding(s) associated",
                "detail": {"finding_count": asset.finding_count},
            })

        # Sort ascending by timestamp
        timeline.sort(key=lambda e: e.get("timestamp", ""))
        return timeline

    # ---- Bulk import ----

    def bulk_import(self, assets: List[Dict[str, Any]], org_id: str) -> int:
        """Import assets from a list of dicts (e.g. parsed from CSV/JSON).

        Coerces string enum values. Skips invalid records with a warning.
        Returns the count of successfully imported assets.

        PERF-FIX-2: builds all valid ManagedAsset objects first, applies
        compliance auto-scope, then writes them all in a single
        executemany + commit via upsert_assets_batch().  Previous code called
        register_asset() (and therefore commit()) once per record — O(N) fsyncs.
        """
        valid_assets: List[ManagedAsset] = []
        skipped = 0
        for raw in assets:
            try:
                raw = dict(raw)  # don't mutate caller's dict
                raw["org_id"] = org_id
                for field, enum_cls in (
                    ("criticality", AssetCriticality),
                    ("criticality_tier", CriticalityTier),
                    ("environment", Environment),
                    ("lifecycle", AssetLifecycle),
                    ("data_classification", DataClassification),
                ):
                    if field in raw and isinstance(raw[field], str):
                        raw[field] = enum_cls(raw[field])
                asset = ManagedAsset(**raw)
                # Apply compliance auto-scope (mirrors register_asset logic)
                if not asset.compliance_scope:
                    asset = asset.model_copy(update={
                        "compliance_scope": [
                            f.value for f in _CLASSIFICATION_TO_COMPLIANCE.get(
                                asset.data_classification, []
                            )
                        ]
                    })
                valid_assets.append(asset)
            except Exception as exc:
                skipped += 1
                logger.warning("bulk_import: skipping invalid asset", error=str(exc), raw=raw)

        if valid_assets:
            self._db.upsert_assets_batch(valid_assets)

        count = len(valid_assets)
        logger.info("Bulk import complete", org_id=org_id, count=count, skipped=skipped)
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
