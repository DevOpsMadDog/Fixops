"""Attack Surface Mapping — Asset Inventory, Exposure Paths, Risk Scoring.

Enumerates assets from pipeline findings, maps exposure paths between assets,
scores risk based on exposure level and vulnerability data, and produces a
full attack surface summary per org.

Usage:
    from core.attack_surface import AttackSurfaceMapper, get_attack_surface_mapper
    mapper = get_attack_surface_mapper()
    asset = mapper.register_asset(asset)
    surface = mapper.get_attack_surface(org_id)
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

_DEFAULT_DB = os.getenv("FIXOPS_ATTACK_SURFACE_DB", ".fixops_data/attack_surface.db")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AssetType(str, Enum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    API_ENDPOINT = "api_endpoint"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    REPOSITORY = "repository"
    SERVICE = "service"


class ExposureLevel(str, Enum):
    EXTERNAL = "external"
    DMZ = "dmz"
    INTERNAL = "internal"
    ISOLATED = "isolated"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    id: str = Field(default_factory=lambda: f"ast-{uuid.uuid4().hex[:12]}")
    name: str
    type: AssetType
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    attributes: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    org_id: str = "default"


class ExposurePath(BaseModel):
    id: str = Field(default_factory=lambda: f"path-{uuid.uuid4().hex[:12]}")
    source_asset_id: str
    target_asset_id: str
    hops: List[str] = Field(default_factory=list)
    protocol: str = "unknown"
    risk_score: float = 0.0
    description: str = ""


class AttackSurface(BaseModel):
    id: str = Field(default_factory=lambda: f"surf-{uuid.uuid4().hex[:12]}")
    org_id: str
    total_assets: int = 0
    external_assets: int = 0
    high_risk_paths: int = 0
    risk_score: float = 0.0
    last_scan: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    assets_by_type: Dict[str, int] = Field(default_factory=dict)
    assets_by_exposure: Dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------

class _AssetDB:
    """SQLite persistence for attack surface assets and paths."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    exposure_level TEXT NOT NULL,
                    attributes TEXT DEFAULT '{}',
                    tags TEXT DEFAULT '[]',
                    discovered_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);
                CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
                CREATE INDEX IF NOT EXISTS idx_assets_exposure ON assets(exposure_level);

                CREATE TABLE IF NOT EXISTS exposure_paths (
                    id TEXT PRIMARY KEY,
                    source_asset_id TEXT NOT NULL,
                    target_asset_id TEXT NOT NULL,
                    hops TEXT DEFAULT '[]',
                    protocol TEXT DEFAULT 'unknown',
                    risk_score REAL DEFAULT 0.0,
                    description TEXT DEFAULT '',
                    org_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_paths_org ON exposure_paths(org_id);
                CREATE INDEX IF NOT EXISTS idx_paths_source ON exposure_paths(source_asset_id);
                CREATE INDEX IF NOT EXISTS idx_paths_target ON exposure_paths(target_asset_id);
            """)
            self._conn.commit()

    def upsert_asset(self, asset: Asset) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO assets
                   (id, name, type, exposure_level, attributes, tags, discovered_at, last_seen, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asset.id, asset.name, asset.type.value,
                    asset.exposure_level.value,
                    json.dumps(asset.attributes),
                    json.dumps(asset.tags),
                    asset.discovered_at, asset.last_seen, asset.org_id,
                ),
            )
            self._conn.commit()

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, name, type, exposure_level, attributes, tags, discovered_at, last_seen, org_id "
                "FROM assets WHERE id = ?",
                (asset_id,),
            ).fetchone()
        return self._row_to_asset(row) if row else None

    def list_assets(
        self,
        org_id: str,
        type_filter: Optional[str] = None,
        exposure_filter: Optional[str] = None,
    ) -> List[Asset]:
        query = "SELECT id, name, type, exposure_level, attributes, tags, discovered_at, last_seen, org_id FROM assets WHERE org_id = ?"
        params: List[Any] = [org_id]
        if type_filter:
            query += " AND type = ?"
            params.append(type_filter)
        if exposure_filter:
            query += " AND exposure_level = ?"
            params.append(exposure_filter)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def delete_asset(self, asset_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def upsert_path(self, path: ExposurePath, org_id: str) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO exposure_paths
                   (id, source_asset_id, target_asset_id, hops, protocol, risk_score, description, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    path.id, path.source_asset_id, path.target_asset_id,
                    json.dumps(path.hops), path.protocol, path.risk_score,
                    path.description, org_id,
                ),
            )
            self._conn.commit()

    def list_paths(self, org_id: str, min_score: float = 0.0) -> List[ExposurePath]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, source_asset_id, target_asset_id, hops, protocol, risk_score, description "
                "FROM exposure_paths WHERE org_id = ? AND risk_score >= ?",
                (org_id, min_score),
            ).fetchall()
        return [self._row_to_path(r) for r in rows]

    def get_assets_since(self, org_id: str, since: str) -> List[Asset]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, name, type, exposure_level, attributes, tags, discovered_at, last_seen, org_id "
                "FROM assets WHERE org_id = ? AND discovered_at >= ?",
                (org_id, since),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def get_assets_not_seen_since(self, org_id: str, since: str) -> List[Asset]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, name, type, exposure_level, attributes, tags, discovered_at, last_seen, org_id "
                "FROM assets WHERE org_id = ? AND last_seen < ?",
                (org_id, since),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    @staticmethod
    def _row_to_asset(row: tuple) -> Asset:
        (id_, name, type_, exposure_level, attributes, tags, discovered_at, last_seen, org_id) = row
        return Asset(
            id=id_, name=name,
            type=AssetType(type_),
            exposure_level=ExposureLevel(exposure_level),
            attributes=json.loads(attributes or "{}"),
            tags=json.loads(tags or "[]"),
            discovered_at=discovered_at,
            last_seen=last_seen,
            org_id=org_id,
        )

    @staticmethod
    def _row_to_path(row: tuple) -> ExposurePath:
        (id_, source, target, hops, protocol, risk_score, description) = row
        return ExposurePath(
            id=id_, source_asset_id=source, target_asset_id=target,
            hops=json.loads(hops or "[]"),
            protocol=protocol, risk_score=risk_score, description=description,
        )


# ---------------------------------------------------------------------------
# Exposure level scoring weights
# ---------------------------------------------------------------------------
_EXPOSURE_RISK: Dict[ExposureLevel, float] = {
    ExposureLevel.EXTERNAL: 1.0,
    ExposureLevel.DMZ: 0.7,
    ExposureLevel.INTERNAL: 0.3,
    ExposureLevel.ISOLATED: 0.1,
}

_TYPE_RISK: Dict[AssetType, float] = {
    AssetType.API_ENDPOINT: 0.9,
    AssetType.DOMAIN: 0.8,
    AssetType.IP_ADDRESS: 0.7,
    AssetType.CLOUD_RESOURCE: 0.6,
    AssetType.SERVICE: 0.5,
    AssetType.CONTAINER: 0.4,
    AssetType.REPOSITORY: 0.3,
}

# Regex patterns for finding extraction from pipeline findings
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_ENDPOINT_PATTERN = re.compile(r"(?:GET|POST|PUT|DELETE|PATCH)\s+(/[^\s]+)")
_PORT_PATTERN = re.compile(r":(\d{2,5})\b")


# ---------------------------------------------------------------------------
# AttackSurfaceMapper
# ---------------------------------------------------------------------------

class AttackSurfaceMapper:
    """Maps and tracks the attack surface from discovered assets and findings."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _AssetDB(db_path)
        logger.info("AttackSurfaceMapper initialised", db_path=db_path)

    # ------------------------------------------------------------------
    # Asset CRUD
    # ------------------------------------------------------------------

    def register_asset(self, asset: Asset) -> Asset:
        """Add or update an asset in the inventory."""
        asset.last_seen = datetime.now(timezone.utc).isoformat()
        self._db.upsert_asset(asset)
        logger.info("Asset registered", asset_id=asset.id, name=asset.name, type=asset.type.value)
        return asset

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Retrieve a single asset by ID."""
        return self._db.get_asset(asset_id)

    def list_assets(
        self,
        org_id: str,
        type_filter: Optional[AssetType] = None,
        exposure_filter: Optional[ExposureLevel] = None,
    ) -> List[Asset]:
        """List assets for an org with optional type/exposure filters."""
        return self._db.list_assets(
            org_id,
            type_filter.value if type_filter else None,
            exposure_filter.value if exposure_filter else None,
        )

    def delete_asset(self, asset_id: str) -> bool:
        """Delete an asset by ID. Returns True if deleted."""
        deleted = self._db.delete_asset(asset_id)
        if deleted:
            logger.info("Asset deleted", asset_id=asset_id)
        return deleted

    def get_external_assets(self, org_id: str) -> List[Asset]:
        """Return only internet-facing (EXTERNAL exposure) assets."""
        return self._db.list_assets(org_id, exposure_filter=ExposureLevel.EXTERNAL.value)

    # ------------------------------------------------------------------
    # Finding-based discovery
    # ------------------------------------------------------------------

    def discover_from_findings(self, findings: List[Dict[str, Any]]) -> List[Asset]:
        """Extract assets from pipeline findings.

        Looks for host, ip, url, endpoint fields and auto-registers discovered assets.
        """
        discovered: List[Asset] = []
        seen_names: set = set()

        for finding in findings:
            org_id = finding.get("org_id", "default")
            assets_from_finding = self._extract_assets_from_finding(finding, org_id)
            for asset in assets_from_finding:
                if asset.name not in seen_names:
                    seen_names.add(asset.name)
                    registered = self.register_asset(asset)
                    discovered.append(registered)

        logger.info("Discovery complete", total_discovered=len(discovered))
        return discovered

    def _extract_assets_from_finding(
        self, finding: Dict[str, Any], org_id: str
    ) -> List[Asset]:
        """Extract asset candidates from a single finding dict."""
        assets: List[Asset] = []
        now = datetime.now(timezone.utc).isoformat()

        # Explicit host/asset fields
        host = finding.get("host") or finding.get("hostname") or finding.get("target")
        if host and isinstance(host, str):
            asset_type = AssetType.IP_ADDRESS if _IP_PATTERN.fullmatch(host.strip()) else AssetType.DOMAIN
            exposure = self._infer_exposure(finding)
            assets.append(Asset(
                name=host.strip(), type=asset_type, exposure_level=exposure,
                attributes=self._extract_attributes(finding),
                tags=["auto-discovered"],
                discovered_at=now, last_seen=now, org_id=org_id,
            ))

        # URL / endpoint fields
        url = finding.get("url") or finding.get("endpoint")
        if url and isinstance(url, str):
            assets.append(Asset(
                name=url.strip(), type=AssetType.API_ENDPOINT,
                exposure_level=self._infer_exposure(finding),
                attributes={"url": url},
                tags=["auto-discovered", "endpoint"],
                discovered_at=now, last_seen=now, org_id=org_id,
            ))

        # Cloud resource
        cloud_res = finding.get("cloud_resource") or finding.get("resource_arn")
        if cloud_res and isinstance(cloud_res, str):
            assets.append(Asset(
                name=cloud_res.strip(), type=AssetType.CLOUD_RESOURCE,
                exposure_level=ExposureLevel.INTERNAL,
                attributes={
                    "cloud_provider": finding.get("cloud_provider", "aws"),
                    "region": finding.get("region", ""),
                },
                tags=["auto-discovered", "cloud"],
                discovered_at=now, last_seen=now, org_id=org_id,
            ))

        # Container image
        container = finding.get("container") or finding.get("image")
        if container and isinstance(container, str):
            assets.append(Asset(
                name=container.strip(), type=AssetType.CONTAINER,
                exposure_level=ExposureLevel.INTERNAL,
                attributes={"image": container},
                tags=["auto-discovered", "container"],
                discovered_at=now, last_seen=now, org_id=org_id,
            ))

        # Free-text scanning for IPs in description
        description = finding.get("description", "") or finding.get("details", "")
        if isinstance(description, str):
            for ip in _IP_PATTERN.findall(description):
                assets.append(Asset(
                    name=ip, type=AssetType.IP_ADDRESS,
                    exposure_level=ExposureLevel.INTERNAL,
                    attributes={"source": "description_scan"},
                    tags=["auto-discovered", "text-extracted"],
                    discovered_at=now, last_seen=now, org_id=org_id,
                ))

        return assets

    @staticmethod
    def _infer_exposure(finding: Dict[str, Any]) -> ExposureLevel:
        """Infer exposure level from finding metadata."""
        exposure = finding.get("exposure") or finding.get("exposure_level", "")
        if isinstance(exposure, str):
            exposure_lower = exposure.lower()
            for level in ExposureLevel:
                if level.value in exposure_lower:
                    return level

        # Heuristics
        severity = str(finding.get("severity", "")).lower()
        env = str(finding.get("environment", "") or finding.get("env", "")).lower()
        if "prod" in env or "external" in env or "public" in env:
            return ExposureLevel.EXTERNAL
        if "dmz" in env:
            return ExposureLevel.DMZ
        if "internal" in env or "private" in env:
            return ExposureLevel.INTERNAL
        if "critical" in severity:
            return ExposureLevel.EXTERNAL
        return ExposureLevel.INTERNAL

    @staticmethod
    def _extract_attributes(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract useful attributes from a finding."""
        attrs: Dict[str, Any] = {}
        for key in ("port", "protocol", "cloud_provider", "region", "severity", "scanner"):
            if key in finding:
                attrs[key] = finding[key]
        return attrs

    # ------------------------------------------------------------------
    # Exposure path mapping
    # ------------------------------------------------------------------

    def map_exposure_path(
        self,
        source_id: str,
        target_id: str,
        hops: List[str],
        protocol: str = "unknown",
        org_id: str = "default",
    ) -> ExposurePath:
        """Create an explicit exposure path between two assets."""
        source = self._db.get_asset(source_id)
        target = self._db.get_asset(target_id)

        risk_score = self._compute_path_risk(source, target, hops)
        description = self._describe_path(source, target, protocol)

        path = ExposurePath(
            source_asset_id=source_id, target_asset_id=target_id,
            hops=hops, protocol=protocol,
            risk_score=risk_score, description=description,
        )
        self._db.upsert_path(path, org_id)
        logger.info("Exposure path mapped", path_id=path.id, risk_score=risk_score)
        return path

    def auto_map_paths(self, org_id: str) -> List[ExposurePath]:
        """Infer exposure paths from asset relationships.

        Creates paths from EXTERNAL assets to INTERNAL assets that share
        attributes (same port, protocol, or tag group).
        """
        all_assets = self._db.list_assets(org_id)
        external = [a for a in all_assets if a.exposure_level == ExposureLevel.EXTERNAL]
        internal = [a for a in all_assets if a.exposure_level in (ExposureLevel.INTERNAL, ExposureLevel.DMZ)]

        paths: List[ExposurePath] = []
        for ext in external:
            for inn in internal:
                # Only create paths for assets that share a protocol or port
                ext_port = ext.attributes.get("port")
                inn_port = inn.attributes.get("port")
                ext_proto = ext.attributes.get("protocol", "")
                inn_proto = inn.attributes.get("protocol", "")

                if ext_port and ext_port == inn_port:
                    protocol = ext_proto or inn_proto or "unknown"
                    path = self.map_exposure_path(
                        ext.id, inn.id, hops=[ext.id, inn.id],
                        protocol=str(protocol), org_id=org_id,
                    )
                    paths.append(path)
                elif ext_proto and ext_proto == inn_proto and ext_proto:
                    path = self.map_exposure_path(
                        ext.id, inn.id, hops=[ext.id, inn.id],
                        protocol=str(ext_proto), org_id=org_id,
                    )
                    paths.append(path)

        logger.info("Auto-mapped exposure paths", count=len(paths), org_id=org_id)
        return paths

    def get_high_risk_paths(self, org_id: str, min_score: float = 0.7) -> List[ExposurePath]:
        """Return exposure paths with risk_score >= min_score."""
        return self._db.list_paths(org_id, min_score=min_score)

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def score_asset_risk(self, asset_id: str) -> float:
        """Score an asset's risk as a float 0.0–1.0.

        Factors: exposure level, asset type, age (stale assets = higher risk).
        """
        asset = self._db.get_asset(asset_id)
        if not asset:
            return 0.0

        exposure_score = _EXPOSURE_RISK.get(asset.exposure_level, 0.3)
        type_score = _TYPE_RISK.get(asset.type, 0.5)

        # Age penalty: assets not seen in >30 days get +0.2
        try:
            last_seen_dt = datetime.fromisoformat(asset.last_seen.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - last_seen_dt).days
        except (ValueError, TypeError):
            age_days = 0
        age_penalty = 0.2 if age_days > 30 else 0.0

        score = min(1.0, (exposure_score * 0.5 + type_score * 0.4 + age_penalty * 0.1))
        return round(score, 3)

    # ------------------------------------------------------------------
    # Attack surface summary
    # ------------------------------------------------------------------

    def get_attack_surface(self, org_id: str) -> AttackSurface:
        """Compute and return the full attack surface summary for an org."""
        all_assets = self._db.list_assets(org_id)
        all_paths = self._db.list_paths(org_id)

        # Aggregate counts
        assets_by_type: Dict[str, int] = {}
        assets_by_exposure: Dict[str, int] = {}
        total_risk = 0.0

        for asset in all_assets:
            assets_by_type[asset.type.value] = assets_by_type.get(asset.type.value, 0) + 1
            assets_by_exposure[asset.exposure_level.value] = (
                assets_by_exposure.get(asset.exposure_level.value, 0) + 1
            )
            total_risk += _EXPOSURE_RISK.get(asset.exposure_level, 0.3)

        external_count = assets_by_exposure.get(ExposureLevel.EXTERNAL.value, 0)
        high_risk_count = sum(1 for p in all_paths if p.risk_score >= 0.7)

        overall_risk = round(total_risk / max(len(all_assets), 1), 3)

        return AttackSurface(
            org_id=org_id,
            total_assets=len(all_assets),
            external_assets=external_count,
            high_risk_paths=high_risk_count,
            risk_score=overall_risk,
            last_scan=datetime.now(timezone.utc).isoformat(),
            assets_by_type=assets_by_type,
            assets_by_exposure=assets_by_exposure,
        )

    # ------------------------------------------------------------------
    # Surface change detection
    # ------------------------------------------------------------------

    def get_surface_changes(self, org_id: str, since_days: int = 7) -> Dict[str, Any]:
        """Return new, removed, and changed assets since N days ago."""
        since_dt = datetime.now(timezone.utc) - timedelta(days=since_days)
        since_str = since_dt.isoformat()

        new_assets = self._db.get_assets_since(org_id, since_str)
        stale_assets = self._db.get_assets_not_seen_since(org_id, since_str)

        return {
            "since_days": since_days,
            "new_assets": [a.model_dump() for a in new_assets],
            "removed_assets": [a.model_dump() for a in stale_assets],
            "new_count": len(new_assets),
            "removed_count": len(stale_assets),
            "summary": f"{len(new_assets)} new, {len(stale_assets)} potentially removed",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_path_risk(
        self,
        source: Optional[Asset],
        target: Optional[Asset],
        hops: List[str],
    ) -> float:
        """Compute risk score for a path based on source/target exposure."""
        source_risk = _EXPOSURE_RISK.get(source.exposure_level, 0.5) if source else 0.5
        target_risk = _EXPOSURE_RISK.get(target.exposure_level, 0.3) if target else 0.3
        hop_penalty = min(0.2, len(hops) * 0.05)
        score = (source_risk * 0.6 + target_risk * 0.3 + hop_penalty * 0.1)
        return round(min(1.0, score), 3)

    @staticmethod
    def _describe_path(
        source: Optional[Asset],
        target: Optional[Asset],
        protocol: str,
    ) -> str:
        src_name = source.name if source else "unknown"
        tgt_name = target.name if target else "unknown"
        return f"{src_name} → {tgt_name} via {protocol}"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_mapper: Optional[AttackSurfaceMapper] = None
_mapper_lock = threading.Lock()


def get_attack_surface_mapper(db_path: str = _DEFAULT_DB) -> AttackSurfaceMapper:
    """Return the singleton AttackSurfaceMapper instance."""
    global _mapper
    if _mapper is None:
        with _mapper_lock:
            if _mapper is None:
                _mapper = AttackSurfaceMapper(db_path=db_path)
    return _mapper
