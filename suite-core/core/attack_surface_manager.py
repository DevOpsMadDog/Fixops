"""Attack Surface Management (ASM) Engine — CTEM Positioning.

Full-lifecycle ASM: external asset discovery, scoring, shadow IT detection,
exposure analysis, attack path mapping, continuous monitoring, and risk
prioritization with EPSS integration stubs.

Usage:
    from core.attack_surface_manager import get_asm_engine
    engine = get_asm_engine()
    result = engine.run_scan("org-123")
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

import hashlib
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

_DEFAULT_DB = os.getenv("FIXOPS_ASM_DB", ".fixops_data/attack_surface_manager.db")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AssetCategory(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    CLOUD_RESOURCE = "cloud_resource"
    API_ENDPOINT = "api_endpoint"
    CERTIFICATE = "certificate"
    SAAS_APP = "saas_app"
    NETWORK_DEVICE = "network_device"
    REPOSITORY = "repository"


class ExposureZone(str, Enum):
    INTERNET_FACING = "internet_facing"
    DMZ = "dmz"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class RiskTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class ChangeType(str, Enum):
    NEW_ASSET = "new_asset"
    REMOVED_ASSET = "removed_asset"
    EXPOSURE_CHANGED = "exposure_changed"
    CERT_EXPIRING = "cert_expiring"
    WAF_REMOVED = "waf_removed"
    NEW_PORT = "new_port"
    SCORE_CHANGED = "score_changed"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class ManagedAsset(BaseModel):
    """Core asset tracked by the ASM engine."""

    id: str = Field(default_factory=lambda: f"asm-{uuid.uuid4().hex[:12]}")
    org_id: str = "default"
    name: str
    category: AssetCategory
    exposure_zone: ExposureZone = ExposureZone.INTERNAL
    # Composite risk score 0.0–100.0
    risk_score: float = 0.0
    risk_tier: RiskTier = RiskTier.INFORMATIONAL
    # Discovery metadata
    is_managed: bool = True
    is_shadow_it: bool = False
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_scanned: Optional[str] = None
    # Asset details
    ip_addresses: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    # Security posture
    has_waf: bool = False
    has_cdn: bool = False
    tls_grade: Optional[str] = None
    cert_expiry_days: Optional[int] = None
    security_headers_score: float = 0.0
    # Business context
    business_value: float = 50.0  # 0–100
    owner: Optional[str] = None


class CertificateRecord(BaseModel):
    """TLS certificate tracked per asset."""

    id: str = Field(default_factory=lambda: f"cert-{uuid.uuid4().hex[:10]}")
    org_id: str = "default"
    asset_id: str
    asset_name: str
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    days_until_expiry: int
    san_domains: List[str] = Field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    tls_version: str = "TLS 1.2"
    cipher_suite: str = ""
    grade: str = "A"
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AttackPath(BaseModel):
    """Modelled attack path from internet into internal zone."""

    id: str = Field(default_factory=lambda: f"path-{uuid.uuid4().hex[:10]}")
    org_id: str = "default"
    name: str = ""
    entry_asset_id: str
    target_asset_id: str
    hops: List[str] = Field(default_factory=list)
    protocol: str = "unknown"
    # Risk metrics
    path_risk_score: float = 0.0
    blast_radius: int = 0
    is_choke_point: bool = False
    # MITRE ATT&CK alignment
    techniques: List[str] = Field(default_factory=list)
    description: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ShadowITFinding(BaseModel):
    """Unmanaged / rogue asset detected via shadow IT scan."""

    id: str = Field(default_factory=lambda: f"shadow-{uuid.uuid4().hex[:10]}")
    org_id: str = "default"
    asset_name: str
    asset_category: AssetCategory
    exposure_zone: ExposureZone
    reason: str  # Why flagged as shadow IT
    risk_tier: RiskTier = RiskTier.MEDIUM
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)


class SurfaceChange(BaseModel):
    """A detected change in the attack surface."""

    id: str = Field(default_factory=lambda: f"chg-{uuid.uuid4().hex[:10]}")
    org_id: str = "default"
    change_type: ChangeType
    asset_id: str
    asset_name: str
    description: str
    severity: RiskTier = RiskTier.MEDIUM
    detected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of a full attack surface scan."""

    id: str = Field(default_factory=lambda: f"scan-{uuid.uuid4().hex[:10]}")
    org_id: str = "default"
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    assets_discovered: int = 0
    shadow_it_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    changes_detected: int = 0
    overall_score: float = 0.0
    error: Optional[str] = None


class ASMSurfaceScore(BaseModel):
    """Overall attack surface score with breakdown."""

    org_id: str
    overall_score: float  # 0–100 (lower = better)
    exposure_score: float
    vulnerability_score: float
    configuration_score: float
    certificate_score: float
    shadow_it_score: float
    total_assets: int
    internet_facing_count: int
    critical_assets: int
    shadow_it_count: int
    unpatched_assets: int
    expiring_certs: int
    computed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

_ZONE_WEIGHT: Dict[ExposureZone, float] = {
    ExposureZone.INTERNET_FACING: 1.0,
    ExposureZone.DMZ: 0.65,
    ExposureZone.INTERNAL: 0.3,
    ExposureZone.ISOLATED: 0.05,
}

_CATEGORY_WEIGHT: Dict[AssetCategory, float] = {
    AssetCategory.API_ENDPOINT: 0.95,
    AssetCategory.DOMAIN: 0.85,
    AssetCategory.SUBDOMAIN: 0.80,
    AssetCategory.IP_ADDRESS: 0.70,
    AssetCategory.CLOUD_RESOURCE: 0.65,
    AssetCategory.NETWORK_DEVICE: 0.60,
    AssetCategory.SAAS_APP: 0.55,
    AssetCategory.REPOSITORY: 0.40,
    AssetCategory.CERTIFICATE: 0.30,
}

_RISK_PORT_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}

_HIGH_RISK_PORTS = {21, 23, 3306, 3389, 5432, 6379, 27017}

_RISKY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

# Shadow IT heuristics — SaaS domains that suggest unmanaged usage
_SAAS_PATTERNS = [
    r"\.dropbox\.com$",
    r"\.box\.com$",
    r"\.wetransfer\.com$",
    r"\.notion\.so$",
    r"\.trello\.com$",
    r"\.airtable\.com$",
    r"\.monday\.com$",
    r"\.figma\.com$",
    r"\.miro\.com$",
    r"account\..*\.io$",
]
_SAAS_RE = [re.compile(p) for p in _SAAS_PATTERNS]


# ---------------------------------------------------------------------------
# SQLite persistence layer
# ---------------------------------------------------------------------------


class _ASMDB:
    """SQLite-backed store for all ASM entities."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS asm_assets (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    exposure_zone TEXT NOT NULL,
                    risk_score REAL DEFAULT 0.0,
                    risk_tier TEXT DEFAULT 'informational',
                    is_managed INTEGER DEFAULT 1,
                    is_shadow_it INTEGER DEFAULT 0,
                    discovered_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_scanned TEXT,
                    ip_addresses TEXT DEFAULT '[]',
                    open_ports TEXT DEFAULT '[]',
                    technologies TEXT DEFAULT '[]',
                    tags TEXT DEFAULT '[]',
                    attributes TEXT DEFAULT '{}',
                    has_waf INTEGER DEFAULT 0,
                    has_cdn INTEGER DEFAULT 0,
                    tls_grade TEXT,
                    cert_expiry_days INTEGER,
                    security_headers_score REAL DEFAULT 0.0,
                    business_value REAL DEFAULT 50.0,
                    owner TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_asm_assets_org ON asm_assets(org_id);
                CREATE INDEX IF NOT EXISTS idx_asm_assets_zone ON asm_assets(exposure_zone);
                CREATE INDEX IF NOT EXISTS idx_asm_assets_shadow ON asm_assets(is_shadow_it);
                CREATE INDEX IF NOT EXISTS idx_asm_assets_tier ON asm_assets(risk_tier);

                CREATE TABLE IF NOT EXISTS asm_certificates (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    asset_name TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    valid_to TEXT NOT NULL,
                    days_until_expiry INTEGER NOT NULL,
                    san_domains TEXT DEFAULT '[]',
                    is_expired INTEGER DEFAULT 0,
                    is_self_signed INTEGER DEFAULT 0,
                    tls_version TEXT DEFAULT 'TLS 1.2',
                    cipher_suite TEXT DEFAULT '',
                    grade TEXT DEFAULT 'A',
                    checked_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_asm_certs_org ON asm_certificates(org_id);
                CREATE INDEX IF NOT EXISTS idx_asm_certs_asset ON asm_certificates(asset_id);
                CREATE INDEX IF NOT EXISTS idx_asm_certs_expiry ON asm_certificates(days_until_expiry);

                CREATE TABLE IF NOT EXISTS asm_attack_paths (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    name TEXT DEFAULT '',
                    entry_asset_id TEXT NOT NULL,
                    target_asset_id TEXT NOT NULL,
                    hops TEXT DEFAULT '[]',
                    protocol TEXT DEFAULT 'unknown',
                    path_risk_score REAL DEFAULT 0.0,
                    blast_radius INTEGER DEFAULT 0,
                    is_choke_point INTEGER DEFAULT 0,
                    techniques TEXT DEFAULT '[]',
                    description TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_asm_paths_org ON asm_attack_paths(org_id);
                CREATE INDEX IF NOT EXISTS idx_asm_paths_entry ON asm_attack_paths(entry_asset_id);

                CREATE TABLE IF NOT EXISTS asm_shadow_it (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    asset_name TEXT NOT NULL,
                    asset_category TEXT NOT NULL,
                    exposure_zone TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    risk_tier TEXT DEFAULT 'medium',
                    detected_at TEXT NOT NULL,
                    details TEXT DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_shadow_org ON asm_shadow_it(org_id);

                CREATE TABLE IF NOT EXISTS asm_changes (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    asset_name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    detected_at TEXT NOT NULL,
                    details TEXT DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_asm_changes_org ON asm_changes(org_id);
                CREATE INDEX IF NOT EXISTS idx_asm_changes_type ON asm_changes(change_type);

                CREATE TABLE IF NOT EXISTS asm_scans (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    assets_discovered INTEGER DEFAULT 0,
                    shadow_it_count INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    changes_detected INTEGER DEFAULT 0,
                    overall_score REAL DEFAULT 0.0,
                    error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_asm_scans_org ON asm_scans(org_id);
            """)
            self._conn.commit()

    # ---- Assets ----

    def upsert_asset(self, asset: ManagedAsset) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO asm_assets
                   (id, org_id, name, category, exposure_zone, risk_score, risk_tier,
                    is_managed, is_shadow_it, discovered_at, last_seen, last_scanned,
                    ip_addresses, open_ports, technologies, tags, attributes,
                    has_waf, has_cdn, tls_grade, cert_expiry_days,
                    security_headers_score, business_value, owner)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    asset.id, asset.org_id, asset.name, asset.category.value,
                    asset.exposure_zone.value, asset.risk_score, asset.risk_tier.value,
                    int(asset.is_managed), int(asset.is_shadow_it),
                    asset.discovered_at, asset.last_seen, asset.last_scanned,
                    json.dumps(asset.ip_addresses), json.dumps(asset.open_ports),
                    json.dumps(asset.technologies), json.dumps(asset.tags),
                    json.dumps(asset.attributes),
                    int(asset.has_waf), int(asset.has_cdn),
                    asset.tls_grade, asset.cert_expiry_days,
                    asset.security_headers_score, asset.business_value, asset.owner,
                ),
            )
            self._conn.commit()

    def get_asset(self, asset_id: str) -> Optional[ManagedAsset]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM asm_assets WHERE id = ?", (asset_id,)
            ).fetchone()
        return self._row_to_asset(row) if row else None

    def list_assets(
        self,
        org_id: str,
        category: Optional[str] = None,
        zone: Optional[str] = None,
        shadow_it_only: bool = False,
        tier: Optional[str] = None,
    ) -> List[ManagedAsset]:
        query = "SELECT * FROM asm_assets WHERE org_id = ?"
        params: List[Any] = [org_id]
        if category:
            query += " AND category = ?"
            params.append(category)
        if zone:
            query += " AND exposure_zone = ?"
            params.append(zone)
        if shadow_it_only:
            query += " AND is_shadow_it = 1"
        if tier:
            query += " AND risk_tier = ?"
            params.append(tier)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def delete_asset(self, asset_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM asm_assets WHERE id = ?", (asset_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def get_assets_since(self, org_id: str, since: str) -> List[ManagedAsset]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM asm_assets WHERE org_id = ? AND discovered_at >= ?",
                (org_id, since),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def get_stale_assets(self, org_id: str, before: str) -> List[ManagedAsset]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM asm_assets WHERE org_id = ? AND last_seen < ?",
                (org_id, before),
            ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    # ---- Certificates ----

    def upsert_cert(self, cert: CertificateRecord) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO asm_certificates
                   (id, org_id, asset_id, asset_name, subject, issuer, valid_from,
                    valid_to, days_until_expiry, san_domains, is_expired,
                    is_self_signed, tls_version, cipher_suite, grade, checked_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cert.id, cert.org_id, cert.asset_id, cert.asset_name,
                    cert.subject, cert.issuer, cert.valid_from, cert.valid_to,
                    cert.days_until_expiry, json.dumps(cert.san_domains),
                    int(cert.is_expired), int(cert.is_self_signed),
                    cert.tls_version, cert.cipher_suite, cert.grade, cert.checked_at,
                ),
            )
            self._conn.commit()

    def list_certs(self, org_id: str) -> List[CertificateRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM asm_certificates WHERE org_id = ? ORDER BY days_until_expiry ASC",
                (org_id,),
            ).fetchall()
        return [self._row_to_cert(r) for r in rows]

    def get_expiring_certs(self, org_id: str, within_days: int = 30) -> List[CertificateRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM asm_certificates WHERE org_id = ? AND days_until_expiry <= ? AND is_expired = 0",
                (org_id, within_days),
            ).fetchall()
        return [self._row_to_cert(r) for r in rows]

    # ---- Attack paths ----

    def upsert_path(self, path: AttackPath) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO asm_attack_paths
                   (id, org_id, name, entry_asset_id, target_asset_id, hops, protocol,
                    path_risk_score, blast_radius, is_choke_point, techniques, description, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    path.id, path.org_id, path.name, path.entry_asset_id, path.target_asset_id,
                    json.dumps(path.hops), path.protocol, path.path_risk_score,
                    path.blast_radius, int(path.is_choke_point),
                    json.dumps(path.techniques), path.description, path.created_at,
                ),
            )
            self._conn.commit()

    def list_paths(self, org_id: str, min_score: float = 0.0) -> List[AttackPath]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM asm_attack_paths WHERE org_id = ? AND path_risk_score >= ? ORDER BY path_risk_score DESC",
                (org_id, min_score),
            ).fetchall()
        return [self._row_to_path(r) for r in rows]

    # ---- Shadow IT ----

    def upsert_shadow_finding(self, finding: ShadowITFinding) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO asm_shadow_it
                   (id, org_id, asset_name, asset_category, exposure_zone, reason, risk_tier, detected_at, details)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    finding.id, finding.org_id, finding.asset_name,
                    finding.asset_category.value, finding.exposure_zone.value,
                    finding.reason, finding.risk_tier.value,
                    finding.detected_at, json.dumps(finding.details),
                ),
            )
            self._conn.commit()

    def list_shadow_findings(self, org_id: str) -> List[ShadowITFinding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM asm_shadow_it WHERE org_id = ? ORDER BY detected_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_shadow(r) for r in rows]

    # ---- Changes ----

    def record_change(self, change: SurfaceChange) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO asm_changes
                   (id, org_id, change_type, asset_id, asset_name, description, severity, detected_at, details)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    change.id, change.org_id, change.change_type.value,
                    change.asset_id, change.asset_name, change.description,
                    change.severity.value, change.detected_at, json.dumps(change.details),
                ),
            )
            self._conn.commit()

    def list_changes(self, org_id: str, since: Optional[str] = None) -> List[SurfaceChange]:
        query = "SELECT * FROM asm_changes WHERE org_id = ?"
        params: List[Any] = [org_id]
        if since:
            query += " AND detected_at >= ?"
            params.append(since)
        query += " ORDER BY detected_at DESC"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_change(r) for r in rows]

    # ---- Scans ----

    def upsert_scan(self, scan: ScanResult) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO asm_scans
                   (id, org_id, status, started_at, completed_at,
                    assets_discovered, shadow_it_count, critical_count, high_count,
                    changes_detected, overall_score, error)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan.id, scan.org_id, scan.status.value,
                    scan.started_at, scan.completed_at,
                    scan.assets_discovered, scan.shadow_it_count,
                    scan.critical_count, scan.high_count,
                    scan.changes_detected, scan.overall_score, scan.error,
                ),
            )
            self._conn.commit()

    def get_latest_scan(self, org_id: str) -> Optional[ScanResult]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM asm_scans WHERE org_id = ? ORDER BY started_at DESC LIMIT 1",
                (org_id,),
            ).fetchone()
        return self._row_to_scan(row) if row else None

    # ---- Row converters ----

    @staticmethod
    def _row_to_asset(row: tuple) -> ManagedAsset:
        (
            id_, org_id, name, category, zone, risk_score, risk_tier,
            is_managed, is_shadow_it, discovered_at, last_seen, last_scanned,
            ip_addresses, open_ports, technologies, tags, attributes,
            has_waf, has_cdn, tls_grade, cert_expiry_days,
            sec_headers_score, business_value, owner,
        ) = row
        return ManagedAsset(
            id=id_, org_id=org_id, name=name,
            category=AssetCategory(category),
            exposure_zone=ExposureZone(zone),
            risk_score=risk_score, risk_tier=RiskTier(risk_tier),
            is_managed=bool(is_managed), is_shadow_it=bool(is_shadow_it),
            discovered_at=discovered_at, last_seen=last_seen, last_scanned=last_scanned,
            ip_addresses=json.loads(ip_addresses or "[]"),
            open_ports=json.loads(open_ports or "[]"),
            technologies=json.loads(technologies or "[]"),
            tags=json.loads(tags or "[]"),
            attributes=json.loads(attributes or "{}"),
            has_waf=bool(has_waf), has_cdn=bool(has_cdn),
            tls_grade=tls_grade, cert_expiry_days=cert_expiry_days,
            security_headers_score=sec_headers_score,
            business_value=business_value, owner=owner,
        )

    @staticmethod
    def _row_to_cert(row: tuple) -> CertificateRecord:
        (
            id_, org_id, asset_id, asset_name, subject, issuer,
            valid_from, valid_to, days_until_expiry, san_domains,
            is_expired, is_self_signed, tls_version, cipher_suite, grade, checked_at,
        ) = row
        return CertificateRecord(
            id=id_, org_id=org_id, asset_id=asset_id, asset_name=asset_name,
            subject=subject, issuer=issuer, valid_from=valid_from, valid_to=valid_to,
            days_until_expiry=days_until_expiry,
            san_domains=json.loads(san_domains or "[]"),
            is_expired=bool(is_expired), is_self_signed=bool(is_self_signed),
            tls_version=tls_version, cipher_suite=cipher_suite,
            grade=grade, checked_at=checked_at,
        )

    @staticmethod
    def _row_to_path(row: tuple) -> AttackPath:
        (
            id_, org_id, name, entry_asset_id, target_asset_id, hops, protocol,
            path_risk_score, blast_radius, is_choke_point, techniques, description, created_at,
        ) = row
        return AttackPath(
            id=id_, org_id=org_id, name=name,
            entry_asset_id=entry_asset_id, target_asset_id=target_asset_id,
            hops=json.loads(hops or "[]"),
            protocol=protocol, path_risk_score=path_risk_score,
            blast_radius=blast_radius, is_choke_point=bool(is_choke_point),
            techniques=json.loads(techniques or "[]"),
            description=description, created_at=created_at,
        )

    @staticmethod
    def _row_to_shadow(row: tuple) -> ShadowITFinding:
        (id_, org_id, asset_name, asset_category, exposure_zone, reason, risk_tier, detected_at, details) = row
        return ShadowITFinding(
            id=id_, org_id=org_id, asset_name=asset_name,
            asset_category=AssetCategory(asset_category),
            exposure_zone=ExposureZone(exposure_zone),
            reason=reason, risk_tier=RiskTier(risk_tier),
            detected_at=detected_at, details=json.loads(details or "{}"),
        )

    @staticmethod
    def _row_to_change(row: tuple) -> SurfaceChange:
        (id_, org_id, change_type, asset_id, asset_name, description, severity, detected_at, details) = row
        return SurfaceChange(
            id=id_, org_id=org_id, change_type=ChangeType(change_type),
            asset_id=asset_id, asset_name=asset_name, description=description,
            severity=RiskTier(severity), detected_at=detected_at,
            details=json.loads(details or "{}"),
        )

    @staticmethod
    def _row_to_scan(row: tuple) -> ScanResult:
        (
            id_, org_id, status, started_at, completed_at,
            assets_discovered, shadow_it_count, critical_count, high_count,
            changes_detected, overall_score, error,
        ) = row
        return ScanResult(
            id=id_, org_id=org_id, status=ScanStatus(status),
            started_at=started_at, completed_at=completed_at,
            assets_discovered=assets_discovered, shadow_it_count=shadow_it_count,
            critical_count=critical_count, high_count=high_count,
            changes_detected=changes_detected, overall_score=overall_score, error=error,
        )


# ---------------------------------------------------------------------------
# EPSS stub
# ---------------------------------------------------------------------------


def _epss_score_stub(cve_id: str) -> float:
    """Stub for EPSS exploit probability lookup.

    Real implementation would call https://api.first.org/data/v1/epss?cve=CVE-XXXX.
    Returns a deterministic pseudo-score based on CVE hash for testing.
    """
    h = int(hashlib.md5(cve_id.encode(), usedforsecurity=False).hexdigest()[:4], 16)
    return round((h % 1000) / 1000, 3)


# ---------------------------------------------------------------------------
# Core ASM Engine
# ---------------------------------------------------------------------------


class AttackSurfaceManager:
    """Full-lifecycle Attack Surface Management engine.

    Covers:
    - External asset discovery and categorization
    - Composite risk scoring (exposure × vuln × business value)
    - Shadow IT detection against CMDB inventory
    - Exposure analysis (ports, TLS, security headers)
    - Attack path mapping with blast radius
    - Continuous change monitoring
    - Risk prioritization with EPSS stubs
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db = _ASMDB(db_path)
        logger.info("AttackSurfaceManager initialised", db_path=db_path)

    # ------------------------------------------------------------------
    # 1. Asset registration + external discovery
    # ------------------------------------------------------------------

    def register_asset(self, asset: ManagedAsset) -> ManagedAsset:
        """Register or update a managed asset. Scores are recomputed."""
        asset.last_seen = datetime.now(timezone.utc).isoformat()
        asset.risk_score = self._compute_asset_score(asset)
        asset.risk_tier = self._score_to_tier(asset.risk_score)
        self._db.upsert_asset(asset)
        logger.info(
            "Asset registered", asset_id=asset.id, name=asset.name,
            zone=asset.exposure_zone.value, score=asset.risk_score,
        )
        _emit_event("attack_surface_manager.asset_registered", {
            "asset_id": asset.id,
            "org_id": asset.org_id,
            "name": asset.name,
            "category": asset.category.value,
            "exposure_zone": asset.exposure_zone.value,
            "risk_score": asset.risk_score,
            "risk_tier": asset.risk_tier.value if asset.risk_tier else None,
        })
        return asset

    def get_asset(self, asset_id: str) -> Optional[ManagedAsset]:
        return self._db.get_asset(asset_id)

    def delete_asset(self, asset_id: str) -> bool:
        deleted = self._db.delete_asset(asset_id)
        if deleted:
            logger.info("Asset deleted", asset_id=asset_id)
        return deleted

    def list_assets(
        self,
        org_id: str,
        category: Optional[AssetCategory] = None,
        zone: Optional[ExposureZone] = None,
        shadow_it_only: bool = False,
        tier: Optional[RiskTier] = None,
    ) -> List[ManagedAsset]:
        return self._db.list_assets(
            org_id,
            category=category.value if category else None,
            zone=zone.value if zone else None,
            shadow_it_only=shadow_it_only,
            tier=tier.value if tier else None,
        )

    def discover_assets_from_data(
        self, data: List[Dict[str, Any]], org_id: str = "default"
    ) -> List[ManagedAsset]:
        """Parse raw discovery data (network scans, DNS records, etc.) into assets.

        Each dict may contain: host, ip, domain, subdomain, cloud_arn, saas_url,
        open_ports, technologies, tls_grade, has_waf, has_cdn, cert_expiry_days.
        """
        discovered: List[ManagedAsset] = []
        seen: set = set()
        now = datetime.now(timezone.utc).isoformat()

        for item in data:
            assets = self._parse_discovery_item(item, org_id, now)
            for asset in assets:
                if asset.name not in seen:
                    seen.add(asset.name)
                    registered = self.register_asset(asset)
                    discovered.append(registered)

        logger.info("Discovery complete", count=len(discovered), org_id=org_id)
        _emit_event("attack_surface_manager.discovery_complete", {
            "org_id": org_id,
            "asset_count": len(discovered),
        })
        return discovered

    def _parse_discovery_item(
        self, item: Dict[str, Any], org_id: str, now: str
    ) -> List[ManagedAsset]:
        assets: List[ManagedAsset] = []
        zone = self._infer_zone(item)

        for field_name, cat in (
            ("domain", AssetCategory.DOMAIN),
            ("subdomain", AssetCategory.SUBDOMAIN),
            ("host", AssetCategory.DOMAIN),
        ):
            val = item.get(field_name)
            if val and isinstance(val, str):
                assets.append(self._build_asset(val.strip(), cat, zone, item, org_id, now))

        for field_name, cat in (
            ("ip", AssetCategory.IP_ADDRESS),
            ("ip_address", AssetCategory.IP_ADDRESS),
        ):
            val = item.get(field_name)
            if val and isinstance(val, str):
                assets.append(self._build_asset(val.strip(), AssetCategory.IP_ADDRESS, zone, item, org_id, now))

        cloud_arn = item.get("cloud_arn") or item.get("resource_arn") or item.get("cloud_resource")
        if cloud_arn and isinstance(cloud_arn, str):
            assets.append(self._build_asset(cloud_arn.strip(), AssetCategory.CLOUD_RESOURCE, ExposureZone.INTERNAL, item, org_id, now))

        api_url = item.get("api_url") or item.get("api_endpoint")
        if api_url and isinstance(api_url, str):
            assets.append(self._build_asset(api_url.strip(), AssetCategory.API_ENDPOINT, ExposureZone.INTERNET_FACING, item, org_id, now))

        saas_url = item.get("saas_url")
        if saas_url and isinstance(saas_url, str):
            assets.append(self._build_asset(saas_url.strip(), AssetCategory.SAAS_APP, ExposureZone.INTERNET_FACING, item, org_id, now))

        return assets

    def _build_asset(
        self,
        name: str,
        category: AssetCategory,
        zone: ExposureZone,
        item: Dict[str, Any],
        org_id: str,
        now: str,
    ) -> ManagedAsset:
        ports_raw = item.get("open_ports", [])
        open_ports = [int(p) for p in ports_raw if isinstance(p, (int, str)) and str(p).isdigit()] if isinstance(ports_raw, list) else []
        return ManagedAsset(
            name=name, category=category, exposure_zone=zone, org_id=org_id,
            discovered_at=now, last_seen=now,
            ip_addresses=item.get("ip_addresses", []),
            open_ports=open_ports,
            technologies=item.get("technologies", []),
            tags=item.get("tags", ["auto-discovered"]),
            attributes={k: v for k, v in item.items() if k not in (
                "domain", "subdomain", "host", "ip", "ip_address", "cloud_arn",
                "resource_arn", "cloud_resource", "api_url", "api_endpoint",
                "saas_url", "open_ports", "technologies", "tags",
            )},
            has_waf=bool(item.get("has_waf", False)),
            has_cdn=bool(item.get("has_cdn", False)),
            tls_grade=item.get("tls_grade"),
            cert_expiry_days=item.get("cert_expiry_days"),
            security_headers_score=float(item.get("security_headers_score", 0.0)),
            business_value=float(item.get("business_value", 50.0)),
            owner=item.get("owner"),
        )

    # ------------------------------------------------------------------
    # 2. Attack surface scoring
    # ------------------------------------------------------------------

    def compute_surface_score(self, org_id: str) -> ASMSurfaceScore:
        """Compute overall and component scores for the org's attack surface."""
        assets = self._db.list_assets(org_id)
        certs = self._db.list_certs(org_id)
        shadow = self._db.list_shadow_findings(org_id)

        internet_facing = [a for a in assets if a.exposure_zone == ExposureZone.INTERNET_FACING]
        critical_assets = [a for a in assets if a.risk_tier == RiskTier.CRITICAL]
        expiring_certs = [c for c in certs if c.days_until_expiry <= 30 or c.is_expired]
        unpatched = [a for a in assets if a.attributes.get("patch_age_days", 0) > 90]

        # Component scores (0–100, higher = worse)
        n = max(len(assets), 1)
        exposure_score = round(len(internet_facing) / n * 100, 1)
        vuln_score = round(sum(a.risk_score for a in assets) / n, 1)
        config_score = round(
            sum(
                (1.0 - a.security_headers_score / 100) * 100
                for a in internet_facing
            ) / max(len(internet_facing), 1),
            1,
        )
        cert_score = round(
            (len(expiring_certs) / max(len(certs), 1)) * 100 if certs else 0.0,
            1,
        )
        shadow_score = round(len(shadow) / n * 100, 1)

        overall = round(
            exposure_score * 0.30
            + vuln_score * 0.35
            + config_score * 0.15
            + cert_score * 0.10
            + shadow_score * 0.10,
            1,
        )

        return ASMSurfaceScore(
            org_id=org_id,
            overall_score=min(100.0, overall),
            exposure_score=min(100.0, exposure_score),
            vulnerability_score=min(100.0, vuln_score),
            configuration_score=min(100.0, config_score),
            certificate_score=min(100.0, cert_score),
            shadow_it_score=min(100.0, shadow_score),
            total_assets=len(assets),
            internet_facing_count=len(internet_facing),
            critical_assets=len(critical_assets),
            shadow_it_count=len(shadow),
            unpatched_assets=len(unpatched),
            expiring_certs=len(expiring_certs),
        )

    def _compute_asset_score(self, asset: ManagedAsset) -> float:
        """Composite risk score 0–100 for a single asset."""
        zone_w = _ZONE_WEIGHT.get(asset.exposure_zone, 0.3)
        cat_w = _CATEGORY_WEIGHT.get(asset.category, 0.5)

        # Port risk: risky open ports increase score
        port_risk = 0.0
        if asset.open_ports:
            risky = sum(1 for p in asset.open_ports if p in _HIGH_RISK_PORTS)
            port_risk = min(1.0, risky / max(len(asset.open_ports), 1))

        # WAF / CDN protection lowers score
        protection = (0.15 if asset.has_waf else 0.0) + (0.10 if asset.has_cdn else 0.0)

        # Certificate health
        cert_penalty = 0.0
        if asset.cert_expiry_days is not None:
            if asset.cert_expiry_days <= 0:
                cert_penalty = 0.3
            elif asset.cert_expiry_days <= 14:
                cert_penalty = 0.2
            elif asset.cert_expiry_days <= 30:
                cert_penalty = 0.1

        # Security headers (0–100 → penalty if low)
        headers_penalty = max(0.0, (100.0 - asset.security_headers_score) / 100.0) * 0.1

        # Business value amplifier
        bv_amp = asset.business_value / 100.0

        raw = (
            zone_w * 0.40
            + cat_w * 0.25
            + port_risk * 0.15
            + cert_penalty * 0.10
            + headers_penalty * 0.05
            - protection * 0.05
        ) * bv_amp

        return round(min(100.0, raw * 100), 2)

    @staticmethod
    def _score_to_tier(score: float) -> RiskTier:
        if score >= 80:
            return RiskTier.CRITICAL
        if score >= 60:
            return RiskTier.HIGH
        if score >= 35:
            return RiskTier.MEDIUM
        if score >= 10:
            return RiskTier.LOW
        return RiskTier.INFORMATIONAL

    # ------------------------------------------------------------------
    # 3. Shadow IT detection
    # ------------------------------------------------------------------

    def detect_shadow_it(
        self,
        org_id: str,
        cmdb_names: Optional[List[str]] = None,
        discovered_names: Optional[List[str]] = None,
    ) -> List[ShadowITFinding]:
        """Compare discovered assets against CMDB/inventory to find shadow IT.

        Args:
            org_id: Organisation scope.
            cmdb_names: Known/approved asset names from CMDB.
            discovered_names: Additional names from network discovery (optional).
        """
        managed_names: set = set(cmdb_names or [])
        findings: List[ShadowITFinding] = []
        assets = self._db.list_assets(org_id)

        for asset in assets:
            reason: Optional[str] = None

            # Not in CMDB inventory
            if managed_names and asset.name not in managed_names:
                reason = f"Asset '{asset.name}' not found in CMDB inventory"

            # Matches known SaaS pattern (potential unauthorized SaaS)
            for pattern in _SAAS_RE:
                if pattern.search(asset.name):
                    reason = f"Asset '{asset.name}' matches known SaaS pattern — possible unauthorized SaaS usage"
                    break

            # Unmanaged flag explicitly set
            if not asset.is_managed:
                reason = reason or f"Asset '{asset.name}' is marked unmanaged"

            if reason:
                asset.is_shadow_it = True
                self._db.upsert_asset(asset)
                tier = (
                    RiskTier.HIGH
                    if asset.exposure_zone == ExposureZone.INTERNET_FACING
                    else RiskTier.MEDIUM
                )
                finding = ShadowITFinding(
                    org_id=org_id,
                    asset_name=asset.name,
                    asset_category=asset.category,
                    exposure_zone=asset.exposure_zone,
                    reason=reason,
                    risk_tier=tier,
                    details={"asset_id": asset.id, "risk_score": asset.risk_score},
                )
                self._db.upsert_shadow_finding(finding)
                findings.append(finding)

        # Also scan extra discovered names not in assets at all
        if discovered_names:
            for name in discovered_names:
                if managed_names and name not in managed_names:
                    known_ids = {a.name for a in assets}
                    if name not in known_ids:
                        finding = ShadowITFinding(
                            org_id=org_id,
                            asset_name=name,
                            asset_category=AssetCategory.DOMAIN,
                            exposure_zone=ExposureZone.INTERNET_FACING,
                            reason=f"Discovered domain '{name}' not in CMDB or asset inventory",
                            risk_tier=RiskTier.HIGH,
                        )
                        self._db.upsert_shadow_finding(finding)
                        findings.append(finding)

        logger.info("Shadow IT scan complete", count=len(findings), org_id=org_id)
        return findings

    def list_shadow_it(self, org_id: str) -> List[ShadowITFinding]:
        return self._db.list_shadow_findings(org_id)

    # ------------------------------------------------------------------
    # 4. Exposure analysis
    # ------------------------------------------------------------------

    def analyze_exposure(self, asset_id: str) -> Dict[str, Any]:
        """Return detailed exposure analysis for an internet-facing asset."""
        asset = self._db.get_asset(asset_id)
        if not asset:
            return {"error": f"Asset '{asset_id}' not found"}

        risky_ports = [p for p in asset.open_ports if p in _HIGH_RISK_PORTS]
        port_details = [
            {"port": p, "service": _RISK_PORT_MAP.get(p, "unknown"), "risk": "high" if p in _HIGH_RISK_PORTS else "low"}
            for p in asset.open_ports
        ]

        header_findings: List[str] = []
        for h in _RISKY_HEADERS:
            if h not in [t.lower() for t in asset.technologies]:
                header_findings.append(f"Missing security header: {h}")

        tls_issues: List[str] = []
        if asset.tls_grade and asset.tls_grade not in ("A", "A+"):
            tls_issues.append(f"TLS grade {asset.tls_grade} — consider improving cipher suite")
        if asset.cert_expiry_days is not None and asset.cert_expiry_days <= 30:
            tls_issues.append(f"Certificate expires in {asset.cert_expiry_days} days")

        return {
            "asset_id": asset_id,
            "asset_name": asset.name,
            "exposure_zone": asset.exposure_zone.value,
            "risk_score": asset.risk_score,
            "risk_tier": asset.risk_tier.value,
            "open_ports": port_details,
            "risky_ports": risky_ports,
            "technologies": asset.technologies,
            "has_waf": asset.has_waf,
            "has_cdn": asset.has_cdn,
            "tls_grade": asset.tls_grade,
            "cert_expiry_days": asset.cert_expiry_days,
            "security_headers_score": asset.security_headers_score,
            "security_header_findings": header_findings,
            "tls_issues": tls_issues,
            "protection_controls": {
                "waf": asset.has_waf,
                "cdn": asset.has_cdn,
                "tls_enforced": asset.tls_grade is not None,
            },
        }

    # ------------------------------------------------------------------
    # 5. Attack path mapping
    # ------------------------------------------------------------------

    def map_attack_path(
        self,
        org_id: str,
        entry_asset_id: str,
        target_asset_id: str,
        hops: Optional[List[str]] = None,
        protocol: str = "unknown",
        techniques: Optional[List[str]] = None,
    ) -> AttackPath:
        """Define an attack path from entry point to target asset."""
        entry = self._db.get_asset(entry_asset_id)
        target = self._db.get_asset(target_asset_id)

        hops = hops or [entry_asset_id, target_asset_id]
        blast_radius = self._estimate_blast_radius(org_id, target_asset_id)
        path_score = self._compute_path_score(entry, target, hops)
        is_choke_point = blast_radius > 5

        name = f"{entry.name if entry else entry_asset_id} → {target.name if target else target_asset_id}"
        description = (
            f"Attack path via {protocol}: "
            f"{entry.name if entry else entry_asset_id} "
            f"({len(hops)} hops) → {target.name if target else target_asset_id}. "
            f"Blast radius: {blast_radius} assets."
        )

        path = AttackPath(
            org_id=org_id, name=name,
            entry_asset_id=entry_asset_id, target_asset_id=target_asset_id,
            hops=hops, protocol=protocol,
            path_risk_score=path_score, blast_radius=blast_radius,
            is_choke_point=is_choke_point,
            techniques=techniques or [],
            description=description,
        )
        self._db.upsert_path(path)
        logger.info(
            "Attack path mapped", path_id=path.id, score=path_score,
            blast_radius=blast_radius, is_choke_point=is_choke_point,
        )
        return path

    def auto_generate_paths(self, org_id: str) -> List[AttackPath]:
        """Auto-generate attack paths from internet-facing to internal assets."""
        all_assets = self._db.list_assets(org_id)
        entry_points = [a for a in all_assets if a.exposure_zone == ExposureZone.INTERNET_FACING]
        dmz_assets = [a for a in all_assets if a.exposure_zone == ExposureZone.DMZ]
        internal_assets = [a for a in all_assets if a.exposure_zone == ExposureZone.INTERNAL]

        paths: List[AttackPath] = []

        for entry in entry_points:
            # Direct internet → internal (high risk)
            for target in internal_assets:
                if entry.id != target.id:
                    path = self.map_attack_path(
                        org_id, entry.id, target.id,
                        hops=[entry.id, target.id],
                        protocol=self._infer_protocol(entry, target),
                        techniques=["T1190", "T1078"],
                    )
                    paths.append(path)

            # Internet → DMZ → internal (lateral movement)
            for dmz in dmz_assets:
                for target in internal_assets:
                    path = self.map_attack_path(
                        org_id, entry.id, target.id,
                        hops=[entry.id, dmz.id, target.id],
                        protocol=self._infer_protocol(entry, target),
                        techniques=["T1190", "T1210", "T1021"],
                    )
                    paths.append(path)

        logger.info("Auto-generated attack paths", count=len(paths), org_id=org_id)
        return paths

    def list_attack_paths(self, org_id: str, min_score: float = 0.0) -> List[AttackPath]:
        return self._db.list_paths(org_id, min_score=min_score)

    def get_choke_points(self, org_id: str) -> List[AttackPath]:
        """Return paths that represent network choke points (high blast radius)."""
        return [p for p in self._db.list_paths(org_id) if p.is_choke_point]

    def _estimate_blast_radius(self, org_id: str, asset_id: str) -> int:
        """Estimate how many assets are reachable from the target (naive BFS stub)."""
        all_assets = self._db.list_assets(org_id)
        target = self._db.get_asset(asset_id)
        if not target:
            return 0

        # Reachable = assets in same zone or less-exposed zones
        zone_order = [
            ExposureZone.INTERNET_FACING,
            ExposureZone.DMZ,
            ExposureZone.INTERNAL,
            ExposureZone.ISOLATED,
        ]
        try:
            idx = zone_order.index(target.exposure_zone)
        except ValueError:
            idx = 2
        # Assets in same or more internal zones
        reachable_zones = set(z.value for z in zone_order[idx:])
        return sum(1 for a in all_assets if a.exposure_zone.value in reachable_zones and a.id != asset_id)

    def _compute_path_score(
        self,
        entry: Optional[ManagedAsset],
        target: Optional[ManagedAsset],
        hops: List[str],
    ) -> float:
        entry_w = _ZONE_WEIGHT.get(entry.exposure_zone, 0.5) if entry else 0.5
        target_w = _ZONE_WEIGHT.get(target.exposure_zone, 0.3) if target else 0.3
        entry_score = entry.risk_score / 100.0 if entry else 0.5
        target_score = target.risk_score / 100.0 if target else 0.3
        hop_bonus = min(0.15, len(hops) * 0.03)
        score = entry_w * 0.4 + target_w * 0.2 + entry_score * 0.25 + target_score * 0.10 + hop_bonus
        return round(min(1.0, score), 3)

    @staticmethod
    def _infer_protocol(
        entry: Optional[ManagedAsset], target: Optional[ManagedAsset]
    ) -> str:
        for asset in (entry, target):
            if asset is None:
                continue
            if 443 in asset.open_ports:
                return "HTTPS"
            if 80 in asset.open_ports:
                return "HTTP"
            if 22 in asset.open_ports:
                return "SSH"
        return "unknown"

    # ------------------------------------------------------------------
    # 6. Certificate management
    # ------------------------------------------------------------------

    def register_certificate(self, cert: CertificateRecord) -> CertificateRecord:
        self._db.upsert_cert(cert)
        logger.info("Certificate registered", cert_id=cert.id, asset=cert.asset_name, days=cert.days_until_expiry)

        # Auto-flag cert issues as changes
        if cert.is_expired:
            self._record_change(
                cert.org_id, ChangeType.CERT_EXPIRING,
                cert.asset_id, cert.asset_name,
                f"Certificate for {cert.asset_name} is EXPIRED",
                RiskTier.CRITICAL,
                {"cert_id": cert.id, "valid_to": cert.valid_to},
            )
        elif cert.days_until_expiry <= 14:
            self._record_change(
                cert.org_id, ChangeType.CERT_EXPIRING,
                cert.asset_id, cert.asset_name,
                f"Certificate for {cert.asset_name} expires in {cert.days_until_expiry} days",
                RiskTier.HIGH,
                {"cert_id": cert.id, "days_until_expiry": cert.days_until_expiry},
            )
        return cert

    def list_certificates(self, org_id: str) -> List[CertificateRecord]:
        return self._db.list_certs(org_id)

    def get_expiring_certificates(self, org_id: str, within_days: int = 30) -> List[CertificateRecord]:
        return self._db.get_expiring_certs(org_id, within_days)

    # ------------------------------------------------------------------
    # 7. Continuous monitoring + change detection
    # ------------------------------------------------------------------

    def detect_changes(self, org_id: str, lookback_days: int = 7) -> List[SurfaceChange]:
        """Detect changes in the attack surface over the lookback window."""
        since = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        new_assets = self._db.get_assets_since(org_id, since)
        stale_assets = self._db.get_stale_assets(org_id, since)
        changes: List[SurfaceChange] = []

        for asset in new_assets:
            chg = self._record_change(
                org_id, ChangeType.NEW_ASSET, asset.id, asset.name,
                f"New {asset.category.value} discovered: {asset.name}",
                RiskTier.HIGH if asset.exposure_zone == ExposureZone.INTERNET_FACING else RiskTier.MEDIUM,
                {"category": asset.category.value, "zone": asset.exposure_zone.value},
            )
            changes.append(chg)

        for asset in stale_assets:
            chg = self._record_change(
                org_id, ChangeType.REMOVED_ASSET, asset.id, asset.name,
                f"Asset not seen since {since}: {asset.name}",
                RiskTier.LOW,
                {"last_seen": asset.last_seen},
            )
            changes.append(chg)

        # Expiring certs
        expiring = self.get_expiring_certificates(org_id, within_days=30)
        for cert in expiring:
            chg = self._record_change(
                org_id, ChangeType.CERT_EXPIRING, cert.asset_id, cert.asset_name,
                f"Certificate expiring soon: {cert.asset_name} ({cert.days_until_expiry}d)",
                RiskTier.HIGH if cert.days_until_expiry <= 14 else RiskTier.MEDIUM,
                {"cert_id": cert.id, "days_until_expiry": cert.days_until_expiry},
            )
            changes.append(chg)

        logger.info("Change detection complete", count=len(changes), org_id=org_id)
        return changes

    def list_changes(self, org_id: str, since: Optional[str] = None) -> List[SurfaceChange]:
        return self._db.list_changes(org_id, since=since)

    def _record_change(
        self,
        org_id: str,
        change_type: ChangeType,
        asset_id: str,
        asset_name: str,
        description: str,
        severity: RiskTier,
        details: Optional[Dict[str, Any]] = None,
    ) -> SurfaceChange:
        change = SurfaceChange(
            org_id=org_id, change_type=change_type,
            asset_id=asset_id, asset_name=asset_name,
            description=description, severity=severity,
            details=details or {},
        )
        self._db.record_change(change)
        return change

    # ------------------------------------------------------------------
    # 8. Risk prioritization
    # ------------------------------------------------------------------

    def prioritize_assets(
        self, org_id: str, top_n: int = 20
    ) -> List[Dict[str, Any]]:
        """Rank assets by risk = exposure × vulnerability × business value.

        Includes EPSS score stubs for associated CVEs.
        """
        assets = self._db.list_assets(org_id)
        ranked: List[Dict[str, Any]] = []

        for asset in assets:
            # EPSS stubs for CVEs in attributes
            cves = asset.attributes.get("cves", [])
            epss_scores = {cve: _epss_score_stub(cve) for cve in cves} if cves else {}
            max_epss = max(epss_scores.values(), default=0.0)

            # Composite priority score
            priority = (
                asset.risk_score * 0.50
                + _ZONE_WEIGHT.get(asset.exposure_zone, 0.3) * 30
                + max_epss * 20
            )
            ranked.append({
                "asset_id": asset.id,
                "name": asset.name,
                "category": asset.category.value,
                "exposure_zone": asset.exposure_zone.value,
                "risk_score": asset.risk_score,
                "risk_tier": asset.risk_tier.value,
                "business_value": asset.business_value,
                "epss_scores": epss_scores,
                "max_epss": max_epss,
                "priority_score": round(priority, 2),
                "is_shadow_it": asset.is_shadow_it,
                "has_waf": asset.has_waf,
                "open_ports": asset.open_ports,
            })

        ranked.sort(key=lambda x: x["priority_score"], reverse=True)
        return ranked[:top_n]

    # ------------------------------------------------------------------
    # 9. Full scan orchestration
    # ------------------------------------------------------------------

    def run_scan(
        self,
        org_id: str,
        discovery_data: Optional[List[Dict[str, Any]]] = None,
        cmdb_names: Optional[List[str]] = None,
    ) -> ScanResult:
        """Orchestrate a full ASM scan cycle.

        Steps: discover → score → shadow IT → paths → changes → record.
        """
        scan = ScanResult(org_id=org_id, status=ScanStatus.RUNNING,
                          started_at=datetime.now(timezone.utc).isoformat())
        self._db.upsert_scan(scan)
        logger.info("ASM scan started", scan_id=scan.id, org_id=org_id)

        try:
            # Discovery
            if discovery_data:
                self.discover_assets_from_data(discovery_data, org_id)

            all_assets = self._db.list_assets(org_id)
            scan.assets_discovered = len(all_assets)

            # Shadow IT
            shadow_findings = self.detect_shadow_it(org_id, cmdb_names=cmdb_names)
            scan.shadow_it_count = len(shadow_findings)

            # Attack paths (only if there are both entry points and targets)
            internet_assets = [a for a in all_assets if a.exposure_zone == ExposureZone.INTERNET_FACING]
            internal_assets = [a for a in all_assets if a.exposure_zone == ExposureZone.INTERNAL]
            if internet_assets and internal_assets:
                self.auto_generate_paths(org_id)

            # Change detection
            changes = self.detect_changes(org_id)
            scan.changes_detected = len(changes)

            # Scoring
            surface_score = self.compute_surface_score(org_id)
            scan.overall_score = surface_score.overall_score
            scan.critical_count = surface_score.critical_assets
            scan.high_count = sum(1 for a in all_assets if a.risk_tier == RiskTier.HIGH)

            scan.status = ScanStatus.COMPLETE
            scan.completed_at = datetime.now(timezone.utc).isoformat()

        except Exception as exc:
            logger.exception("ASM scan failed", scan_id=scan.id, error=str(exc))
            scan.status = ScanStatus.FAILED
            scan.error = str(exc)

        self._db.upsert_scan(scan)
        logger.info(
            "ASM scan complete", scan_id=scan.id, status=scan.status.value,
            assets=scan.assets_discovered, score=scan.overall_score,
        )
        _emit_event("attack_surface_manager.scan_complete", {
            "scan_id": scan.id,
            "org_id": org_id,
            "status": scan.status.value,
            "assets_discovered": scan.assets_discovered,
            "shadow_it_count": scan.shadow_it_count,
            "changes_detected": scan.changes_detected,
            "overall_score": scan.overall_score,
            "critical_count": scan.critical_count,
        })
        return scan

    def get_latest_scan(self, org_id: str) -> Optional[ScanResult]:
        return self._db.get_latest_scan(org_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_zone(item: Dict[str, Any]) -> ExposureZone:
        zone = str(item.get("zone") or item.get("exposure_zone") or item.get("exposure") or "").lower()
        if "internet" in zone or "external" in zone or "public" in zone:
            return ExposureZone.INTERNET_FACING
        if "dmz" in zone:
            return ExposureZone.DMZ
        if "isolat" in zone:
            return ExposureZone.ISOLATED
        if "internal" in zone or "private" in zone:
            return ExposureZone.INTERNAL
        # Heuristic from environment field
        env = str(item.get("environment") or item.get("env") or "").lower()
        if "prod" in env or "ext" in env or "public" in env:
            return ExposureZone.INTERNET_FACING
        if "dmz" in env:
            return ExposureZone.DMZ
        return ExposureZone.INTERNAL


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[AttackSurfaceManager] = None
_engine_lock = threading.Lock()


def get_asm_engine(db_path: str = _DEFAULT_DB) -> AttackSurfaceManager:
    """Return the singleton AttackSurfaceManager instance."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = AttackSurfaceManager(db_path=db_path)
    return _engine
