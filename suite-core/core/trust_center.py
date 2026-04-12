"""
ALDECI Trust Center — public-facing security/compliance page management.

Provides:
- TrustPageConfig, ComplianceBadge, SecurityControl, SubprocessorEntry, TrustCenterData models
- TrustCenterManager class (SQLite-backed, thread-safe)

Replaces what Vanta charges $10K+/yr for with a self-hosted equivalent.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class TrustPageConfig(BaseModel):
    """Configuration for a public-facing trust page."""

    org_id: str
    org_name: str
    logo_url: Optional[str] = None
    brand_color: str = "#0066CC"
    enabled_sections: List[str] = Field(
        default_factory=lambda: ["compliance", "controls", "subprocessors"]
    )
    custom_message: Optional[str] = None
    contact_email: Optional[str] = None


class ComplianceBadge(BaseModel):
    """A compliance certification or attestation badge."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str  # SOC2, ISO27001, GDPR, HIPAA, PCI-DSS, etc.
    status: str  # certified | in_progress | planned
    certified_date: Optional[str] = None
    auditor: Optional[str] = None
    report_url: Optional[str] = None
    org_id: str = ""


class SecurityControl(BaseModel):
    """A security control with implementation status."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str  # Access Control, Encryption, Monitoring, etc.
    title: str
    description: str
    status: str  # implemented | planned
    org_id: str = ""


class SubprocessorEntry(BaseModel):
    """A sub-processor (third-party vendor) used by the organization."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    purpose: str
    location: str  # Country / region
    data_types: List[str] = Field(default_factory=list)
    org_id: str = ""


class TrustCenterData(BaseModel):
    """Aggregated public trust center page data — NO SECRETS."""

    config: TrustPageConfig
    badges: List[ComplianceBadge] = Field(default_factory=list)
    controls: List[SecurityControl] = Field(default_factory=list)
    subprocessors: List[SubprocessorEntry] = Field(default_factory=list)
    last_updated: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_configs (
    org_id          TEXT PRIMARY KEY,
    org_name        TEXT NOT NULL,
    logo_url        TEXT,
    brand_color     TEXT NOT NULL DEFAULT '#0066CC',
    enabled_sections TEXT NOT NULL DEFAULT '["compliance","controls","subprocessors"]',
    custom_message  TEXT,
    contact_email   TEXT
);

CREATE TABLE IF NOT EXISTS trust_badges (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    framework       TEXT NOT NULL,
    status          TEXT NOT NULL,
    certified_date  TEXT,
    auditor         TEXT,
    report_url      TEXT
);
CREATE INDEX IF NOT EXISTS idx_badges_org ON trust_badges (org_id);

CREATE TABLE IF NOT EXISTS trust_controls (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    status      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_controls_org ON trust_controls (org_id);

CREATE TABLE IF NOT EXISTS trust_subprocessors (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    location    TEXT NOT NULL,
    data_types  TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_sub_org ON trust_subprocessors (org_id);
"""


# ---------------------------------------------------------------------------
# TrustCenterManager
# ---------------------------------------------------------------------------


class TrustCenterManager:
    """Thread-safe, SQLite-backed manager for public trust center pages.

    Usage::

        mgr = TrustCenterManager()
        mgr.configure(TrustPageConfig(org_id="acme", org_name="Acme Corp"))
        mgr.add_badge(ComplianceBadge(framework="SOC2", status="certified", org_id="acme"))
        page = mgr.get_public_page("acme")
    """

    _instance: Optional[TrustCenterManager] = None
    _instance_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls, db_path: str | Path = ":memory:") -> TrustCenterManager:
        """Return the process-wide singleton, creating it if needed."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton (useful for tests)."""
        with cls._instance_lock:
            cls._instance = None

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = db_path if isinstance(db_path, Path) else Path(str(db_path))
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if str(self._db_path) == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript(_SCHEMA)
            conn.commit()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def configure(self, config: TrustPageConfig) -> TrustPageConfig:
        """Upsert trust page configuration for an org."""
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO trust_configs
                    (org_id, org_name, logo_url, brand_color, enabled_sections,
                     custom_message, contact_email)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id) DO UPDATE SET
                    org_name        = excluded.org_name,
                    logo_url        = excluded.logo_url,
                    brand_color     = excluded.brand_color,
                    enabled_sections = excluded.enabled_sections,
                    custom_message  = excluded.custom_message,
                    contact_email   = excluded.contact_email
                """,
                (
                    config.org_id,
                    config.org_name,
                    config.logo_url,
                    config.brand_color,
                    json.dumps(config.enabled_sections),
                    config.custom_message,
                    config.contact_email,
                ),
            )
            conn.commit()
        _logger.info("trust_center: configured org=%s", config.org_id)
        return config

    def get_config(self, org_id: str) -> Optional[TrustPageConfig]:
        """Return trust page config for org, or None if not found."""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM trust_configs WHERE org_id = ?", (org_id,)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["enabled_sections"] = json.loads(d.get("enabled_sections") or "[]")
        return TrustPageConfig(**d)

    # ------------------------------------------------------------------
    # Badges
    # ------------------------------------------------------------------

    def add_badge(self, badge: ComplianceBadge, org_id: str) -> ComplianceBadge:
        """Add or upsert a compliance badge for an org."""
        badge = badge.model_copy(update={"org_id": org_id})
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO trust_badges
                    (id, org_id, framework, status, certified_date, auditor, report_url)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    framework      = excluded.framework,
                    status         = excluded.status,
                    certified_date = excluded.certified_date,
                    auditor        = excluded.auditor,
                    report_url     = excluded.report_url
                """,
                (
                    badge.id,
                    badge.org_id,
                    badge.framework,
                    badge.status,
                    badge.certified_date,
                    badge.auditor,
                    badge.report_url,
                ),
            )
            conn.commit()
        return badge

    def list_badges(self, org_id: str) -> List[ComplianceBadge]:
        """List all compliance badges for an org."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM trust_badges WHERE org_id = ? ORDER BY framework",
                (org_id,),
            ).fetchall()
        return [ComplianceBadge(**dict(r)) for r in rows]

    def delete_badge(self, badge_id: str, org_id: str) -> bool:
        """Delete a badge. Returns True if deleted, False if not found."""
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "DELETE FROM trust_badges WHERE id = ? AND org_id = ?",
                (badge_id, org_id),
            )
            conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def add_control(self, control: SecurityControl, org_id: str) -> SecurityControl:
        """Add or upsert a security control for an org."""
        control = control.model_copy(update={"org_id": org_id})
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO trust_controls
                    (id, org_id, category, title, description, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    category    = excluded.category,
                    title       = excluded.title,
                    description = excluded.description,
                    status      = excluded.status
                """,
                (
                    control.id,
                    control.org_id,
                    control.category,
                    control.title,
                    control.description,
                    control.status,
                ),
            )
            conn.commit()
        return control

    def list_controls(self, org_id: str) -> List[SecurityControl]:
        """List all security controls for an org."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM trust_controls WHERE org_id = ? ORDER BY category, title",
                (org_id,),
            ).fetchall()
        return [SecurityControl(**dict(r)) for r in rows]

    def delete_control(self, control_id: str, org_id: str) -> bool:
        """Delete a control. Returns True if deleted, False if not found."""
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "DELETE FROM trust_controls WHERE id = ? AND org_id = ?",
                (control_id, org_id),
            )
            conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Subprocessors
    # ------------------------------------------------------------------

    def add_subprocessor(self, entry: SubprocessorEntry, org_id: str) -> SubprocessorEntry:
        """Add or upsert a sub-processor entry for an org."""
        entry = entry.model_copy(update={"org_id": org_id})
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO trust_subprocessors
                    (id, org_id, name, purpose, location, data_types)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name       = excluded.name,
                    purpose    = excluded.purpose,
                    location   = excluded.location,
                    data_types = excluded.data_types
                """,
                (
                    entry.id,
                    entry.org_id,
                    entry.name,
                    entry.purpose,
                    entry.location,
                    json.dumps(entry.data_types),
                ),
            )
            conn.commit()
        return entry

    def list_subprocessors(self, org_id: str) -> List[SubprocessorEntry]:
        """List all sub-processor entries for an org."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM trust_subprocessors WHERE org_id = ? ORDER BY name",
                (org_id,),
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["data_types"] = json.loads(d.get("data_types") or "[]")
            result.append(SubprocessorEntry(**d))
        return result

    def delete_subprocessor(self, entry_id: str, org_id: str) -> bool:
        """Delete a sub-processor entry. Returns True if deleted."""
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "DELETE FROM trust_subprocessors WHERE id = ? AND org_id = ?",
                (entry_id, org_id),
            )
            conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Public page aggregation
    # ------------------------------------------------------------------

    def get_public_page(self, org_id: str) -> Optional[TrustCenterData]:
        """Return full public trust page data for an org — NO SECRETS.

        Returns None if the org has no trust page configured.
        """
        config = self.get_config(org_id)
        if config is None:
            return None
        return TrustCenterData(
            config=config,
            badges=self.list_badges(org_id),
            controls=self.list_controls(org_id),
            subprocessors=self.list_subprocessors(org_id),
            last_updated=datetime.now(timezone.utc).isoformat(),
        )

    # ------------------------------------------------------------------
    # Reports & stats
    # ------------------------------------------------------------------

    def generate_security_report(self, org_id: str) -> Dict[str, Any]:
        """Generate a downloadable security overview report dict."""
        config = self.get_config(org_id)
        badges = self.list_badges(org_id)
        controls = self.list_controls(org_id)
        subprocessors = self.list_subprocessors(org_id)

        certified = [b for b in badges if b.status == "certified"]
        in_progress = [b for b in badges if b.status == "in_progress"]
        implemented = [c for c in controls if c.status == "implemented"]
        planned = [c for c in controls if c.status == "planned"]

        # Group controls by category
        categories: Dict[str, List[str]] = {}
        for ctrl in controls:
            categories.setdefault(ctrl.category, []).append(ctrl.title)

        return {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "organization": config.org_name if config else org_id,
            "org_id": org_id,
            "compliance_summary": {
                "total_frameworks": len(badges),
                "certified": len(certified),
                "in_progress": len(in_progress),
                "planned": len(badges) - len(certified) - len(in_progress),
                "certifications": [
                    {
                        "framework": b.framework,
                        "status": b.status,
                        "certified_date": b.certified_date,
                        "auditor": b.auditor,
                    }
                    for b in badges
                ],
            },
            "security_controls": {
                "total": len(controls),
                "implemented": len(implemented),
                "planned": len(planned),
                "implementation_rate": (
                    round(len(implemented) / len(controls) * 100, 1) if controls else 0.0
                ),
                "by_category": categories,
            },
            "subprocessors": {
                "total": len(subprocessors),
                "list": [
                    {
                        "name": s.name,
                        "purpose": s.purpose,
                        "location": s.location,
                        "data_types": s.data_types,
                    }
                    for s in subprocessors
                ],
            },
        }

    def get_trust_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics for an org's trust center."""
        badges = self.list_badges(org_id)
        controls = self.list_controls(org_id)
        subprocessors = self.list_subprocessors(org_id)

        implemented = sum(1 for c in controls if c.status == "implemented")
        certified = sum(1 for b in badges if b.status == "certified")

        return {
            "org_id": org_id,
            "badges": {
                "total": len(badges),
                "certified": certified,
                "in_progress": sum(1 for b in badges if b.status == "in_progress"),
                "planned": sum(1 for b in badges if b.status == "planned"),
            },
            "controls": {
                "total": len(controls),
                "implemented": implemented,
                "planned": sum(1 for c in controls if c.status == "planned"),
                "implementation_rate": (
                    round(implemented / len(controls) * 100, 1) if controls else 0.0
                ),
            },
            "subprocessors": {
                "total": len(subprocessors),
            },
            "trust_score": _compute_trust_score(badges, controls),
        }


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _compute_trust_score(
    badges: List[ComplianceBadge], controls: List[SecurityControl]
) -> float:
    """Compute a 0-100 trust score based on certifications and controls."""
    score = 0.0
    # Certifications worth up to 50 points
    if badges:
        cert_ratio = sum(1 for b in badges if b.status == "certified") / len(badges)
        score += cert_ratio * 50
    # Control implementation worth up to 50 points
    if controls:
        impl_ratio = sum(1 for c in controls if c.status == "implemented") / len(controls)
        score += impl_ratio * 50
    return round(score, 1)
