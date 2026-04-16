"""
TrustGraph Migration Adapter for ALDECI.

Migrates SQLite data from existing ALDECI modules into TrustGraph Knowledge Cores:
  Core 1 — Customer Environment Core  : assets
  Core 2 — Threat Intelligence Core   : findings, threat actors
  Core 3 — Compliance & Regulatory    : compliance controls
  Core 4 — Decision Memory Core       : incidents
  Core 5 — Competitive Intelligence   : vendors (external intel)

Usage:
    migrator = TrustGraphMigrator()
    status = migrator.migrate_all("org_acme")
    report = migrator.verify_migration("org_acme")
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph core-ID mapping
# ---------------------------------------------------------------------------
CORE_CUSTOMER_ENV   = 1   # assets, configurations, topology
CORE_THREAT_INTEL   = 2   # CVEs, findings, threat actors, IOCs
CORE_COMPLIANCE     = 3   # frameworks, controls, evidence
CORE_DECISION_MEM   = 4   # incidents, verdicts, overrides
CORE_EXTERNAL       = 5   # vendors, competitive intel

# Module names used as keys in status tracking
_MODULES = [
    "findings",
    "assets",
    "incidents",
    "compliance",
    "vendors",
    "threat_actors",
]

# ---------------------------------------------------------------------------
# Default DB paths (env-overridable)
# ---------------------------------------------------------------------------
_FINDING_DB    = os.getenv("FIXOPS_FINDING_DB",     "data/finding_correlator.db")
_ASSET_DB      = os.getenv("FIXOPS_ASSET_DB",       ".fixops_data/asset_inventory.db")
_INCIDENT_DB   = os.getenv("FIXOPS_INCIDENT_DB",    "data/incident_response.db")
_COMPLIANCE_DB = os.getenv("FIXOPS_COMPLIANCE_DB",  "data/audit.db")
_VENDOR_DB     = os.getenv("FIXOPS_VENDOR_DB",      "data/vendor_scorecard.db")
_THREAT_DB     = os.getenv("FIXOPS_THREAT_DB",      ":memory:")


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class MigrationStatus(BaseModel):
    """Per-module migration status record."""

    module_name: str
    records_migrated: int = 0
    records_failed: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending | running | completed | failed | rolled_back
    error: Optional[str] = None


class MigrationReport(BaseModel):
    """Full migration report for an org."""

    org_id: str
    modules: List[MigrationStatus] = Field(default_factory=list)
    total_migrated: int = 0
    total_failed: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    overall_status: str = "pending"


class VerificationReport(BaseModel):
    """Compare SQLite counts vs TrustGraph counts."""

    org_id: str
    modules: List[Dict[str, Any]] = Field(default_factory=list)
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    all_match: bool = False


# ---------------------------------------------------------------------------
# Internal state store (in-memory, keyed by org_id + module)
# ---------------------------------------------------------------------------
_STATUS_STORE: Dict[str, Dict[str, MigrationStatus]] = {}


def _get_status(org_id: str) -> Dict[str, MigrationStatus]:
    if org_id not in _STATUS_STORE:
        _STATUS_STORE[org_id] = {
            m: MigrationStatus(module_name=m) for m in _MODULES
        }
    return _STATUS_STORE[org_id]


def _set_status(org_id: str, module: str, status: MigrationStatus) -> None:
    _get_status(org_id)[module] = status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_db(path: str) -> Optional[sqlite3.Connection]:
    """Open SQLite DB; return None if file doesn't exist."""
    if path == ":memory:":
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        return conn
    p = Path(path)
    if not p.exists():
        return None
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    return conn


def _count_sqlite(conn: sqlite3.Connection, table: str, org_id: Optional[str] = None) -> int:
    """Count rows in a SQLite table, optionally filtered by org_id."""
    try:
        cur = conn.cursor()
        if org_id:
            cur.execute(f"SELECT COUNT(*) FROM {table} WHERE org_id = ?", (org_id,))  # nosemgrep: formatted-sql-query  # nosec B608
        else:
            cur.execute(f"SELECT COUNT(*) FROM {table}")  # nosemgrep: formatted-sql-query  # nosec B608
        return cur.fetchone()[0]
    except Exception:
        return 0


def _make_entity_id(prefix: str, raw_id: str) -> str:
    return f"{prefix}_{raw_id}".replace("-", "_")


# ---------------------------------------------------------------------------
# TrustGraphMigrator
# ---------------------------------------------------------------------------

class TrustGraphMigrator:
    """Migrate ALDECI SQLite data into TrustGraph Knowledge Cores.

    Args:
        knowledge_store: Optional KnowledgeStore instance. If not provided,
            the global singleton from trustgraph package is used.
        finding_db: Path to finding_correlator SQLite DB.
        asset_db: Path to asset_inventory SQLite DB.
        incident_db: Path to incident_response SQLite DB.
        compliance_db: Path to audit SQLite DB.
        vendor_db: Path to vendor_scorecard SQLite DB.
        threat_db: Path to threat_intel_correlator SQLite DB.
    """

    def __init__(
        self,
        knowledge_store=None,
        finding_db: str = _FINDING_DB,
        asset_db: str = _ASSET_DB,
        incident_db: str = _INCIDENT_DB,
        compliance_db: str = _COMPLIANCE_DB,
        vendor_db: str = _VENDOR_DB,
        threat_db: str = _THREAT_DB,
    ) -> None:
        if knowledge_store is None:
            from trustgraph import get_knowledge_store
            knowledge_store = get_knowledge_store()
        self._store = knowledge_store
        self._finding_db = finding_db
        self._asset_db = asset_db
        self._incident_db = incident_db
        self._compliance_db = compliance_db
        self._vendor_db = vendor_db
        self._threat_db = threat_db

    # ------------------------------------------------------------------
    # Public migrate methods
    # ------------------------------------------------------------------

    def migrate_findings(self, org_id: str) -> MigrationStatus:
        """Read exposure_cases from finding_correlator.db → Core 2 (Threat Intel).

        Each ExposureCase becomes a 'Finding' entity in TrustGraph.
        """
        status = MigrationStatus(
            module_name="findings",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        _set_status(org_id, "findings", status)

        conn = _open_db(self._finding_db)
        if conn is None:
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)
            status.records_migrated = 0
            _set_status(org_id, "findings", status)
            return status

        try:
            from trustgraph.knowledge_store import KnowledgeEntity

            cur = conn.cursor()
            try:
                cur.execute("SELECT * FROM exposure_cases WHERE org_id = ?", (org_id,))
            except sqlite3.OperationalError:
                cur.execute("SELECT * FROM exposure_cases")

            rows = cur.fetchall()
            migrated = 0
            failed = 0

            for row in rows:
                try:
                    row_dict = dict(row)
                    entity = KnowledgeEntity(
                        entity_id=_make_entity_id("finding", row_dict.get("id", str(uuid.uuid4()))),
                        core_id=CORE_THREAT_INTEL,
                        entity_type="Finding",
                        name=row_dict.get("title", f"Finding {row_dict.get('id', '')}"),
                        properties={
                            "severity": row_dict.get("severity", "unknown"),
                            "risk_score": row_dict.get("risk_score", 0.0),
                            "status": row_dict.get("status", "open"),
                            "created_at": row_dict.get("created_at", ""),
                            "source_id": row_dict.get("id", ""),
                        },
                        org_id=org_id,
                    )
                    self._store.ingest(entity)
                    migrated += 1
                except Exception as exc:
                    logger.warning("Failed to migrate finding row: %s", exc)
                    failed += 1

            status.records_migrated = migrated
            status.records_failed = failed
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error("migrate_findings error: %s", exc)
            status.status = "failed"
            status.error = str(exc)
            status.completed_at = datetime.now(timezone.utc)
        finally:
            conn.close()

        _set_status(org_id, "findings", status)
        return status

    def migrate_assets(self, org_id: str) -> MigrationStatus:
        """Read managed_assets from asset_inventory.db → Core 1 (Customer Env).

        Each ManagedAsset becomes an entity of its asset_type in TrustGraph.
        """
        status = MigrationStatus(
            module_name="assets",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        _set_status(org_id, "assets", status)

        conn = _open_db(self._asset_db)
        if conn is None:
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)
            _set_status(org_id, "assets", status)
            return status

        try:
            from trustgraph.knowledge_store import KnowledgeEntity

            cur = conn.cursor()
            cur.execute("SELECT * FROM managed_assets WHERE org_id = ?", (org_id,))
            rows = cur.fetchall()
            migrated = 0
            failed = 0

            for row in rows:
                try:
                    row_dict = dict(row)
                    tags_raw = row_dict.get("tags", "[]")
                    try:
                        tags = json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw
                    except Exception:
                        tags = []

                    entity = KnowledgeEntity(
                        entity_id=_make_entity_id("asset", row_dict.get("id", str(uuid.uuid4()))),
                        core_id=CORE_CUSTOMER_ENV,
                        entity_type=row_dict.get("asset_type", "Host"),
                        name=row_dict.get("name", f"Asset {row_dict.get('id', '')}"),
                        properties={
                            "hostname": row_dict.get("hostname", ""),
                            "ip_address": row_dict.get("ip_address", ""),
                            "criticality": row_dict.get("criticality", "medium"),
                            "lifecycle": row_dict.get("lifecycle", "active"),
                            "environment": row_dict.get("environment", "production"),
                            "owner_email": row_dict.get("owner_email", ""),
                            "tags": tags,
                            "source_id": row_dict.get("id", ""),
                        },
                        org_id=org_id,
                    )
                    self._store.ingest(entity)
                    migrated += 1
                except Exception as exc:
                    logger.warning("Failed to migrate asset row: %s", exc)
                    failed += 1

            status.records_migrated = migrated
            status.records_failed = failed
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error("migrate_assets error: %s", exc)
            status.status = "failed"
            status.error = str(exc)
            status.completed_at = datetime.now(timezone.utc)
        finally:
            conn.close()

        _set_status(org_id, "assets", status)
        return status

    def migrate_incidents(self, org_id: str) -> MigrationStatus:
        """Read incidents from incident_response.db → Core 4 (Decision Memory).

        Each Incident becomes a 'Decision' entity capturing the response record.
        """
        status = MigrationStatus(
            module_name="incidents",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        _set_status(org_id, "incidents", status)

        conn = _open_db(self._incident_db)
        if conn is None:
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)
            _set_status(org_id, "incidents", status)
            return status

        try:
            from trustgraph.knowledge_store import KnowledgeEntity

            cur = conn.cursor()
            try:
                cur.execute("SELECT * FROM incidents WHERE org_id = ?", (org_id,))
            except sqlite3.OperationalError:
                cur.execute("SELECT * FROM incidents")

            rows = cur.fetchall()
            migrated = 0
            failed = 0

            for row in rows:
                try:
                    row_dict = dict(row)
                    entity = KnowledgeEntity(
                        entity_id=_make_entity_id("incident", row_dict.get("id", str(uuid.uuid4()))),
                        core_id=CORE_DECISION_MEM,
                        entity_type="Decision",
                        name=row_dict.get("title", f"Incident {row_dict.get('id', '')}"),
                        properties={
                            "incident_type": row_dict.get("type", "unknown"),
                            "severity": row_dict.get("severity", "sev3"),
                            "status": row_dict.get("status", "detected"),
                            "detected_at": row_dict.get("detected_at", ""),
                            "resolved_at": row_dict.get("resolved_at", ""),
                            "source_id": row_dict.get("id", ""),
                        },
                        org_id=org_id,
                    )
                    self._store.ingest(entity)
                    migrated += 1
                except Exception as exc:
                    logger.warning("Failed to migrate incident row: %s", exc)
                    failed += 1

            status.records_migrated = migrated
            status.records_failed = failed
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error("migrate_incidents error: %s", exc)
            status.status = "failed"
            status.error = str(exc)
            status.completed_at = datetime.now(timezone.utc)
        finally:
            conn.close()

        _set_status(org_id, "incidents", status)
        return status

    def migrate_compliance(self, org_id: str) -> MigrationStatus:
        """Read compliance_controls from audit.db → Core 3 (Compliance).

        Each control becomes a 'Control' entity in TrustGraph.
        """
        status = MigrationStatus(
            module_name="compliance",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        _set_status(org_id, "compliance", status)

        conn = _open_db(self._compliance_db)
        if conn is None:
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)
            _set_status(org_id, "compliance", status)
            return status

        try:
            from trustgraph.knowledge_store import KnowledgeEntity

            cur = conn.cursor()
            cur.execute("SELECT * FROM compliance_controls")
            rows = cur.fetchall()
            migrated = 0
            failed = 0

            for row in rows:
                try:
                    row_dict = dict(row)
                    entity = KnowledgeEntity(
                        entity_id=_make_entity_id("ctrl", row_dict.get("id", str(uuid.uuid4()))),
                        core_id=CORE_COMPLIANCE,
                        entity_type="Control",
                        name=row_dict.get("name", f"Control {row_dict.get('control_id', '')}"),
                        properties={
                            "control_id": row_dict.get("control_id", ""),
                            "framework_id": row_dict.get("framework_id", ""),
                            "category": row_dict.get("category", ""),
                            "description": row_dict.get("description", ""),
                            "source_id": row_dict.get("id", ""),
                        },
                        org_id=org_id,
                    )
                    self._store.ingest(entity)
                    migrated += 1
                except Exception as exc:
                    logger.warning("Failed to migrate compliance row: %s", exc)
                    failed += 1

            status.records_migrated = migrated
            status.records_failed = failed
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error("migrate_compliance error: %s", exc)
            status.status = "failed"
            status.error = str(exc)
            status.completed_at = datetime.now(timezone.utc)
        finally:
            conn.close()

        _set_status(org_id, "compliance", status)
        return status

    def migrate_vendors(self, org_id: str) -> MigrationStatus:
        """Read vendors from vendor_scorecard.db → Core 5 (External / Competitive).

        Each Vendor becomes an entity in TrustGraph.
        """
        status = MigrationStatus(
            module_name="vendors",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        _set_status(org_id, "vendors", status)

        conn = _open_db(self._vendor_db)
        if conn is None:
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)
            _set_status(org_id, "vendors", status)
            return status

        try:
            from trustgraph.knowledge_store import KnowledgeEntity

            cur = conn.cursor()
            cur.execute("SELECT * FROM vendors WHERE org_id = ?", (org_id,))
            rows = cur.fetchall()
            migrated = 0
            failed = 0

            for row in rows:
                try:
                    row_dict = dict(row)
                    tags_raw = row_dict.get("tags", "[]")
                    try:
                        tags = json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw
                    except Exception:
                        tags = []

                    entity = KnowledgeEntity(
                        entity_id=_make_entity_id("vendor", row_dict.get("id", str(uuid.uuid4()))),
                        core_id=CORE_EXTERNAL,
                        entity_type="Competitor",
                        name=row_dict.get("name", f"Vendor {row_dict.get('id', '')}"),
                        properties={
                            "domain": row_dict.get("domain", ""),
                            "risk_tier": row_dict.get("tier", "medium"),
                            "description": row_dict.get("description", ""),
                            "contact_email": row_dict.get("contact_email", ""),
                            "sbom_component_count": row_dict.get("sbom_component_count", 0),
                            "tags": tags,
                            "source_id": row_dict.get("id", ""),
                        },
                        org_id=org_id,
                    )
                    self._store.ingest(entity)
                    migrated += 1
                except Exception as exc:
                    logger.warning("Failed to migrate vendor row: %s", exc)
                    failed += 1

            status.records_migrated = migrated
            status.records_failed = failed
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error("migrate_vendors error: %s", exc)
            status.status = "failed"
            status.error = str(exc)
            status.completed_at = datetime.now(timezone.utc)
        finally:
            conn.close()

        _set_status(org_id, "vendors", status)
        return status

    def migrate_threat_actors(self, org_id: str) -> MigrationStatus:
        """Read threat_actors from threat_intel_correlator.db → Core 2 (Threat Intel).

        Each ThreatActor becomes a 'Threat' entity in TrustGraph.
        """
        status = MigrationStatus(
            module_name="threat_actors",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        _set_status(org_id, "threat_actors", status)

        conn = _open_db(self._threat_db)
        if conn is None:
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)
            _set_status(org_id, "threat_actors", status)
            return status

        try:
            from trustgraph.knowledge_store import KnowledgeEntity

            cur = conn.cursor()
            try:
                cur.execute("SELECT * FROM threat_actors WHERE active = 1")
            except sqlite3.OperationalError:
                cur.execute("SELECT * FROM threat_actors")

            rows = cur.fetchall()
            migrated = 0
            failed = 0

            for row in rows:
                try:
                    row_dict = dict(row)
                    ttps_raw = row_dict.get("ttps", "[]")
                    try:
                        ttps = json.loads(ttps_raw) if isinstance(ttps_raw, str) else ttps_raw
                    except Exception:
                        ttps = []

                    aliases_raw = row_dict.get("aliases", "[]")
                    try:
                        aliases = json.loads(aliases_raw) if isinstance(aliases_raw, str) else aliases_raw
                    except Exception:
                        aliases = []

                    entity = KnowledgeEntity(
                        entity_id=_make_entity_id("actor", row_dict.get("id", str(uuid.uuid4()))),
                        core_id=CORE_THREAT_INTEL,
                        entity_type="Threat",
                        name=row_dict.get("name", f"Actor {row_dict.get('id', '')}"),
                        properties={
                            "aliases": aliases,
                            "ttps": ttps,
                            "motivation": row_dict.get("motivation", "unknown"),
                            "origin_country": row_dict.get("origin_country", ""),
                            "active": bool(row_dict.get("active", True)),
                            "source_id": row_dict.get("id", ""),
                        },
                        org_id=org_id,
                    )
                    self._store.ingest(entity)
                    migrated += 1
                except Exception as exc:
                    logger.warning("Failed to migrate threat_actor row: %s", exc)
                    failed += 1

            status.records_migrated = migrated
            status.records_failed = failed
            status.status = "completed"
            status.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error("migrate_threat_actors error: %s", exc)
            status.status = "failed"
            status.error = str(exc)
            status.completed_at = datetime.now(timezone.utc)
        finally:
            conn.close()

        _set_status(org_id, "threat_actors", status)
        return status

    # ------------------------------------------------------------------
    # migrate_all
    # ------------------------------------------------------------------

    def migrate_all(self, org_id: str) -> MigrationReport:
        """Run all 6 migrations sequentially.

        Returns a MigrationReport summarising results per module.
        """
        report = MigrationReport(
            org_id=org_id,
            started_at=datetime.now(timezone.utc),
            overall_status="running",
        )

        migrate_fns = [
            self.migrate_findings,
            self.migrate_assets,
            self.migrate_incidents,
            self.migrate_compliance,
            self.migrate_vendors,
            self.migrate_threat_actors,
        ]

        for fn in migrate_fns:
            s = fn(org_id)
            report.modules.append(s)
            report.total_migrated += s.records_migrated
            report.total_failed += s.records_failed

        failed_count = sum(1 for m in report.modules if m.status == "failed")
        if failed_count == 0:
            report.overall_status = "completed"
        elif failed_count < len(report.modules):
            report.overall_status = "partial"
        else:
            report.overall_status = "failed"

        report.completed_at = datetime.now(timezone.utc)
        return report

    # ------------------------------------------------------------------
    # Status / verify / rollback
    # ------------------------------------------------------------------

    def get_migration_status(self, org_id: str) -> List[MigrationStatus]:
        """Return per-module migration status for the given org."""
        return list(_get_status(org_id).values())

    def rollback_migration(self, org_id: str, module: str) -> MigrationStatus:
        """Undo a migration by soft-deleting TrustGraph entities for the module.

        Removes all entities in TrustGraph that were tagged with source module
        equal to *module* for *org_id*.  Updates the module status to
        'rolled_back'.

        Args:
            org_id: Organisation ID.
            module: One of findings, assets, incidents, compliance, vendors, threat_actors.

        Returns:
            Updated MigrationStatus with status='rolled_back'.
        """
        current = _get_status(org_id).get(module)
        if current is None:
            current = MigrationStatus(module_name=module)

        # Map module -> (core_id, entity_type)
        _MODULE_CORE_MAP: Dict[str, tuple] = {
            "findings":      (CORE_THREAT_INTEL,  "Finding"),
            "assets":        (CORE_CUSTOMER_ENV,  None),      # any type
            "incidents":     (CORE_DECISION_MEM,  "Decision"),
            "compliance":    (CORE_COMPLIANCE,    "Control"),
            "vendors":       (CORE_EXTERNAL,      "Competitor"),
            "threat_actors": (CORE_THREAT_INTEL,  "Threat"),
        }

        if module not in _MODULE_CORE_MAP:
            current.status = "failed"
            current.error = f"Unknown module: {module}"
            _set_status(org_id, module, current)
            return current

        core_id, entity_type = _MODULE_CORE_MAP[module]

        try:
            # Query entities for this org + core + type via store's underlying DB
            conn = self._store._get_conn()
            cur = conn.cursor()

            if entity_type:
                cur.execute(
                    "SELECT entity_id FROM entities WHERE org_id = ? AND core_id = ? AND entity_type = ? AND deleted_at IS NULL",
                    (org_id, core_id, entity_type),
                )
            else:
                cur.execute(
                    "SELECT entity_id FROM entities WHERE org_id = ? AND core_id = ? AND deleted_at IS NULL",
                    (org_id, core_id),
                )

            entity_ids = [row[0] for row in cur.fetchall()]

            for eid in entity_ids:
                self._store.delete_entity(eid)

            current.status = "rolled_back"
            current.completed_at = datetime.now(timezone.utc)
            current.error = None

            logger.info(
                "Rolled back %d entities for org=%s module=%s",
                len(entity_ids), org_id, module,
            )

        except Exception as exc:
            logger.error("rollback_migration error: %s", exc)
            current.status = "failed"
            current.error = str(exc)
            current.completed_at = datetime.now(timezone.utc)

        _set_status(org_id, module, current)
        return current

    def verify_migration(self, org_id: str) -> VerificationReport:
        """Compare SQLite record counts vs TrustGraph entity counts per module.

        Returns a VerificationReport where all_match=True if every module's
        counts agree (or both are zero).
        """
        report = VerificationReport(org_id=org_id)
        all_match = True

        checks = [
            {
                "module": "findings",
                "sqlite_db": self._finding_db,
                "sqlite_table": "exposure_cases",
                "sqlite_org_col": True,
                "core_id": CORE_THREAT_INTEL,
                "entity_type": "Finding",
            },
            {
                "module": "assets",
                "sqlite_db": self._asset_db,
                "sqlite_table": "managed_assets",
                "sqlite_org_col": True,
                "core_id": CORE_CUSTOMER_ENV,
                "entity_type": None,
            },
            {
                "module": "incidents",
                "sqlite_db": self._incident_db,
                "sqlite_table": "incidents",
                "sqlite_org_col": False,
                "core_id": CORE_DECISION_MEM,
                "entity_type": "Decision",
            },
            {
                "module": "compliance",
                "sqlite_db": self._compliance_db,
                "sqlite_table": "compliance_controls",
                "sqlite_org_col": False,
                "core_id": CORE_COMPLIANCE,
                "entity_type": "Control",
            },
            {
                "module": "vendors",
                "sqlite_db": self._vendor_db,
                "sqlite_table": "vendors",
                "sqlite_org_col": True,
                "core_id": CORE_EXTERNAL,
                "entity_type": "Competitor",
            },
            {
                "module": "threat_actors",
                "sqlite_db": self._threat_db,
                "sqlite_table": "threat_actors",
                "sqlite_org_col": False,
                "core_id": CORE_THREAT_INTEL,
                "entity_type": "Threat",
            },
        ]

        tg_conn = self._store._get_conn()
        tg_cur = tg_conn.cursor()

        for check in checks:
            sqlite_count = 0
            src_conn = _open_db(check["sqlite_db"])
            if src_conn is not None:
                try:
                    org_filter = org_id if check["sqlite_org_col"] else None
                    sqlite_count = _count_sqlite(src_conn, check["sqlite_table"], org_filter)
                except Exception:
                    sqlite_count = -1
                finally:
                    src_conn.close()

            # Count in TrustGraph
            try:
                if check["entity_type"]:
                    tg_cur.execute(
                        "SELECT COUNT(*) FROM entities WHERE org_id = ? AND core_id = ? AND entity_type = ? AND deleted_at IS NULL",
                        (org_id, check["core_id"], check["entity_type"]),
                    )
                else:
                    tg_cur.execute(
                        "SELECT COUNT(*) FROM entities WHERE org_id = ? AND core_id = ? AND deleted_at IS NULL",
                        (org_id, check["core_id"]),
                    )
                tg_count = tg_cur.fetchone()[0]
            except Exception:
                tg_count = -1

            match = sqlite_count == tg_count
            if not match:
                all_match = False

            report.modules.append(
                {
                    "module": check["module"],
                    "sqlite_count": sqlite_count,
                    "trustgraph_count": tg_count,
                    "match": match,
                }
            )

        report.all_match = all_match
        return report
