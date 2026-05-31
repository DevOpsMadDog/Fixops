"""
Inventory database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.inventory_models import Application, ApplicationCriticality, ApplicationStatus


class InventoryDB:
    """Database manager for inventory records."""

    def __init__(self, db_path: str = "data/inventory.db"):
        """Initialize database connection."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Initialize database tables."""
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS applications (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    criticality TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owner_team TEXT,
                    repository_url TEXT,
                    environment TEXT NOT NULL,
                    tags TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS services (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    application_id TEXT NOT NULL,
                    description TEXT,
                    version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    endpoint_url TEXT,
                    repository_url TEXT,
                    tags TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (application_id) REFERENCES applications(id)
                );

                CREATE TABLE IF NOT EXISTS api_endpoints (
                    id TEXT PRIMARY KEY,
                    service_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    description TEXT,
                    is_public INTEGER NOT NULL,
                    requires_auth INTEGER NOT NULL,
                    rate_limit INTEGER,
                    tags TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (service_id) REFERENCES services(id)
                );

                CREATE TABLE IF NOT EXISTS components (
                    id TEXT PRIMARY KEY,
                    application_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    type TEXT NOT NULL,
                    license TEXT,
                    source_url TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (application_id) REFERENCES applications(id)
                );

                CREATE INDEX IF NOT EXISTS idx_services_app ON services(application_id);
                CREATE INDEX IF NOT EXISTS idx_api_endpoints_service ON api_endpoints(service_id);
                CREATE INDEX IF NOT EXISTS idx_components_app ON components(application_id);
            """
            )
            conn.commit()
            # Schema migration: ensure org_id column exists, backfill, and index.
            cols = {row[1] for row in conn.execute("PRAGMA table_info(applications)").fetchall()}
            if "org_id" not in cols:
                import logging as _l
                _l.getLogger(__name__).warning(
                    "LEGACY DB DETECTED: applications.org_id missing — adding column and backfilling to 'default'"
                )
                conn.execute("ALTER TABLE applications ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'")
                conn.execute("UPDATE applications SET org_id = 'default' WHERE org_id IS NULL OR org_id = ''")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_applications_org_id ON applications(org_id)")
                conn.commit()
        finally:
            conn.close()

    def create_application(self, app: Application, org_id: str = "default") -> Application:
        """Create new application."""
        if not app.id:
            app.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO applications
                   (id, name, description, criticality, status, owner_team, repository_url,
                    environment, tags, metadata, created_at, updated_at, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    app.id,
                    app.name,
                    app.description,
                    app.criticality.value,
                    app.status.value,
                    app.owner_team,
                    app.repository_url,
                    app.environment,
                    json.dumps(app.tags),
                    json.dumps(app.metadata),
                    app.created_at.isoformat(),
                    app.updated_at.isoformat(),
                    org_id,
                ),
            )
            conn.commit()
            return app
        finally:
            conn.close()

    def get_application(self, app_id: str, org_id: Optional[str] = None) -> Optional[Application]:
        """Get application by ID. If org_id is provided, enforces ownership."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM applications WHERE id = ?", (app_id,)
            ).fetchone()
            if not row:
                return None
            if org_id is not None:
                cols = {r[1] for r in conn.execute("PRAGMA table_info(applications)").fetchall()}
                if "org_id" not in cols:
                    import logging as _l
                    _l.getLogger(__name__).warning(
                        "LEGACY DB DETECTED: applications.org_id missing — returning None for safety"
                    )
                    return None
                if row["org_id"] != org_id:
                    return None
            return self._row_to_application(row)
        finally:
            conn.close()

    def list_applications(self, org_id: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[Application]:
        """List applications with pagination, optionally filtered by org_id."""
        conn = self._get_connection()
        try:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(applications)").fetchall()}
            if org_id is not None and "org_id" in cols:
                rows = conn.execute(
                    "SELECT * FROM applications WHERE org_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (org_id, limit, offset),
                ).fetchall()
            else:
                if org_id is not None and "org_id" not in cols:
                    import logging as _l
                    _l.getLogger(__name__).warning(
                        "LEGACY DB DETECTED: applications.org_id missing — returning empty for safety, run migration"
                    )
                    return []
                rows = conn.execute(
                    "SELECT * FROM applications ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_application(row) for row in rows]
        finally:
            conn.close()

    def update_application(self, app: Application) -> Application:
        """Update application."""
        app.updated_at = datetime.now(timezone.utc)
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE applications SET name=?, description=?, criticality=?,
                   status=?, owner_team=?, repository_url=?, environment=?,
                   tags=?, metadata=?, updated_at=? WHERE id=?""",
                (
                    app.name,
                    app.description,
                    app.criticality.value,
                    app.status.value,
                    app.owner_team,
                    app.repository_url,
                    app.environment,
                    json.dumps(app.tags),
                    json.dumps(app.metadata),
                    app.updated_at.isoformat(),
                    app.id,
                ),
            )
            conn.commit()
            return app
        finally:
            conn.close()

    def delete_application(self, app_id: str) -> bool:
        """Delete application."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM applications WHERE id = ?", (app_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def search_inventory(self, query: str, limit: int = 100) -> Dict[str, List[Dict]]:
        """Search across all inventory types."""
        conn = self._get_connection()
        try:
            search_pattern = f"%{query}%"
            results: Dict[str, List[Dict]] = {
                "applications": [],
                "services": [],
                "apis": [],
                "components": [],
            }

            app_rows = conn.execute(
                """SELECT * FROM applications WHERE name LIKE ? OR description LIKE ?
                   LIMIT ?""",
                (search_pattern, search_pattern, limit),
            ).fetchall()
            results["applications"] = [
                self._row_to_application(row).to_dict() for row in app_rows
            ]

            return results
        finally:
            conn.close()

    def _row_to_application(self, row) -> Application:
        """Convert database row to Application object."""
        return Application(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            criticality=ApplicationCriticality(row["criticality"]),
            status=ApplicationStatus(row["status"]),
            owner_team=row["owner_team"],
            repository_url=row["repository_url"],
            environment=row["environment"],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
