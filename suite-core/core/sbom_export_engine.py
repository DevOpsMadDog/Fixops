"""SBOM Export Engine — ALDECI.

Generates and stores Software Bills of Materials in CycloneDX 1.4 and SPDX 2.3
formats with full multi-tenant isolation.

Capabilities:
  - Component registry with dedup (INSERT OR IGNORE on org+project+name+version)
  - Vulnerability tracking with vuln_count auto-recompute per component
  - CycloneDX 1.4 JSON generation
  - SPDX 2.3 JSON generation
  - Export history tracking
  - Project summary aggregation
  - Org-scoped isolation — org_a data never visible from org_b

Compliance: NTIA SBOM Minimum Elements, CycloneDX 1.4, SPDX 2.3, EO 14028
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "sbom_export.db"
)

_VALID_COMPONENT_TYPES = {
    "library", "framework", "application", "container",
    "device", "firmware", "file", "operating-system",
}
_VALID_ECOSYSTEMS = {
    "npm", "pypi", "maven", "nuget", "cargo", "go", "gem", "composer",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_VALID_FORMATS = {"cyclonedx", "spdx"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SBOMExportEngine:
    """SQLite WAL-backed SBOM Export engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sbom_components (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    project_name      TEXT NOT NULL,
                    component_name    TEXT NOT NULL,
                    component_version TEXT NOT NULL,
                    component_type    TEXT NOT NULL DEFAULT 'library',
                    ecosystem         TEXT NOT NULL DEFAULT '',
                    license           TEXT NOT NULL DEFAULT '',
                    purl              TEXT NOT NULL DEFAULT '',
                    cpe               TEXT NOT NULL DEFAULT '',
                    supplier          TEXT NOT NULL DEFAULT '',
                    hash_sha256       TEXT NOT NULL DEFAULT '',
                    vuln_count        INTEGER NOT NULL DEFAULT 0,
                    created_at        TEXT NOT NULL,
                    UNIQUE(org_id, project_name, component_name, component_version)
                );

                CREATE TABLE IF NOT EXISTS sbom_exports (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    project_name    TEXT NOT NULL,
                    format          TEXT NOT NULL,
                    version_tag     TEXT NOT NULL DEFAULT '1.0',
                    component_count INTEGER NOT NULL DEFAULT 0,
                    generated_at    TEXT NOT NULL,
                    exported_by     TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sbom_vulnerabilities (
                    id               TEXT PRIMARY KEY,
                    component_id     TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    cve_id           TEXT NOT NULL,
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    cvss_score       REAL NOT NULL DEFAULT 0.0,
                    affects_version  TEXT NOT NULL DEFAULT '',
                    fixed_in         TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    def register_component(
        self,
        org_id: str,
        project_name: str,
        component_name: str,
        component_version: str,
        component_type: str,
        ecosystem: str,
        license: str,
        purl: str = "",
        cpe: str = "",
        supplier: str = "",
        hash_sha256: str = "",
    ) -> Dict[str, Any]:
        """Register a component; dedup on (org_id, project_name, name, version)."""
        if component_type not in _VALID_COMPONENT_TYPES:
            raise ValueError(
                f"component_type must be one of: {sorted(_VALID_COMPONENT_TYPES)}"
            )

        comp_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": comp_id,
            "org_id": org_id,
            "project_name": project_name,
            "component_name": component_name,
            "component_version": component_version,
            "component_type": component_type,
            "ecosystem": ecosystem,
            "license": license,
            "purl": purl,
            "cpe": cpe,
            "supplier": supplier,
            "hash_sha256": hash_sha256,
            "vuln_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO sbom_components
                       (id, org_id, project_name, component_name, component_version,
                        component_type, ecosystem, license, purl, cpe, supplier,
                        hash_sha256, vuln_count, created_at)
                       VALUES (:id, :org_id, :project_name, :component_name,
                               :component_version, :component_type, :ecosystem,
                               :license, :purl, :cpe, :supplier, :hash_sha256,
                               :vuln_count, :created_at)""",
                    row,
                )
                # Return existing if already registered
                existing = conn.execute(
                    """SELECT * FROM sbom_components
                       WHERE org_id=? AND project_name=? AND component_name=?
                         AND component_version=?""",
                    (org_id, project_name, component_name, component_version),
                ).fetchone()
        return self._row(existing)

    def list_components(
        self,
        org_id: str,
        project_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List components, optionally filtered by project."""
        sql = "SELECT * FROM sbom_components WHERE org_id = ?"
        params: list = [org_id]
        if project_name is not None:
            sql += " AND project_name = ?"
            params.append(project_name)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_component(self, component_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return a single component or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sbom_components WHERE id = ? AND org_id = ?",
                (component_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    def add_vuln(
        self,
        component_id: str,
        org_id: str,
        cve_id: str,
        severity: str,
        cvss_score: float,
        affects_version: str,
        fixed_in: str = "",
    ) -> Dict[str, Any]:
        """Add a vulnerability to a component and recompute vuln_count."""
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of: {sorted(_VALID_SEVERITIES)}"
            )
        vuln_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": vuln_id,
            "component_id": component_id,
            "org_id": org_id,
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": float(cvss_score),
            "affects_version": affects_version,
            "fixed_in": fixed_in,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sbom_vulnerabilities
                       (id, component_id, org_id, cve_id, severity, cvss_score,
                        affects_version, fixed_in, created_at)
                       VALUES (:id, :component_id, :org_id, :cve_id, :severity,
                               :cvss_score, :affects_version, :fixed_in, :created_at)""",
                    row,
                )
                # Recompute vuln_count for the component
                count_row = conn.execute(
                    "SELECT COUNT(*) as c FROM sbom_vulnerabilities WHERE component_id = ? AND org_id = ?",
                    (component_id, org_id),
                ).fetchone()
                count = count_row["c"] if count_row else 0
                conn.execute(
                    "UPDATE sbom_components SET vuln_count = ? WHERE id = ? AND org_id = ?",
                    (count, component_id, org_id),
                )
        return row

    def list_vulns(self, org_id: str, component_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List vulnerabilities for an org, optionally filtered by component."""
        sql = "SELECT * FROM sbom_vulnerabilities WHERE org_id = ?"
        params: list = [org_id]
        if component_id is not None:
            sql += " AND component_id = ?"
            params.append(component_id)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # CycloneDX Export
    # ------------------------------------------------------------------

    def generate_cyclonedx(
        self,
        org_id: str,
        project_name: str,
        version_tag: str = "1.0",
        exported_by: str = "",
    ) -> Dict[str, Any]:
        """Generate a CycloneDX 1.4 SBOM and record the export."""
        now = _now_iso()
        with self._conn() as conn:
            comps = conn.execute(
                """SELECT * FROM sbom_components
                   WHERE org_id = ? AND project_name = ?
                   ORDER BY component_name""",
                (org_id, project_name),
            ).fetchall()

            comp_ids = [c["id"] for c in comps]
            vulns: list = []
            if comp_ids:
                placeholders = ",".join("?" * len(comp_ids))
                vulns = conn.execute(
                    f"SELECT * FROM sbom_vulnerabilities WHERE component_id IN ({placeholders}) AND org_id = ?",
                    comp_ids + [org_id],
                ).fetchall()

        components_list = []
        for c in comps:
            comp_entry: Dict[str, Any] = {
                "type": c["component_type"],
                "name": c["component_name"],
                "version": c["component_version"],
                "purl": c["purl"],
                "cpe": c["cpe"],
                "licenses": [{"license": {"id": c["license"]}}],
                "supplier": {"name": c["supplier"]},
                "hashes": (
                    [{"alg": "SHA-256", "content": c["hash_sha256"]}]
                    if c["hash_sha256"]
                    else []
                ),
            }
            components_list.append(comp_entry)

        # Build purl lookup for vulnerabilities section
        purl_map = {c["id"]: c["purl"] for c in comps}
        vulnerabilities_list = []
        for v in vulns:
            vuln_entry = {
                "id": v["cve_id"],
                "ratings": [{"severity": v["severity"], "score": v["cvss_score"]}],
                "affects": [{"ref": purl_map.get(v["component_id"], "")}],
            }
            vulnerabilities_list.append(vuln_entry)

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": now,
                "component": {
                    "name": project_name,
                    "version": version_tag,
                },
            },
            "components": components_list,
            "vulnerabilities": vulnerabilities_list,
        }

        # Record the export
        export_id = str(uuid.uuid4())
        export_row = {
            "id": export_id,
            "org_id": org_id,
            "project_name": project_name,
            "format": "cyclonedx",
            "version_tag": version_tag,
            "component_count": len(comps),
            "generated_at": now,
            "exported_by": exported_by,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sbom_exports
                       (id, org_id, project_name, format, version_tag,
                        component_count, generated_at, exported_by, created_at)
                       VALUES (:id, :org_id, :project_name, :format, :version_tag,
                               :component_count, :generated_at, :exported_by, :created_at)""",
                    export_row,
                )

        bom["_export_id"] = export_id
        return bom

    # ------------------------------------------------------------------
    # SPDX Export
    # ------------------------------------------------------------------

    def generate_spdx(
        self,
        org_id: str,
        project_name: str,
        version_tag: str = "1.0",
        exported_by: str = "",
    ) -> Dict[str, Any]:
        """Generate an SPDX 2.3 SBOM and record the export."""
        now = _now_iso()
        with self._conn() as conn:
            comps = conn.execute(
                """SELECT * FROM sbom_components
                   WHERE org_id = ? AND project_name = ?
                   ORDER BY component_name""",
                (org_id, project_name),
            ).fetchall()

        packages_list = []
        for c in comps:
            pkg: Dict[str, Any] = {
                "SPDXID": f"SPDXRef-{c['component_name']}-{c['component_version']}",
                "name": c["component_name"],
                "versionInfo": c["component_version"],
                "licenseConcluded": c["license"],
                "supplier": (
                    f"Organization: {c['supplier']}"
                    if c["supplier"]
                    else "NOASSERTION"
                ),
                "externalRefs": (
                    [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": c["purl"],
                        }
                    ]
                    if c["purl"]
                    else []
                ),
            }
            packages_list.append(pkg)

        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": project_name,
            "documentNamespace": f"https://aldeci.io/sbom/{project_name}/{version_tag}",
            "packages": packages_list,
        }

        # Record the export
        export_id = str(uuid.uuid4())
        export_row = {
            "id": export_id,
            "org_id": org_id,
            "project_name": project_name,
            "format": "spdx",
            "version_tag": version_tag,
            "component_count": len(comps),
            "generated_at": now,
            "exported_by": exported_by,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sbom_exports
                       (id, org_id, project_name, format, version_tag,
                        component_count, generated_at, exported_by, created_at)
                       VALUES (:id, :org_id, :project_name, :format, :version_tag,
                               :component_count, :generated_at, :exported_by, :created_at)""",
                    export_row,
                )

        spdx_doc["_export_id"] = export_id
        return spdx_doc

    # ------------------------------------------------------------------
    # Summary & Analytics
    # ------------------------------------------------------------------

    def get_project_summary(self, org_id: str, project_name: str) -> Dict[str, Any]:
        """Return aggregated summary for a project."""
        with self._conn() as conn:
            comp_row = conn.execute(
                """SELECT COUNT(*) as component_count,
                          SUM(vuln_count) as total_vulns
                   FROM sbom_components
                   WHERE org_id = ? AND project_name = ?""",
                (org_id, project_name),
            ).fetchone()

            # Critical vulns
            critical_row = conn.execute(
                """SELECT COUNT(*) as c FROM sbom_vulnerabilities v
                   JOIN sbom_components c ON v.component_id = c.id
                   WHERE c.org_id = ? AND c.project_name = ? AND v.severity = 'critical'""",
                (org_id, project_name),
            ).fetchone()

            # By ecosystem
            eco_rows = conn.execute(
                """SELECT ecosystem, COUNT(*) as cnt
                   FROM sbom_components
                   WHERE org_id = ? AND project_name = ? AND ecosystem != ''
                   GROUP BY ecosystem""",
                (org_id, project_name),
            ).fetchall()

            # By license
            lic_rows = conn.execute(
                """SELECT license, COUNT(*) as cnt
                   FROM sbom_components
                   WHERE org_id = ? AND project_name = ? AND license != ''
                   GROUP BY license""",
                (org_id, project_name),
            ).fetchall()

            # Latest export
            export_row = conn.execute(
                """SELECT * FROM sbom_exports
                   WHERE org_id = ? AND project_name = ?
                   ORDER BY generated_at DESC LIMIT 1""",
                (org_id, project_name),
            ).fetchone()

        return {
            "project_name": project_name,
            "org_id": org_id,
            "component_count": comp_row["component_count"] if comp_row else 0,
            "total_vulns": comp_row["total_vulns"] or 0 if comp_row else 0,
            "critical_vulns": critical_row["c"] if critical_row else 0,
            "by_ecosystem": {r["ecosystem"]: r["cnt"] for r in eco_rows},
            "by_license": {r["license"]: r["cnt"] for r in lic_rows},
            "latest_export": self._row(export_row) if export_row else None,
        }

    def list_projects(self, org_id: str) -> List[Dict[str, Any]]:
        """Return distinct projects with component counts."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT project_name, COUNT(*) as component_count
                   FROM sbom_components
                   WHERE org_id = ?
                   GROUP BY project_name
                   ORDER BY project_name""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_export_history(self, org_id: str, project_name: str) -> List[Dict[str, Any]]:
        """Return export records ordered by generated_at DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM sbom_exports
                   WHERE org_id = ? AND project_name = ?
                   ORDER BY generated_at DESC""",
                (org_id, project_name),
            ).fetchall()
        return [self._row(r) for r in rows]

    def search_component(self, org_id: str, query: str) -> List[Dict[str, Any]]:
        """Search components by name or purl."""
        like = f"%{query}%"
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM sbom_components
                   WHERE org_id = ? AND (component_name LIKE ? OR purl LIKE ?)
                   ORDER BY component_name""",
                (org_id, like, like),
            ).fetchall()
        return [self._row(r) for r in rows]
