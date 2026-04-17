"""Security Dependency Risk Engine — ALDECI.

Software dependency risk tracking: transitive vulnerabilities, license conflicts.

Capabilities:
  - Register direct and transitive dependencies per org
  - Add CVE vulnerabilities to dependencies with auto risk_score recomputation
  - Patch vulnerabilities and recompute risk
  - Flag license risks (copyleft, commercial restrictions)
  - Detect license conflicts, build transitive graph

Compliance: NIST SP 800-161, CISA SBOM guidance, OWASP Dependency-Check
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_dependency_risk.db"
)

_VALID_ECOSYSTEMS = {
    "npm", "pypi", "maven", "nuget", "cargo", "go", "gem", "composer", "hex"
}
_VALID_LICENSE_RISK_LEVELS = {"low", "medium", "high", "critical"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityDependencyRiskEngine:
    """SQLite WAL-backed Software Dependency Risk engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_dependency_risk.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dependencies (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    package_name        TEXT NOT NULL,
                    version             TEXT NOT NULL,
                    ecosystem           TEXT NOT NULL DEFAULT 'npm',
                    license             TEXT NOT NULL DEFAULT '',
                    direct              INTEGER NOT NULL DEFAULT 1,
                    depth               INTEGER NOT NULL DEFAULT 0,
                    parent_package      TEXT NOT NULL DEFAULT '',
                    risk_score          REAL NOT NULL DEFAULT 0.0,
                    vuln_count          INTEGER NOT NULL DEFAULT 0,
                    critical_vuln_count INTEGER NOT NULL DEFAULT 0,
                    status              TEXT NOT NULL DEFAULT 'active',
                    created_at          TEXT NOT NULL,
                    UNIQUE(org_id, package_name, version)
                );

                CREATE TABLE IF NOT EXISTS dependency_vulns (
                    id              TEXT PRIMARY KEY,
                    dependency_id   TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    cve_id          TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    cvss_score      REAL NOT NULL DEFAULT 0.0,
                    fixed_version   TEXT NOT NULL DEFAULT '',
                    patched         INTEGER NOT NULL DEFAULT 0,
                    detected_at     TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS license_risks (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    license_name            TEXT NOT NULL,
                    risk_level              TEXT NOT NULL DEFAULT 'low',
                    copyleft                INTEGER NOT NULL DEFAULT 0,
                    commercial_use_allowed  INTEGER NOT NULL DEFAULT 1,
                    notes                   TEXT NOT NULL DEFAULT '',
                    created_at              TEXT NOT NULL,
                    UNIQUE(org_id, license_name)
                );
                """
            )

    def _recompute_risk_score(self, conn, dependency_id: str, org_id: str) -> None:
        """Recompute risk_score, vuln_count, critical_vuln_count for a dependency."""
        rows = conn.execute(
            """SELECT severity, cvss_score FROM dependency_vulns
               WHERE dependency_id=? AND org_id=? AND patched=0""",
            (dependency_id, org_id),
        ).fetchall()

        vuln_count_total = conn.execute(
            "SELECT COUNT(*) FROM dependency_vulns WHERE dependency_id=? AND org_id=?",
            (dependency_id, org_id),
        ).fetchone()[0]

        unpatched = [r for r in rows]
        unpatched_count = len(unpatched)
        critical_count = sum(1 for r in unpatched if r["severity"] == "critical")

        if unpatched_count == 0:
            risk_score = 0.0
        else:
            avg_cvss = sum(r["cvss_score"] for r in unpatched) / unpatched_count
            risk_score = min(10.0, avg_cvss + critical_count * 0.5)

        conn.execute(
            """UPDATE dependencies
               SET vuln_count=?, critical_vuln_count=?, risk_score=?
               WHERE id=? AND org_id=?""",
            (vuln_count_total, critical_count, risk_score, dependency_id, org_id),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_dependency(
        self,
        org_id: str,
        package_name: str,
        version: str,
        ecosystem: str,
        license: str,
        direct: bool = True,
        depth: int = 0,
        parent_package: str = "",
    ) -> Dict[str, Any]:
        """Register a dependency (INSERT OR IGNORE on org+package+version)."""
        ecosystem = ecosystem if ecosystem in _VALID_ECOSYSTEMS else "npm"
        now = _now_iso()
        dep_id = str(uuid.uuid4())

        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO dependencies
                   (id, org_id, package_name, version, ecosystem, license,
                    direct, depth, parent_package, risk_score, vuln_count,
                    critical_vuln_count, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,0.0,0,0,'active',?)""",
                (dep_id, org_id, package_name, version, ecosystem,
                 license, 1 if direct else 0, depth, parent_package, now),
            )
            row = conn.execute(
                "SELECT * FROM dependencies WHERE org_id=? AND package_name=? AND version=?",
                (org_id, package_name, version),
            ).fetchone()
            if _get_tg_bus:
                try:
                    bus = _get_tg_bus()
                    if bus and getattr(bus, "enabled", False):
                        bus.emit("RISK_ASSESSED", {"entity_type": "security_dependency_risk_engine", "org_id": org_id, "source_engine": "security_dependency_risk_engine"})
                except Exception:
                    pass
            return dict(row)

    def add_vuln(
        self,
        dependency_id: str,
        org_id: str,
        cve_id: str,
        severity: str,
        cvss_score: float,
        fixed_version: str,
    ) -> Dict[str, Any]:
        """Add a vulnerability to a dependency and recompute risk_score."""
        severity = severity if severity in _VALID_SEVERITIES else "medium"
        cvss_score = max(0.0, min(10.0, float(cvss_score)))
        now = _now_iso()

        with self._lock, self._conn() as conn:
            vuln_id = str(uuid.uuid4())
            conn.execute(
                """INSERT INTO dependency_vulns
                   (id, dependency_id, org_id, cve_id, severity, cvss_score,
                    fixed_version, patched, detected_at, created_at)
                   VALUES (?,?,?,?,?,?,?,0,?,?)""",
                (vuln_id, dependency_id, org_id, cve_id, severity, cvss_score,
                 fixed_version, now, now),
            )
            self._recompute_risk_score(conn, dependency_id, org_id)
            row = conn.execute(
                "SELECT * FROM dependency_vulns WHERE id=?", (vuln_id,)
            ).fetchone()
            if _get_tg_bus:
                try:
                    bus = _get_tg_bus()
                    if bus and getattr(bus, "enabled", False):
                        bus.emit("RISK_ASSESSED", {"entity_type": "security_dependency_risk_engine", "org_id": org_id, "source_engine": "security_dependency_risk_engine"})
                except Exception:
                    pass
            return dict(row)

    def patch_vuln(self, vuln_id: str, org_id: str) -> Dict[str, Any]:
        """Mark a vulnerability as patched and recompute parent dependency risk."""
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE dependency_vulns SET patched=1 WHERE id=? AND org_id=?",
                (vuln_id, org_id),
            )
            vuln = conn.execute(
                "SELECT * FROM dependency_vulns WHERE id=? AND org_id=?", (vuln_id, org_id)
            ).fetchone()
            if vuln:
                self._recompute_risk_score(conn, vuln["dependency_id"], org_id)
            return dict(vuln) if vuln else {"error": "not_found"}

    def flag_license_risk(
        self,
        org_id: str,
        license_name: str,
        risk_level: str,
        copyleft: bool,
        commercial_use_allowed: bool,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Insert or replace a license risk record."""
        risk_level = risk_level if risk_level in _VALID_LICENSE_RISK_LEVELS else "low"
        now = _now_iso()

        with self._lock, self._conn() as conn:
            rid = str(uuid.uuid4())
            conn.execute(
                """INSERT OR REPLACE INTO license_risks
                   (id, org_id, license_name, risk_level, copyleft,
                    commercial_use_allowed, notes, created_at)
                   VALUES (
                     COALESCE((SELECT id FROM license_risks WHERE org_id=? AND license_name=?), ?),
                     ?,?,?,?,?,?,?
                   )""",
                (org_id, license_name, rid,
                 org_id, license_name, risk_level,
                 1 if copyleft else 0,
                 1 if commercial_use_allowed else 0,
                 notes, now),
            )
            row = conn.execute(
                "SELECT * FROM license_risks WHERE org_id=? AND license_name=?",
                (org_id, license_name),
            ).fetchone()
            return dict(row)

    def get_dependency_summary(self, org_id: str) -> Dict[str, Any]:
        """Aggregated summary of dependencies and vulnerabilities."""
        with self._lock, self._conn() as conn:
            total_deps = conn.execute(
                "SELECT COUNT(*) FROM dependencies WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            direct_count = conn.execute(
                "SELECT COUNT(*) FROM dependencies WHERE org_id=? AND direct=1", (org_id,)
            ).fetchone()[0]
            transitive_count = total_deps - direct_count

            total_vulns = conn.execute(
                "SELECT COUNT(*) FROM dependency_vulns WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            critical_vulns = conn.execute(
                "SELECT COUNT(*) FROM dependency_vulns WHERE org_id=? AND severity='critical'",
                (org_id,),
            ).fetchone()[0]
            high_risk_deps = conn.execute(
                "SELECT COUNT(*) FROM dependencies WHERE org_id=? AND risk_score>7", (org_id,)
            ).fetchone()[0]

            by_ecosystem: Dict[str, int] = {}
            for row in conn.execute(
                "SELECT ecosystem, COUNT(*) as cnt FROM dependencies WHERE org_id=? GROUP BY ecosystem",
                (org_id,),
            ):
                by_ecosystem[row["ecosystem"]] = row["cnt"]

            return {
                "total_deps": total_deps,
                "direct_count": direct_count,
                "transitive_count": transitive_count,
                "total_vulns": total_vulns,
                "critical_vulns": critical_vulns,
                "high_risk_deps": high_risk_deps,
                "by_ecosystem": by_ecosystem,
            }

    def get_risky_dependencies(self, org_id: str, min_risk: float = 5.0) -> List[Dict[str, Any]]:
        """Dependencies with risk_score >= min_risk, ordered DESC."""
        with self._lock, self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    """SELECT * FROM dependencies
                       WHERE org_id=? AND risk_score >= ?
                       ORDER BY risk_score DESC""",
                    (org_id, min_risk),
                )
            ]

    def get_license_conflicts(self, org_id: str) -> List[Dict[str, Any]]:
        """Dependencies whose license is flagged high-risk or copyleft+no-commercial."""
        with self._lock, self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    """SELECT d.*, lr.risk_level, lr.copyleft, lr.commercial_use_allowed
                       FROM dependencies d
                       JOIN license_risks lr
                         ON lr.org_id = d.org_id AND lr.license_name = d.license
                       WHERE d.org_id=?
                         AND (lr.risk_level='high' OR lr.risk_level='critical'
                              OR (lr.copyleft=1 AND lr.commercial_use_allowed=0))""",
                    (org_id,),
                )
            ]

    def get_vuln_list(self, org_id: str, patched: Optional[bool] = None) -> List[Dict[str, Any]]:
        """All vulns with package_name join; optionally filter by patched."""
        with self._lock, self._conn() as conn:
            query = """
                SELECT dv.*, d.package_name, d.version, d.ecosystem
                FROM dependency_vulns dv
                JOIN dependencies d ON d.id = dv.dependency_id
                WHERE dv.org_id=?
            """
            params: list = [org_id]
            if patched is not None:
                query += " AND dv.patched=?"
                params.append(1 if patched else 0)
            return [dict(r) for r in conn.execute(query, params)]

    def get_transitive_graph(self, org_id: str, package_name: str) -> List[Dict[str, Any]]:
        """Direct children of package_name (WHERE parent_package=package_name)."""
        with self._lock, self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM dependencies WHERE org_id=? AND parent_package=?",
                    (org_id, package_name),
                )
            ]
