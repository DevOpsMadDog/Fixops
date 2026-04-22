"""Supply Chain Intelligence Engine — ALDECI.

Tracks software packages, vulnerabilities, malicious packages, and SBOM snapshots.

Capabilities:
  - Package registry across ecosystems (npm/pypi/maven/go/ruby/cargo/nuget)
  - Per-package vulnerability tracking with patching status
  - Malicious package flagging (typosquat, backdoor, credential stealer, etc.)
  - SBOM snapshot generation with composite risk scoring
  - check_package() fast-path for pipeline gate checks

Compliance: NIST SP 800-161r1 (C-SCRM), EO 14028, CISA SBOM guidance
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "supply_chain_intel.db"
)

_VALID_ECOSYSTEMS = {"npm", "pypi", "maven", "go", "ruby", "cargo", "nuget"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "safe"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_MALWARE_TYPES = {
    "typosquat", "backdoor", "credential_stealer", "cryptominer", "dependency_confusion",
}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_risk_score(
    total_deps: int,
    critical_vulns: int,
    high_vulns: int,
    license_violations: int,
    malicious_flags: int,
) -> float:
    """Compute a 0–100 risk score from SBOM components."""
    if total_deps == 0:
        return 0.0
    score = 0.0
    score += min(critical_vulns * 15.0, 45.0)
    score += min(high_vulns * 5.0, 25.0)
    score += min(license_violations * 3.0, 15.0)
    score += min(malicious_flags * 20.0, 40.0)
    return min(round(score, 2), 100.0)


class SupplyChainIntelEngine:
    """SQLite WAL-backed Supply Chain Intelligence engine.

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
                CREATE TABLE IF NOT EXISTS tracked_packages (
                    pkg_id        TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    ecosystem     TEXT NOT NULL DEFAULT 'pypi',
                    version       TEXT NOT NULL DEFAULT '',
                    license       TEXT NOT NULL DEFAULT '',
                    is_direct     INTEGER NOT NULL DEFAULT 1,
                    risk_level    TEXT NOT NULL DEFAULT 'safe',
                    last_checked  DATETIME,
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pkg_org_eco
                    ON tracked_packages (org_id, ecosystem, risk_level);

                CREATE INDEX IF NOT EXISTS idx_pkg_org_name
                    ON tracked_packages (org_id, name, ecosystem);

                CREATE TABLE IF NOT EXISTS package_vulnerabilities (
                    vuln_id          TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    pkg_id           TEXT NOT NULL,
                    cve_id           TEXT NOT NULL DEFAULT '',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    cvss_score       REAL NOT NULL DEFAULT 0.0,
                    fixed_in_version TEXT NOT NULL DEFAULT '',
                    published_at     DATETIME,
                    patched          INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_vuln_org_pkg
                    ON package_vulnerabilities (org_id, pkg_id, patched);

                CREATE INDEX IF NOT EXISTS idx_vuln_org_severity
                    ON package_vulnerabilities (org_id, severity, patched);

                CREATE TABLE IF NOT EXISTS malicious_packages (
                    mal_id       TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    ecosystem    TEXT NOT NULL DEFAULT 'pypi',
                    version      TEXT NOT NULL DEFAULT '',
                    malware_type TEXT NOT NULL DEFAULT 'backdoor',
                    confidence   REAL NOT NULL DEFAULT 0.8,
                    reported_at  DATETIME NOT NULL,
                    source       TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_mal_org_eco
                    ON malicious_packages (org_id, ecosystem);

                CREATE INDEX IF NOT EXISTS idx_mal_org_name
                    ON malicious_packages (org_id, name, ecosystem);

                CREATE TABLE IF NOT EXISTS sbom_snapshots (
                    snapshot_id      TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    project_name     TEXT NOT NULL,
                    total_deps       INTEGER NOT NULL DEFAULT 0,
                    direct_deps      INTEGER NOT NULL DEFAULT 0,
                    vulnerable_deps  INTEGER NOT NULL DEFAULT 0,
                    critical_vulns   INTEGER NOT NULL DEFAULT 0,
                    high_vulns       INTEGER NOT NULL DEFAULT 0,
                    license_violations INTEGER NOT NULL DEFAULT 0,
                    malicious_flags  INTEGER NOT NULL DEFAULT 0,
                    risk_score       REAL NOT NULL DEFAULT 0.0,
                    taken_at         DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sbom_org_project
                    ON sbom_snapshots (org_id, project_name, taken_at DESC);

                CREATE TABLE IF NOT EXISTS supply_chain_signals (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    package_purl   TEXT NOT NULL,
                    signal_type    TEXT NOT NULL,
                    value          TEXT NOT NULL DEFAULT '',
                    evidence_uri   TEXT NOT NULL DEFAULT '',
                    ingested_at    DATETIME NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_scsignals_unique
                    ON supply_chain_signals (org_id, package_purl, signal_type);

                CREATE INDEX IF NOT EXISTS idx_scsignals_org_purl
                    ON supply_chain_signals (org_id, package_purl);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Packages
    # ------------------------------------------------------------------

    def track_package(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Track a new package. Returns the created record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        ecosystem = data.get("ecosystem", "pypi")
        if ecosystem not in _VALID_ECOSYSTEMS:
            raise ValueError(f"Invalid ecosystem: {ecosystem}. Must be one of {_VALID_ECOSYSTEMS}")

        risk_level = data.get("risk_level", "safe")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(f"Invalid risk_level: {risk_level}")

        now = _now_iso()
        record = {
            "pkg_id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "ecosystem": ecosystem,
            "version": data.get("version", ""),
            "license": data.get("license", ""),
            "is_direct": 1 if data.get("is_direct", True) else 0,
            "risk_level": risk_level,
            "last_checked": now,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tracked_packages
                       (pkg_id, org_id, name, ecosystem, version, license,
                        is_direct, risk_level, last_checked, created_at)
                       VALUES (:pkg_id, :org_id, :name, :ecosystem, :version, :license,
                               :is_direct, :risk_level, :last_checked, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "supply_chain_intel", "org_id": org_id, "source_engine": "supply_chain_intel"})
            except Exception:
                pass

        return record

    def list_packages(
        self,
        org_id: str,
        ecosystem: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tracked packages, optionally filtered."""
        sql = "SELECT * FROM tracked_packages WHERE org_id = ?"
        params: list = [org_id]
        if ecosystem:
            sql += " AND ecosystem = ?"
            params.append(ecosystem)
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    def add_vulnerability(
        self, org_id: str, pkg_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a vulnerability to a tracked package."""
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        record = {
            "vuln_id": str(uuid.uuid4()),
            "org_id": org_id,
            "pkg_id": pkg_id,
            "cve_id": data.get("cve_id", ""),
            "severity": severity,
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "fixed_in_version": data.get("fixed_in_version", ""),
            "published_at": data.get("published_at") or _now_iso(),
            "patched": 1 if data.get("patched", False) else 0,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO package_vulnerabilities
                       (vuln_id, org_id, pkg_id, cve_id, severity, cvss_score,
                        fixed_in_version, published_at, patched)
                       VALUES (:vuln_id, :org_id, :pkg_id, :cve_id, :severity, :cvss_score,
                               :fixed_in_version, :published_at, :patched)""",
                    record,
                )
        return record

    def list_vulnerabilities(
        self,
        org_id: str,
        pkg_id: Optional[str] = None,
        severity: Optional[str] = None,
        patched: bool = False,
    ) -> List[Dict[str, Any]]:
        """List vulnerabilities. patched=False returns only unpatched."""
        sql = "SELECT * FROM package_vulnerabilities WHERE org_id = ?"
        params: list = [org_id]
        if pkg_id:
            sql += " AND pkg_id = ?"
            params.append(pkg_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if not patched:
            sql += " AND patched = 0"
        sql += " ORDER BY cvss_score DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Malicious packages
    # ------------------------------------------------------------------

    def flag_malicious(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Flag a package as malicious."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        ecosystem = data.get("ecosystem", "pypi")
        if ecosystem not in _VALID_ECOSYSTEMS:
            raise ValueError(f"Invalid ecosystem: {ecosystem}")

        malware_type = data.get("malware_type", "backdoor")
        if malware_type not in _VALID_MALWARE_TYPES:
            raise ValueError(f"Invalid malware_type: {malware_type}")

        record = {
            "mal_id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "ecosystem": ecosystem,
            "version": data.get("version", ""),
            "malware_type": malware_type,
            "confidence": float(data.get("confidence", 0.8)),
            "reported_at": data.get("reported_at") or _now_iso(),
            "source": data.get("source", ""),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO malicious_packages
                       (mal_id, org_id, name, ecosystem, version, malware_type,
                        confidence, reported_at, source)
                       VALUES (:mal_id, :org_id, :name, :ecosystem, :version, :malware_type,
                               :confidence, :reported_at, :source)""",
                    record,
                )
        return record

    def list_malicious(
        self, org_id: str, ecosystem: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List malicious packages, optionally filtered by ecosystem."""
        sql = "SELECT * FROM malicious_packages WHERE org_id = ?"
        params: list = [org_id]
        if ecosystem:
            sql += " AND ecosystem = ?"
            params.append(ecosystem)
        sql += " ORDER BY reported_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Package check (pipeline gate)
    # ------------------------------------------------------------------

    def check_package(
        self, org_id: str, name: str, ecosystem: str
    ) -> Dict[str, Any]:
        """Fast-path check for a package by name + ecosystem.

        Returns a summary with is_tracked, is_malicious, vulnerability_count,
        highest_severity, risk_level, and recommendation.
        """
        with self._conn() as conn:
            pkg_row = conn.execute(
                "SELECT * FROM tracked_packages WHERE org_id = ? AND name = ? AND ecosystem = ?",
                (org_id, name, ecosystem),
            ).fetchone()

            mal_row = conn.execute(
                "SELECT * FROM malicious_packages WHERE org_id = ? AND name = ? AND ecosystem = ?",
                (org_id, name, ecosystem),
            ).fetchone()

            vuln_count = 0
            highest_severity = None
            risk_level = "safe"

            if pkg_row:
                pkg_id = pkg_row["pkg_id"]
                risk_level = pkg_row["risk_level"]
                vuln_rows = conn.execute(
                    """SELECT severity FROM package_vulnerabilities
                       WHERE org_id = ? AND pkg_id = ? AND patched = 0""",
                    (org_id, pkg_id),
                ).fetchall()
                vuln_count = len(vuln_rows)
                if vuln_rows:
                    highest_severity = max(
                        (r["severity"] for r in vuln_rows),
                        key=lambda s: _SEVERITY_ORDER.get(s, 0),
                    )

        is_malicious = mal_row is not None
        recommendation = "safe to use"
        if is_malicious:
            recommendation = "block: malicious package detected"
        elif highest_severity == "critical":
            recommendation = "block: critical vulnerability unpatched"
        elif highest_severity == "high":
            recommendation = "warn: high severity vulnerability present"
        elif vuln_count > 0:
            recommendation = "review: vulnerabilities present"

        return {
            "name": name,
            "ecosystem": ecosystem,
            "is_tracked": pkg_row is not None,
            "is_malicious": is_malicious,
            "vulnerability_count": vuln_count,
            "highest_severity": highest_severity,
            "risk_level": risk_level,
            "recommendation": recommendation,
        }

    # ------------------------------------------------------------------
    # SBOM snapshots
    # ------------------------------------------------------------------

    def create_sbom_snapshot(
        self,
        org_id: str,
        project_name: str,
        packages_data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Create an SBOM snapshot from a list of package dicts.

        Each package dict may have: name, ecosystem, version, is_direct,
        license, cve_ids (list of {cve_id, severity}), license_ok (bool).

        Computes counts, risk_score, and saves snapshot.
        """
        total_deps = len(packages_data)
        direct_deps = sum(1 for p in packages_data if p.get("is_direct", True))
        critical_vulns = 0
        high_vulns = 0
        vulnerable_deps = 0
        license_violations = 0
        malicious_flags = 0

        for pkg in packages_data:
            pkg_name = pkg.get("name", "")
            pkg_eco = pkg.get("ecosystem", "pypi")

            # Count CVEs by severity
            cves = pkg.get("cve_ids") or []
            pkg_has_vuln = False
            for cve in cves:
                sev = cve.get("severity", "low") if isinstance(cve, dict) else "low"
                if sev == "critical":
                    critical_vulns += 1
                    pkg_has_vuln = True
                elif sev == "high":
                    high_vulns += 1
                    pkg_has_vuln = True
                else:
                    pkg_has_vuln = True
            if pkg_has_vuln:
                vulnerable_deps += 1

            # License violations
            if not pkg.get("license_ok", True):
                license_violations += 1

            # Check malicious flags from DB
            if pkg_name and pkg_eco:
                with self._conn() as conn:
                    mal = conn.execute(
                        """SELECT 1 FROM malicious_packages
                           WHERE org_id = ? AND name = ? AND ecosystem = ? LIMIT 1""",
                        (org_id, pkg_name, pkg_eco),
                    ).fetchone()
                    if mal:
                        malicious_flags += 1

        risk_score = _compute_risk_score(
            total_deps, critical_vulns, high_vulns, license_violations, malicious_flags
        )

        now = _now_iso()
        snapshot = {
            "snapshot_id": str(uuid.uuid4()),
            "org_id": org_id,
            "project_name": project_name,
            "total_deps": total_deps,
            "direct_deps": direct_deps,
            "vulnerable_deps": vulnerable_deps,
            "critical_vulns": critical_vulns,
            "high_vulns": high_vulns,
            "license_violations": license_violations,
            "malicious_flags": malicious_flags,
            "risk_score": risk_score,
            "taken_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sbom_snapshots
                       (snapshot_id, org_id, project_name, total_deps, direct_deps,
                        vulnerable_deps, critical_vulns, high_vulns, license_violations,
                        malicious_flags, risk_score, taken_at)
                       VALUES (:snapshot_id, :org_id, :project_name, :total_deps, :direct_deps,
                               :vulnerable_deps, :critical_vulns, :high_vulns, :license_violations,
                               :malicious_flags, :risk_score, :taken_at)""",
                    snapshot,
                )
        return snapshot

    def list_snapshots(
        self, org_id: str, project_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List SBOM snapshots, optionally filtered by project_name."""
        sql = "SELECT * FROM sbom_snapshots WHERE org_id = ?"
        params: list = [org_id]
        if project_name:
            sql += " AND project_name = ?"
            params.append(project_name)
        sql += " ORDER BY taken_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_supply_chain_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated supply chain stats for org."""
        with self._conn() as conn:
            total_pkgs = conn.execute(
                "SELECT COUNT(*) FROM tracked_packages WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            critical_pkgs = conn.execute(
                "SELECT COUNT(*) FROM tracked_packages WHERE org_id = ? AND risk_level = 'critical'",
                (org_id,),
            ).fetchone()[0]
            mal_flags = conn.execute(
                "SELECT COUNT(*) FROM malicious_packages WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            total_vulns = conn.execute(
                "SELECT COUNT(*) FROM package_vulnerabilities WHERE org_id = ? AND patched = 0",
                (org_id,),
            ).fetchone()[0]
            crit_vulns = conn.execute(
                """SELECT COUNT(*) FROM package_vulnerabilities
                   WHERE org_id = ? AND severity = 'critical' AND patched = 0""",
                (org_id,),
            ).fetchone()[0]
            projects_count = conn.execute(
                "SELECT COUNT(DISTINCT project_name) FROM sbom_snapshots WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            # Top 5 highest-risk packages
            top_rows = conn.execute(
                """SELECT name FROM tracked_packages
                   WHERE org_id = ?
                   ORDER BY CASE risk_level
                     WHEN 'critical' THEN 4
                     WHEN 'high' THEN 3
                     WHEN 'medium' THEN 2
                     WHEN 'low' THEN 1
                     ELSE 0 END DESC,
                     created_at DESC
                   LIMIT 5""",
                (org_id,),
            ).fetchall()
            highest_risk_packages = [r["name"] for r in top_rows]

        return {
            "total_packages": total_pkgs,
            "critical_packages": critical_pkgs,
            "malicious_flags": mal_flags,
            "total_vulns": total_vulns,
            "critical_vulns": crit_vulns,
            "projects_count": projects_count,
            "highest_risk_packages": highest_risk_packages,
        }

    # ------------------------------------------------------------------
    # Malicious signal ingestion (GAP-009)
    # ------------------------------------------------------------------

    def ingest_malicious_signal(
        self,
        org_id: str,
        package_purl: str,
        signal_type: str,
        value: Any = "",
        evidence_uri: str = "",
    ) -> Dict[str, Any]:
        """Ingest a malicious-behavior signal for a package purl.

        Deduplicates on (org_id, package_purl, signal_type) via UNIQUE index.
        On duplicate, returns the existing record without re-emitting an event.
        Emits TrustGraph FINDING_CREATED for new signals.
        """
        if not package_purl:
            raise ValueError("package_purl is required.")
        if not signal_type:
            raise ValueError("signal_type is required.")

        value_str = "" if value is None else str(value)
        evidence_str = evidence_uri or ""
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "package_purl": package_purl,
            "signal_type": signal_type,
            "value": value_str,
            "evidence_uri": evidence_str,
            "ingested_at": now,
        }

        inserted = False
        with self._lock:
            with self._conn() as conn:
                try:
                    conn.execute(
                        """INSERT INTO supply_chain_signals
                           (id, org_id, package_purl, signal_type,
                            value, evidence_uri, ingested_at)
                           VALUES (:id, :org_id, :package_purl, :signal_type,
                                   :value, :evidence_uri, :ingested_at)""",
                        record,
                    )
                    inserted = True
                except sqlite3.IntegrityError:
                    existing = conn.execute(
                        """SELECT * FROM supply_chain_signals
                           WHERE org_id=? AND package_purl=? AND signal_type=?""",
                        (org_id, package_purl, signal_type),
                    ).fetchone()
                    if existing is not None:
                        return dict(existing)
                    raise

        if inserted and _get_tg_bus is not None:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "finding.created",
                        {
                            "org_id": org_id,
                            "source_engine": "supply_chain_intel",
                            "entity_type": "malicious_package_signal",
                            "package_purl": package_purl,
                            "signal_type": signal_type,
                            "value": value_str,
                            "evidence_uri": evidence_str,
                        },
                    )
            except Exception:
                pass

        return record

    def list_malicious_signals(
        self,
        org_id: str,
        package_purl: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List ingested malicious signals for org, optionally filtered by purl."""
        sql = "SELECT * FROM supply_chain_signals WHERE org_id = ?"
        params: list = [org_id]
        if package_purl:
            sql += " AND package_purl = ?"
            params.append(package_purl)
        sql += " ORDER BY ingested_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]
