"""Container Registry Security Engine — ALDECI.

Manages container registries, image vulnerability scans, and policy enforcement.

Capabilities:
  - Registry registry (Docker Hub, ECR, GCR, ACR, Harbor)
  - Image scanning with CVE tracking and scan scoring
  - Policy engine: block critical, max high vulns, require signed images
  - Policy evaluation per scan: allow / warn / block with violation details
  - Stats aggregation per org

Compliance: CIS Docker Benchmark, NIST SP 800-190, OCI image spec
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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_REGISTRY_TYPES = {"docker", "ecr", "gcr", "acr", "harbor"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "negligible"}
_VALID_POLICY_RESULTS = {"allow", "warn", "block"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ContainerRegistrySecurityEngine:
    """SQLite WAL-backed Container Registry Security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = "") -> None:
        if not db_path:
            db_path = str(Path(_DEFAULT_DB_DIR) / "container_registry_security.db")
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
                CREATE TABLE IF NOT EXISTS registries (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    url              TEXT NOT NULL DEFAULT '',
                    registry_type    TEXT NOT NULL DEFAULT 'docker',
                    auth_configured  INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_registries_org
                    ON registries (org_id);

                CREATE TABLE IF NOT EXISTS image_scans (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    registry_id      TEXT NOT NULL,
                    image_name       TEXT NOT NULL,
                    tag              TEXT NOT NULL DEFAULT 'latest',
                    vulnerabilities  TEXT NOT NULL DEFAULT '[]',
                    scan_score       INTEGER NOT NULL DEFAULT 100,
                    critical_count   INTEGER NOT NULL DEFAULT 0,
                    high_count       INTEGER NOT NULL DEFAULT 0,
                    medium_count     INTEGER NOT NULL DEFAULT 0,
                    low_count        INTEGER NOT NULL DEFAULT 0,
                    scanned_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scans_org_registry
                    ON image_scans (org_id, registry_id, scanned_at DESC);

                CREATE INDEX IF NOT EXISTS idx_scans_org_critical
                    ON image_scans (org_id, critical_count DESC);

                CREATE TABLE IF NOT EXISTS policies (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    block_critical   INTEGER NOT NULL DEFAULT 1,
                    max_high_vulns   INTEGER NOT NULL DEFAULT 5,
                    require_signed   INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_policies_org
                    ON policies (org_id);

                CREATE TABLE IF NOT EXISTS base_image_allowlist (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    image       TEXT NOT NULL,
                    tag_pattern TEXT NOT NULL DEFAULT '*',
                    reason      TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_allowlist_org_image
                    ON base_image_allowlist (org_id, image, tag_pattern);

                CREATE INDEX IF NOT EXISTS idx_allowlist_org
                    ON base_image_allowlist (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("vulnerabilities",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        for field in ("auth_configured", "block_critical", "require_signed"):
            if field in d:
                d[field] = bool(d[field])
        return d

    # ------------------------------------------------------------------
    # Registries
    # ------------------------------------------------------------------

    def register_registry(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new container registry."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        registry_type = data.get("registry_type", "docker")
        if registry_type not in _VALID_REGISTRY_TYPES:
            raise ValueError(
                f"Invalid registry_type: {registry_type}. Must be one of {_VALID_REGISTRY_TYPES}"
            )

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "url": data.get("url", ""),
            "registry_type": registry_type,
            "auth_configured": 1 if data.get("auth_configured", False) else 0,
            "created_at": _now_iso(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO registries
                       (id, org_id, name, url, registry_type, auth_configured, created_at)
                       VALUES (:id, :org_id, :name, :url, :registry_type, :auth_configured, :created_at)""",
                    record,
                )
        record["auth_configured"] = bool(record["auth_configured"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "container_registry_security", "org_id": org_id, "source_engine": "container_registry_security"})
            except Exception:
                pass

        return record

    def list_registries(self, org_id: str) -> List[Dict[str, Any]]:
        """List all registries for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM registries WHERE org_id = ? ORDER BY name ASC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_registry(self, org_id: str, registry_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single registry by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM registries WHERE org_id = ? AND id = ?",
                (org_id, registry_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Image Scans
    # ------------------------------------------------------------------

    def scan_image(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an image vulnerability scan result."""
        registry_id = (data.get("registry_id") or "").strip()
        if not registry_id:
            raise ValueError("registry_id is required.")

        image_name = (data.get("image_name") or "").strip()
        if not image_name:
            raise ValueError("image_name is required.")

        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

        # Validate and normalize vuln entries
        normalized_vulns = []
        severity_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0
        }
        for v in vulnerabilities:
            sev = v.get("severity", "low").lower()
            if sev not in _VALID_SEVERITIES:
                sev = "low"
            normalized_vulns.append({
                "cve_id": v.get("cve_id", ""),
                "severity": sev,
                "package": v.get("package", ""),
            })
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Compute scan_score: start at 100, deduct per severity
        scan_score = data.get("scan_score")
        if scan_score is None:
            deductions = (
                severity_counts["critical"] * 20
                + severity_counts["high"] * 10
                + severity_counts["medium"] * 5
                + severity_counts["low"] * 2
            )
            scan_score = max(0, 100 - deductions)
        else:
            scan_score = max(0, min(100, int(scan_score)))

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "registry_id": registry_id,
            "image_name": image_name,
            "tag": data.get("tag", "latest"),
            "vulnerabilities": json.dumps(normalized_vulns),
            "scan_score": scan_score,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "scanned_at": _now_iso(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO image_scans
                       (id, org_id, registry_id, image_name, tag, vulnerabilities, scan_score,
                        critical_count, high_count, medium_count, low_count, scanned_at)
                       VALUES (:id, :org_id, :registry_id, :image_name, :tag, :vulnerabilities,
                               :scan_score, :critical_count, :high_count, :medium_count,
                               :low_count, :scanned_at)""",
                    record,
                )
        record["vulnerabilities"] = normalized_vulns
        return record

    def list_image_scans(
        self,
        org_id: str,
        registry_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List image scans, optionally filtered by registry or minimum severity."""
        sql = "SELECT * FROM image_scans WHERE org_id = ?"
        params: list = [org_id]
        if registry_id:
            sql += " AND registry_id = ?"
            params.append(registry_id)
        if severity == "critical":
            sql += " AND critical_count > 0"
        elif severity == "high":
            sql += " AND high_count > 0"
        elif severity == "medium":
            sql += " AND medium_count > 0"
        elif severity == "low":
            sql += " AND low_count > 0"
        sql += " ORDER BY scanned_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_scan(self, org_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single image scan by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM image_scans WHERE org_id = ? AND id = ?",
                (org_id, scan_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an image admission policy."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "block_critical": 1 if data.get("block_critical", True) else 0,
            "max_high_vulns": int(data.get("max_high_vulns", 5)),
            "require_signed": 1 if data.get("require_signed", False) else 0,
            "created_at": _now_iso(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO policies
                       (id, org_id, name, block_critical, max_high_vulns, require_signed, created_at)
                       VALUES (:id, :org_id, :name, :block_critical, :max_high_vulns, :require_signed, :created_at)""",
                    record,
                )
        record["block_critical"] = bool(record["block_critical"])
        record["require_signed"] = bool(record["require_signed"])
        return record

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all policies for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM policies WHERE org_id = ? ORDER BY name ASC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def evaluate_image(self, org_id: str, scan_id: str) -> Dict[str, Any]:
        """Evaluate a scan against all org policies.

        Returns:
            policy_result: allow | warn | block
            violations: list of violation strings
        """
        scan = self.get_scan(org_id, scan_id)
        if not scan:
            raise KeyError(f"Scan {scan_id} not found.")

        policies = self.list_policies(org_id)
        if not policies:
            return {
                "scan_id": scan_id,
                "policy_result": "allow",
                "violations": [],
                "policies_evaluated": 0,
            }

        violations: List[str] = []
        worst_result = "allow"

        for policy in policies:
            if policy["block_critical"] and scan["critical_count"] > 0:
                violations.append(
                    f"Policy '{policy['name']}': {scan['critical_count']} critical vulnerability(ies) found (block_critical=True)"
                )
                worst_result = "block"

            if scan["high_count"] > policy["max_high_vulns"]:
                violations.append(
                    f"Policy '{policy['name']}': {scan['high_count']} high vulnerabilities exceeds max_high_vulns={policy['max_high_vulns']}"
                )
                if worst_result != "block":
                    worst_result = "block"

            if policy["require_signed"] and scan["scan_score"] < 70:
                violations.append(
                    f"Policy '{policy['name']}': image requires signing verification (scan_score={scan['scan_score']})"
                )
                if worst_result == "allow":
                    worst_result = "warn"

        return {
            "scan_id": scan_id,
            "image_name": scan["image_name"],
            "tag": scan["tag"],
            "policy_result": worst_result,
            "violations": violations,
            "policies_evaluated": len(policies),
        }

    # ------------------------------------------------------------------
    # Base Image Allowlist
    # ------------------------------------------------------------------

    def add_allowlist_entry(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a base image to the org allowlist.

        Args:
            org_id: Tenant identifier.
            data: {image, tag_pattern, reason}

        Returns:
            The created allowlist record.

        Raises:
            ValueError: if image is missing or entry already exists.
        """
        image = (data.get("image") or "").strip()
        if not image:
            raise ValueError("image is required.")
        tag_pattern = (data.get("tag_pattern") or "*").strip() or "*"
        reason = (data.get("reason") or "").strip()

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "image": image,
            "tag_pattern": tag_pattern,
            "reason": reason,
            "created_at": _now_iso(),
        }
        try:
            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        """INSERT INTO base_image_allowlist
                           (id, org_id, image, tag_pattern, reason, created_at)
                           VALUES (:id, :org_id, :image, :tag_pattern, :reason, :created_at)""",
                        record,
                    )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"Allowlist entry for image='{image}' tag_pattern='{tag_pattern}' already exists."
            ) from exc

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit(
                        "POLICY_UPDATED",
                        {
                            "entity_type": "base_image_allowlist",
                            "org_id": org_id,
                            "source_engine": "container_registry_security",
                        },
                    )
            except Exception:
                pass

        return record

    def list_allowlist(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all allowlist entries for org, ordered by image name."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM base_image_allowlist WHERE org_id = ? ORDER BY image ASC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def remove_allowlist_entry(self, org_id: str, entry_id: str) -> bool:
        """Delete an allowlist entry. Returns True if deleted, False if not found."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "DELETE FROM base_image_allowlist WHERE org_id = ? AND id = ?",
                    (org_id, entry_id),
                )
        return cur.rowcount > 0

    def check_image_allowed(
        self, org_id: str, image: str, tag: str = "latest"
    ) -> Dict[str, Any]:
        """Check whether image:tag is on the allowlist.

        Matching rules (in order):
          1. Exact match on both image and tag_pattern.
          2. Wildcard tag_pattern='*' matches any tag for the image.

        Returns:
            {allowed: bool, matched_entry: dict|None}
        """
        image = (image or "").strip()
        tag = (tag or "latest").strip()

        with self._conn() as conn:
            # Exact match first
            row = conn.execute(
                """SELECT * FROM base_image_allowlist
                   WHERE org_id = ? AND image = ? AND tag_pattern = ?
                   LIMIT 1""",
                (org_id, image, tag),
            ).fetchone()
            if row:
                return {"allowed": True, "matched_entry": dict(row)}

            # Wildcard match
            row = conn.execute(
                """SELECT * FROM base_image_allowlist
                   WHERE org_id = ? AND image = ? AND tag_pattern = '*'
                   LIMIT 1""",
                (org_id, image),
            ).fetchone()
            if row:
                return {"allowed": True, "matched_entry": dict(row)}

        return {"allowed": False, "matched_entry": None}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_registry_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated registry security stats for org."""
        with self._conn() as conn:
            registries = conn.execute(
                "SELECT COUNT(*) FROM registries WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            scans = conn.execute(
                "SELECT COUNT(*) FROM image_scans WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            critical_images = conn.execute(
                "SELECT COUNT(*) FROM image_scans WHERE org_id = ? AND critical_count > 0",
                (org_id,),
            ).fetchone()[0]

            avg_score_row = conn.execute(
                "SELECT AVG(scan_score) FROM image_scans WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_scan_score = round(float(avg_score_row or 0.0), 1)

            # Count policy violations (block results if policies exist)
            policies_count = conn.execute(
                "SELECT COUNT(*) FROM policies WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            policy_violations = 0
            if policies_count > 0:
                # Count scans that would be blocked (have critical or excess high)
                block_critical_count = conn.execute(
                    """SELECT COUNT(*) FROM image_scans WHERE org_id = ? AND critical_count > 0""",
                    (org_id,),
                ).fetchone()[0]
                policy_violations = block_critical_count

        return {
            "registries": registries,
            "scans": scans,
            "critical_images": critical_images,
            "avg_scan_score": avg_scan_score,
            "policy_violations": policy_violations,
        }
