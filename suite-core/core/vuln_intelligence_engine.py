"""Vulnerability Intelligence Engine — ALDECI.

Enhanced CVE intelligence with vendor advisories, patch tracking,
and intel subscriptions. Complements the existing CVE enrichment engine.

Capabilities:
  - CVE ingestion and lifecycle tracking (new/analyzed/patched/mitigated/accepted)
  - KEV (Known Exploited Vulnerabilities) and EPSS score tracking
  - Vendor advisory management
  - Intel subscriptions (vendor/product/cve_keyword)
  - Daily stats snapshots
  - Aggregated stats per org

Compliance: NIST NVD, CISA KEV, CVSS v3.1, FIRST EPSS
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

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_CVE_STATUSES = {"new", "analyzed", "patched", "mitigated", "accepted"}
_VALID_EXPLOIT_TYPES = {None, "poc", "weaponized", "in_the_wild"}
_VALID_ADVISORY_STATUSES = {"new", "applied", "tracked"}
_VALID_SUBSCRIPTION_TYPES = {"vendor", "product", "cve_keyword"}
_VALID_NOTIFY_SEVERITIES = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class VulnIntelligenceEngine:
    """SQLite WAL-backed Vulnerability Intelligence engine.

    Thread-safe via per-org RLock. Multi-tenant via org_id.
    Database path: .fixops_data/{org_id}_vuln_intel.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._single_db_path = db_path
        self._org_locks: Dict[str, threading.RLock] = {}
        self._org_lock_meta = threading.Lock()
        if db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self._init_db(db_path)
        else:
            _DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _org_db_path(self, org_id: str) -> str:
        if self._single_db_path:
            return self._single_db_path
        safe = org_id.replace("/", "_").replace("..", "__")
        return str(_DEFAULT_DB_DIR / f"{safe}_vuln_intel.db")

    def _get_org_lock(self, org_id: str) -> threading.RLock:
        with self._org_lock_meta:
            if org_id not in self._org_locks:
                self._org_locks[org_id] = threading.RLock()
            return self._org_locks[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        path = self._org_db_path(org_id)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db(path)
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, path: str) -> None:
        conn = sqlite3.connect(path, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cve_intel (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    cve_id               TEXT NOT NULL,
                    title                TEXT NOT NULL DEFAULT '',
                    description          TEXT NOT NULL DEFAULT '',
                    cvss_score           REAL NOT NULL DEFAULT 0.0,
                    cvss_vector          TEXT NOT NULL DEFAULT '',
                    epss_score           REAL NOT NULL DEFAULT 0.0,
                    kev_listed           INTEGER NOT NULL DEFAULT 0,
                    kev_added_date       TEXT,
                    severity             TEXT NOT NULL DEFAULT 'medium',
                    affected_products    TEXT NOT NULL DEFAULT '[]',
                    exploit_available    INTEGER NOT NULL DEFAULT 0,
                    exploit_type         TEXT,
                    patch_available      INTEGER NOT NULL DEFAULT 0,
                    patch_url            TEXT NOT NULL DEFAULT '',
                    ref_urls            TEXT NOT NULL DEFAULT '[]',
                    threat_actors_using  TEXT NOT NULL DEFAULT '[]',
                    affected_org_assets  TEXT NOT NULL DEFAULT '[]',
                    status               TEXT NOT NULL DEFAULT 'new',
                    created_at           DATETIME NOT NULL,
                    updated_at           DATETIME NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_org_cveid
                    ON cve_intel (org_id, cve_id);

                CREATE INDEX IF NOT EXISTS idx_cve_org_severity
                    ON cve_intel (org_id, severity, kev_listed);

                CREATE TABLE IF NOT EXISTS vendor_advisories (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    advisory_id   TEXT NOT NULL DEFAULT '',
                    vendor        TEXT NOT NULL DEFAULT '',
                    product       TEXT NOT NULL DEFAULT '',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    advisory_url  TEXT NOT NULL DEFAULT '',
                    cves_covered  TEXT NOT NULL DEFAULT '[]',
                    patch_version TEXT NOT NULL DEFAULT '',
                    release_date  TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'new',
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_adv_org_vendor
                    ON vendor_advisories (org_id, vendor, status);

                CREATE TABLE IF NOT EXISTS vuln_subscriptions (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    subscription_type     TEXT NOT NULL DEFAULT 'vendor',
                    subscription_value    TEXT NOT NULL DEFAULT '',
                    notify_severity_min   TEXT NOT NULL DEFAULT 'high',
                    active                INTEGER NOT NULL DEFAULT 1,
                    created_at            DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sub_org_type
                    ON vuln_subscriptions (org_id, subscription_type, active);

                CREATE TABLE IF NOT EXISTS vuln_intel_stats (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    date               TEXT NOT NULL,
                    new_cves           INTEGER NOT NULL DEFAULT 0,
                    critical_cves      INTEGER NOT NULL DEFAULT 0,
                    kev_added          INTEGER NOT NULL DEFAULT 0,
                    advisories_received INTEGER NOT NULL DEFAULT 0,
                    patches_available  INTEGER NOT NULL DEFAULT 0,
                    created_at         DATETIME NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_stats_org_date
                    ON vuln_intel_stats (org_id, date);
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _deserialize_row(d: dict) -> dict:
        for field in ("affected_products", "ref_urls", "threat_actors_using",
                      "affected_org_assets", "cves_covered"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = []
        for field in ("kev_listed", "exploit_available", "patch_available", "active"):
            if field in d:
                d[field] = bool(d[field])
        return d

    # ------------------------------------------------------------------
    # CVE Intel
    # ------------------------------------------------------------------

    def add_cve(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add or update CVE intelligence. Upserts on (org_id, cve_id)."""
        cve_id = (data.get("cve_id") or "").strip().upper()
        if not cve_id:
            raise ValueError("cve_id is required.")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        exploit_type = data.get("exploit_type")
        if exploit_type not in _VALID_EXPLOIT_TYPES:
            exploit_type = None

        status = data.get("status", "new")
        if status not in _VALID_CVE_STATUSES:
            status = "new"

        now = _now_iso()

        def _js(v: Any) -> str:
            if isinstance(v, list):
                return json.dumps(v)
            if isinstance(v, str):
                return v
            return json.dumps([])

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "vuln_intelligence", "org_id": org_id, "source_engine": "vuln_intelligence"})
            except Exception:
                pass

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cve_id": cve_id,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "cvss_vector": data.get("cvss_vector", ""),
            "epss_score": float(data.get("epss_score", 0.0)),
            "kev_listed": 1 if data.get("kev_listed", False) else 0,
            "kev_added_date": data.get("kev_added_date"),
            "severity": severity,
            "affected_products": _js(data.get("affected_products", [])),
            "exploit_available": 1 if data.get("exploit_available", False) else 0,
            "exploit_type": exploit_type,
            "patch_available": 1 if data.get("patch_available", False) else 0,
            "patch_url": data.get("patch_url", ""),
            "ref_urls": _js(data.get("references", [])),
            "threat_actors_using": _js(data.get("threat_actors_using", [])),
            "affected_org_assets": _js(data.get("affected_org_assets", [])),
            "status": status,
            "created_at": now,
            "updated_at": now,
        }

        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                existing = conn.execute(
                    "SELECT id FROM cve_intel WHERE org_id = ? AND cve_id = ?",
                    (org_id, cve_id),
                ).fetchone()
                if existing:
                    record["id"] = existing["id"]
                    conn.execute(
                        """UPDATE cve_intel SET
                           title=:title, description=:description, cvss_score=:cvss_score,
                           cvss_vector=:cvss_vector, epss_score=:epss_score,
                           kev_listed=:kev_listed, kev_added_date=:kev_added_date,
                           severity=:severity, affected_products=:affected_products,
                           exploit_available=:exploit_available, exploit_type=:exploit_type,
                           patch_available=:patch_available, patch_url=:patch_url,
                           ref_urls=:ref_urls, threat_actors_using=:threat_actors_using,
                           affected_org_assets=:affected_org_assets, status=:status,
                           updated_at=:updated_at
                           WHERE org_id=:org_id AND cve_id=:cve_id""",
                        record,
                    )
                else:
                    conn.execute(
                        """INSERT INTO cve_intel
                           (id, org_id, cve_id, title, description, cvss_score, cvss_vector,
                            epss_score, kev_listed, kev_added_date, severity, affected_products,
                            exploit_available, exploit_type, patch_available, patch_url,
                            ref_urls, threat_actors_using, affected_org_assets, status,
                            created_at, updated_at)
                           VALUES (:id, :org_id, :cve_id, :title, :description, :cvss_score,
                                   :cvss_vector, :epss_score, :kev_listed, :kev_added_date,
                                   :severity, :affected_products, :exploit_available,
                                   :exploit_type, :patch_available, :patch_url, :ref_urls,
                                   :threat_actors_using, :affected_org_assets, :status,
                                   :created_at, :updated_at)""",
                        record,
                    )

        out = dict(record)
        return self._deserialize_row(out)

    def list_cves(
        self,
        org_id: str,
        severity: Optional[str] = None,
        kev_listed: Optional[bool] = None,
        exploit_available: Optional[bool] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List CVEs with optional filters."""
        sql = "SELECT * FROM cve_intel WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if kev_listed is not None:
            sql += " AND kev_listed = ?"
            params.append(1 if kev_listed else 0)
        if exploit_available is not None:
            sql += " AND exploit_available = ?"
            params.append(1 if exploit_available else 0)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY cvss_score DESC, created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn(org_id) as conn:
            return [self._deserialize_row(dict(r)) for r in conn.execute(sql, params).fetchall()]

    def get_cve(self, org_id: str, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a single CVE by CVE-ID with full details."""
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM cve_intel WHERE org_id = ? AND cve_id = ?",
                (org_id, cve_id.upper()),
            ).fetchone()
        return self._deserialize_row(dict(row)) if row else None

    def update_cve_status(
        self, org_id: str, cve_id: str, status: str
    ) -> bool:
        """Update CVE status. Returns True if found and updated."""
        if status not in _VALID_CVE_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {_VALID_CVE_STATUSES}"
            )
        now = _now_iso()
        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE cve_intel SET status = ?, updated_at = ? "
                    "WHERE org_id = ? AND cve_id = ?",
                    (status, now, org_id, cve_id.upper()),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Vendor Advisories
    # ------------------------------------------------------------------

    def add_advisory(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a vendor advisory."""
        vendor = (data.get("vendor") or "").strip()
        if not vendor:
            raise ValueError("vendor is required.")

        cves_covered = data.get("cves_covered", [])
        if not isinstance(cves_covered, list):
            cves_covered = [cves_covered]

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "advisory_id": data.get("advisory_id", ""),
            "vendor": vendor,
            "product": data.get("product", ""),
            "severity": data.get("severity", "medium"),
            "advisory_url": data.get("advisory_url", ""),
            "cves_covered": json.dumps(cves_covered),
            "patch_version": data.get("patch_version", ""),
            "release_date": data.get("release_date", _today()),
            "status": data.get("status", "new"),
            "created_at": now,
        }
        if record["status"] not in _VALID_ADVISORY_STATUSES:
            record["status"] = "new"

        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO vendor_advisories
                       (id, org_id, advisory_id, vendor, product, severity, advisory_url,
                        cves_covered, patch_version, release_date, status, created_at)
                       VALUES (:id, :org_id, :advisory_id, :vendor, :product, :severity,
                               :advisory_url, :cves_covered, :patch_version, :release_date,
                               :status, :created_at)""",
                    record,
                )
        out = dict(record)
        return self._deserialize_row(out)

    def list_advisories(
        self,
        org_id: str,
        vendor: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List vendor advisories with optional filters."""
        sql = "SELECT * FROM vendor_advisories WHERE org_id = ?"
        params: list = [org_id]
        if vendor:
            sql += " AND vendor = ?"
            params.append(vendor)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._deserialize_row(dict(r)) for r in conn.execute(sql, params).fetchall()]

    def apply_advisory(self, org_id: str, advisory_id: str) -> bool:
        """Mark an advisory as applied. Returns True if found."""
        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE vendor_advisories SET status = 'applied' "
                    "WHERE org_id = ? AND id = ?",
                    (org_id, advisory_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    def add_subscription(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an intel subscription."""
        sub_type = data.get("subscription_type", "vendor")
        if sub_type not in _VALID_SUBSCRIPTION_TYPES:
            raise ValueError(
                f"Invalid subscription_type: {sub_type}. Must be one of {_VALID_SUBSCRIPTION_TYPES}"
            )

        sub_value = (data.get("subscription_value") or "").strip()
        if not sub_value:
            raise ValueError("subscription_value is required.")

        notify_sev = data.get("notify_severity_min", "high")
        if notify_sev not in _VALID_NOTIFY_SEVERITIES:
            notify_sev = "high"

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "subscription_type": sub_type,
            "subscription_value": sub_value,
            "notify_severity_min": notify_sev,
            "active": 1,
            "created_at": now,
        }
        with self._get_org_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO vuln_subscriptions
                       (id, org_id, subscription_type, subscription_value,
                        notify_severity_min, active, created_at)
                       VALUES (:id, :org_id, :subscription_type, :subscription_value,
                               :notify_severity_min, :active, :created_at)""",
                    record,
                )
        out = dict(record)
        return self._deserialize_row(out)

    def list_subscriptions(self, org_id: str) -> List[Dict[str, Any]]:
        """List all intel subscriptions for org."""
        with self._conn(org_id) as conn:
            return [
                self._deserialize_row(dict(r))
                for r in conn.execute(
                    "SELECT * FROM vuln_subscriptions WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cve_context(self, org_id: str, cve_id: str) -> Optional[Dict[str, Any]]:
        """Return enriched CVE context combining vuln-intel, supply chain,
        SBOM, and risk aggregator data.

        Returns None if the CVE is not tracked for the org.

        Response shape:
          cve          — full CVE record from vuln_intelligence_engine
          affected_components — packages from supply_chain_intel with this CVE
          related_cves — other CVEs affecting the same product set (up to 5)
          risk_score   — org composite risk score from risk_aggregator_engine
        """
        cve_id_upper = cve_id.strip().upper()

        # 1. Core CVE record
        cve = self.get_cve(org_id, cve_id_upper)
        if not cve:
            return None

        # 2. Affected components from supply chain intel engine
        affected_components: List[Dict[str, Any]] = []
        try:
            from core.supply_chain_intel_engine import SupplyChainIntelEngine
            sc_engine = SupplyChainIntelEngine()
            with sc_engine._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT tp.name, tp.ecosystem, tp.version, tp.risk_level,
                           pv.cve_id, pv.severity, pv.cvss_score,
                           pv.fixed_in_version, pv.patched
                    FROM package_vulnerabilities pv
                    JOIN tracked_packages tp ON tp.pkg_id = pv.pkg_id
                    WHERE pv.org_id = ? AND pv.cve_id = ?
                    ORDER BY pv.cvss_score DESC
                    """,
                    (org_id, cve_id_upper),
                ).fetchall()
            for r in rows:
                rec = dict(r)
                rec["patched"] = bool(rec["patched"])
                fix_ver = rec.get("fixed_in_version") or ""
                rec["fix_available"] = bool(fix_ver)
                rec["fix_version"] = fix_ver if fix_ver else None
                affected_components.append(rec)
        except Exception:
            _logger.debug("supply_chain_intel unavailable for CVE context", exc_info=True)

        # 3. Related CVEs — other CVEs affecting the same products
        related_cves: List[Dict[str, Any]] = []
        try:
            product_names: List[str] = []
            for prod in cve.get("affected_products", []):
                if isinstance(prod, dict):
                    name = prod.get("product") or prod.get("name") or ""
                else:
                    name = str(prod)
                if name:
                    product_names.append(name.lower())

            if product_names:
                with self._conn(org_id) as conn:
                    all_cves = conn.execute(
                        "SELECT cve_id, title, severity, cvss_score, affected_products "
                        "FROM cve_intel WHERE org_id = ? AND cve_id != ?",
                        (org_id, cve_id_upper),
                    ).fetchall()
                for row in all_cves:
                    try:
                        prods = json.loads(row["affected_products"] or "[]")
                    except (json.JSONDecodeError, TypeError):
                        prods = []
                    for p in prods:
                        p_name = (
                            (p.get("product") or p.get("name") or str(p))
                            if isinstance(p, dict)
                            else str(p)
                        ).lower()
                        if p_name in product_names:
                            related_cves.append({
                                "cve_id": row["cve_id"],
                                "title": row["title"],
                                "severity": row["severity"],
                                "cvss_score": row["cvss_score"],
                            })
                            break
                related_cves = related_cves[:5]
        except Exception:
            _logger.debug("related CVE lookup failed", exc_info=True)

        # 4. Org risk score from risk aggregator
        risk_score: Optional[Dict[str, Any]] = None
        try:
            from core.risk_aggregator_engine import RiskAggregatorEngine
            ra_engine = RiskAggregatorEngine()
            risk_score = ra_engine.calculate_org_risk_score(org_id)
        except Exception:
            _logger.debug("risk_aggregator unavailable for CVE context", exc_info=True)

        return {
            "cve": cve,
            "affected_components": affected_components,
            "related_cves": related_cves,
            "risk_score": risk_score,
        }

    def lookup_package_issues(
        self, org_id: str, ecosystem: str, name: str, version: str
    ) -> Dict[str, Any]:
        """Return CVEs and risk score for a specific package version.

        Queries sbom_export's component+vuln tables first (exact purl match),
        then falls back to a name-substring search across cve_intel
        affected_products JSON.

        Returns:
          package     — {ecosystem, name, version, purl}
          cves        — list of CVE records with fix_version
          risk_score  — aggregate float (max cvss_score across matched CVEs)
          vulnerable  — bool
        """
        purl = f"pkg:{ecosystem}/{name}@{version}"

        cves: List[Dict[str, Any]] = []

        # --- Primary: sbom_export component + vulnerability tables ---
        try:
            from core.sbom_export_engine import SBOMExportEngine
            sbom_engine = SBOMExportEngine()
            with sbom_engine._conn() as conn:
                comp_row = conn.execute(
                    """SELECT id FROM sbom_components
                       WHERE org_id = ?
                         AND (
                           purl = ?
                           OR (component_name = ? AND component_version = ?
                               AND (ecosystem = ? OR ecosystem = ''))
                         )
                       LIMIT 1""",
                    (org_id, purl, name, version, ecosystem),
                ).fetchone()
                if comp_row:
                    vuln_rows = conn.execute(
                        """SELECT cve_id, severity, cvss_score, fixed_in
                           FROM sbom_vulnerabilities
                           WHERE component_id = ? AND org_id = ?
                           ORDER BY cvss_score DESC""",
                        (comp_row["id"], org_id),
                    ).fetchall()
                    for vr in vuln_rows:
                        cves.append({
                            "cve_id": vr["cve_id"],
                            "severity": vr["severity"],
                            "cvss_score": float(vr["cvss_score"]),
                            "fix_version": vr["fixed_in"] or None,
                            "source": "sbom_export",
                        })
        except Exception:
            _logger.debug("sbom_export lookup failed for purl %s", purl, exc_info=True)

        # --- Secondary: cve_intel affected_products name match ---
        if not cves:
            name_lower = name.lower()
            with self._conn(org_id) as conn:
                rows = conn.execute(
                    """SELECT cve_id, severity, cvss_score, patch_url, affected_products
                       FROM cve_intel
                       WHERE org_id = ?
                       ORDER BY cvss_score DESC""",
                    (org_id,),
                ).fetchall()
            for row in rows:
                try:
                    products = json.loads(row["affected_products"] or "[]")
                except (json.JSONDecodeError, TypeError):
                    products = []
                matched = False
                for p in products:
                    prod_name = (
                        (p.get("product") or p.get("name") or str(p))
                        if isinstance(p, dict)
                        else str(p)
                    ).lower()
                    if name_lower in prod_name or prod_name in name_lower:
                        matched = True
                        break
                if matched:
                    cves.append({
                        "cve_id": row["cve_id"],
                        "severity": row["severity"],
                        "cvss_score": float(row["cvss_score"]),
                        "fix_version": None,
                        "source": "cve_intel",
                    })

        # --- Tertiary: SCA engine _KNOWN_VULNERABLE in-memory table ---
        if not cves:
            try:
                from core.software_composition_analysis_engine import _KNOWN_VULNERABLE
                name_lower = name.lower()
                for vuln_name, vuln_list in _KNOWN_VULNERABLE.items():
                    if vuln_name in name_lower or name_lower in vuln_name:
                        for v in vuln_list:
                            cves.append({
                                "cve_id": v["cve_id"],
                                "severity": "high",
                                "cvss_score": 0.0,
                                "fix_version": None,
                                "source": "sca_known",
                            })
                        break
            except Exception:
                _logger.debug("_KNOWN_VULNERABLE lookup failed", exc_info=True)

        risk_score = max((c["cvss_score"] for c in cves), default=0.0)

        return {
            "package": {
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "purl": purl,
            },
            "cves": cves,
            "cve_count": len(cves),
            "risk_score": round(risk_score, 2),
            "vulnerable": len(cves) > 0,
        }

    def get_intel_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated vuln intelligence stats for org."""
        with self._conn(org_id) as conn:
            total_cves = conn.execute(
                "SELECT COUNT(*) FROM cve_intel WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_severity = {
                r["severity"]: r["cnt"]
                for r in conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM cve_intel "
                    "WHERE org_id = ? GROUP BY severity",
                    (org_id,),
                ).fetchall()
            }

            kev_count = conn.execute(
                "SELECT COUNT(*) FROM cve_intel WHERE org_id = ? AND kev_listed = 1",
                (org_id,),
            ).fetchone()[0]

            exploit_available = conn.execute(
                "SELECT COUNT(*) FROM cve_intel WHERE org_id = ? AND exploit_available = 1",
                (org_id,),
            ).fetchone()[0]

            patch_available = conn.execute(
                "SELECT COUNT(*) FROM cve_intel WHERE org_id = ? AND patch_available = 1",
                (org_id,),
            ).fetchone()[0]

            avg_epss_row = conn.execute(
                "SELECT AVG(epss_score) FROM cve_intel WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_epss = round(float(avg_epss_row or 0.0), 4)

            # Top affected products: parse JSON, aggregate
            top_products: Dict[str, int] = {}
            rows = conn.execute(
                "SELECT affected_products FROM cve_intel WHERE org_id = ?", (org_id,)
            ).fetchall()
            for row in rows:
                try:
                    products = json.loads(row[0] or "[]")
                    if isinstance(products, list):
                        for p in products:
                            if isinstance(p, dict):
                                key = f"{p.get('vendor','?')}/{p.get('product','?')}"
                            else:
                                key = str(p)
                            top_products[key] = top_products.get(key, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    pass
            top_products_sorted = sorted(
                top_products.items(), key=lambda x: x[1], reverse=True
            )[:10]

            advisories_pending = conn.execute(
                "SELECT COUNT(*) FROM vendor_advisories "
                "WHERE org_id = ? AND status = 'new'",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_cves": total_cves,
            "by_severity": by_severity,
            "kev_count": kev_count,
            "exploit_available": exploit_available,
            "patch_available": patch_available,
            "avg_epss": avg_epss,
            "top_affected_products": [
                {"product": k, "count": v} for k, v in top_products_sorted
            ],
            "advisories_pending": advisories_pending,
        }
