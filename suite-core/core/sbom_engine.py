"""Software Bill of Materials (SBOM) Generation Engine — ALDECI.

Generates, stores, and exports SBOMs in CycloneDX 1.4 and SPDX 2.3 formats.

Capabilities:
  - Asset and component registry (multi-tenant, org-scoped WAL SQLite)
  - Package URL (purl) auto-generation from component metadata
  - CycloneDX 1.4 JSON export with vulnerability mappings
  - SPDX 2.3 JSON export with external references
  - License risk classification (GPL→high, MIT/Apache→low, unknown→medium)
  - Vulnerability exposure analytics per org
  - Cross-org isolation — org_a data never visible from org_b

Compliance: NTIA SBOM Minimum Elements, CycloneDX 1.4, SPDX 2.3, EO 14028
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

_logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_ASSET_TYPES = {"application", "container", "firmware", "device", "service"}
_VALID_COMPONENT_TYPES = {"library", "framework", "os", "runtime", "tool", "device"}
_VALID_SBOM_FORMATS = {"spdx", "cyclonedx"}

# SPDX license identifier → risk level
_LICENSE_RISK_MAP: Dict[str, str] = {
    "GPL-2.0": "high",
    "GPL-2.0-only": "high",
    "GPL-2.0-or-later": "high",
    "GPL-3.0": "high",
    "GPL-3.0-only": "high",
    "GPL-3.0-or-later": "high",
    "AGPL-3.0": "high",
    "AGPL-3.0-only": "high",
    "AGPL-3.0-or-later": "high",
    "SSPL-1.0": "high",
    "LGPL-2.0": "medium",
    "LGPL-2.1": "medium",
    "LGPL-3.0": "medium",
    "BUSL-1.1": "medium",
    "MPL-2.0": "medium",
    "CDDL-1.0": "medium",
    "EPL-1.0": "medium",
    "EPL-2.0": "medium",
    "MIT": "low",
    "MIT-0": "low",
    "Apache-2.0": "low",
    "BSD-2-Clause": "low",
    "BSD-3-Clause": "low",
    "ISC": "low",
    "Unlicense": "low",
    "CC0-1.0": "low",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _license_risk(spdx_id: str) -> str:
    """Return high/medium/low risk for a given SPDX license identifier."""
    if not spdx_id:
        return "medium"
    return _LICENSE_RISK_MAP.get(spdx_id, "medium")


def _build_purl(component_type: str, name: str, version: str, ecosystem: str = "") -> str:
    """Construct a Package URL (purl) from component metadata.

    Examples:
      npm + lodash + 4.17.21  → pkg:npm/lodash@4.17.21
      pypi + requests + 2.28  → pkg:pypi/requests@2.28
      generic + openssl + 3.0 → pkg:generic/openssl@3.0
    """
    eco = (ecosystem or "").lower().strip()
    name_clean = (name or "unknown").strip()
    ver_clean = (version or "").strip()
    ver_suffix = f"@{ver_clean}" if ver_clean else ""

    _KNOWN_ECOSYSTEMS = {
        "npm", "pypi", "maven", "go", "cargo", "nuget", "gem", "hex",
        "composer", "swift", "conan", "conda", "pub", "hackage",
    }

    if eco in _KNOWN_ECOSYSTEMS:
        pkg_type = eco
    elif component_type in {"library", "framework"}:
        # Heuristic: Java-style groupId.artifactId → maven
        if "." in name_clean and name_clean[0].islower():
            pkg_type = "maven"
        else:
            pkg_type = "generic"
    else:
        pkg_type = "generic"

    return f"pkg:{pkg_type}/{name_clean}{ver_suffix}"


class SBOMEngine:
    """SQLite WAL-backed SBOM engine.

    Thread-safe via per-org RLock. Multi-tenant via org_id-scoped DB files
    at .fixops_data/{org_id}_sbom.db.
    """

    def __init__(self, data_dir: Optional[str] = None) -> None:
        self._data_dir = Path(data_dir) if data_dir else _DATA_DIR
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_mutex = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _db_path(self, org_id: str) -> str:
        return str(self._data_dir / f"{org_id}_sbom.db")

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._locks_mutex:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _init_db(self, org_id: str) -> None:
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS sbom_assets (
                        id              TEXT PRIMARY KEY,
                        org_id          TEXT NOT NULL,
                        asset_name      TEXT NOT NULL,
                        asset_type      TEXT NOT NULL DEFAULT 'application',
                        asset_version   TEXT NOT NULL DEFAULT '',
                        description     TEXT NOT NULL DEFAULT '',
                        team_owner      TEXT NOT NULL DEFAULT '',
                        sbom_format     TEXT NOT NULL DEFAULT 'cyclonedx',
                        component_count INTEGER NOT NULL DEFAULT 0,
                        vuln_count      INTEGER NOT NULL DEFAULT 0,
                        high_risk_count INTEGER NOT NULL DEFAULT 0,
                        last_scan       TEXT NOT NULL DEFAULT '',
                        created_at      TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_assets_org
                        ON sbom_assets (org_id);

                    CREATE TABLE IF NOT EXISTS sbom_components (
                        id                TEXT PRIMARY KEY,
                        org_id            TEXT NOT NULL,
                        asset_id          TEXT NOT NULL,
                        asset_name        TEXT NOT NULL DEFAULT '',
                        asset_type        TEXT NOT NULL DEFAULT 'application',
                        component_name    TEXT NOT NULL,
                        component_version TEXT NOT NULL DEFAULT '',
                        component_type    TEXT NOT NULL DEFAULT 'library',
                        purl              TEXT NOT NULL DEFAULT '',
                        cpe               TEXT NOT NULL DEFAULT '',
                        license           TEXT NOT NULL DEFAULT '',
                        supplier          TEXT NOT NULL DEFAULT '',
                        known_vulns       TEXT NOT NULL DEFAULT '[]',
                        risk_score        REAL NOT NULL DEFAULT 0.0,
                        created_at        TEXT NOT NULL,
                        updated_at        TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_comp_org_asset
                        ON sbom_components (org_id, asset_id);

                    CREATE INDEX IF NOT EXISTS idx_comp_purl
                        ON sbom_components (org_id, purl);

                    CREATE TABLE IF NOT EXISTS sbom_exports (
                        id           TEXT PRIMARY KEY,
                        org_id       TEXT NOT NULL,
                        asset_id     TEXT NOT NULL,
                        format       TEXT NOT NULL DEFAULT 'cyclonedx',
                        spec_version TEXT NOT NULL DEFAULT '',
                        sbom_content TEXT NOT NULL DEFAULT '{}',
                        created_at   TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_exports_org_asset
                        ON sbom_exports (org_id, asset_id);

                    CREATE TABLE IF NOT EXISTS license_risks (
                        id           TEXT PRIMARY KEY,
                        org_id       TEXT NOT NULL,
                        license_spdx TEXT NOT NULL,
                        risk_level   TEXT NOT NULL DEFAULT 'medium',
                        count        INTEGER NOT NULL DEFAULT 1,
                        first_seen   TEXT NOT NULL,
                        created_at   TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_licrisks_org
                        ON license_risks (org_id, license_spdx);
                    """
                )

    def _ensure_db(self, org_id: str) -> None:
        """Initialize DB for org on first access."""
        if not Path(self._db_path(org_id)).exists():
            self._init_db(org_id)
        else:
            with self._conn(org_id) as conn:
                conn.execute("PRAGMA journal_mode=WAL")

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new asset for SBOM tracking. Returns the created record."""
        self._ensure_db(org_id)
        asset_name = (data.get("asset_name") or "").strip()
        if not asset_name:
            raise ValueError("asset_name is required.")

        asset_type = data.get("asset_type", "application")
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(
                f"Invalid asset_type: {asset_type}. Must be one of {_VALID_ASSET_TYPES}"
            )

        sbom_format = data.get("sbom_format", "cyclonedx")
        if sbom_format not in _VALID_SBOM_FORMATS:
            sbom_format = "cyclonedx"

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "asset_version": data.get("asset_version", ""),
            "description": data.get("description", ""),
            "team_owner": data.get("team_owner", ""),
            "sbom_format": sbom_format,
            "component_count": 0,
            "vuln_count": 0,
            "high_risk_count": 0,
            "last_scan": now,
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO sbom_assets
                       (id, org_id, asset_name, asset_type, asset_version, description,
                        team_owner, sbom_format, component_count, vuln_count,
                        high_risk_count, last_scan, created_at)
                       VALUES (:id, :org_id, :asset_name, :asset_type, :asset_version,
                               :description, :team_owner, :sbom_format, :component_count,
                               :vuln_count, :high_risk_count, :last_scan, :created_at)""",
                    record,
                )
        return record

    def list_assets(self, org_id: str) -> List[Dict[str, Any]]:
        """List all assets for an org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            rows = conn.execute(
                "SELECT * FROM sbom_assets WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get asset with live component summary."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM sbom_assets WHERE org_id = ? AND id = ?",
                (org_id, asset_id),
            ).fetchone()
            if not row:
                return None
            asset = self._row(row)

            comp_count = conn.execute(
                "SELECT COUNT(*) FROM sbom_components WHERE org_id = ? AND asset_id = ?",
                (org_id, asset_id),
            ).fetchone()[0]

            vuln_rows = conn.execute(
                "SELECT known_vulns FROM sbom_components WHERE org_id = ? AND asset_id = ?",
                (org_id, asset_id),
            ).fetchall()
            vuln_count = 0
            for vr in vuln_rows:
                try:
                    vuln_count += len(json.loads(vr[0] or "[]"))
                except (json.JSONDecodeError, TypeError):
                    pass

            high_risk = conn.execute(
                """SELECT COUNT(*) FROM sbom_components
                   WHERE org_id = ? AND asset_id = ? AND risk_score >= 7.0""",
                (org_id, asset_id),
            ).fetchone()[0]

        asset["component_count"] = comp_count
        asset["vuln_count"] = vuln_count
        asset["high_risk_count"] = high_risk
        return asset

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    def add_component(
        self, org_id: str, asset_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a component to an asset's SBOM. Auto-generates purl if missing."""
        self._ensure_db(org_id)

        component_name = (data.get("component_name") or "").strip()
        if not component_name:
            raise ValueError("component_name is required.")

        component_type = data.get("component_type", "library")
        if component_type not in _VALID_COMPONENT_TYPES:
            raise ValueError(
                f"Invalid component_type: {component_type}. "
                f"Must be one of {_VALID_COMPONENT_TYPES}"
            )

        # Resolve asset metadata for denormalisation
        asset_name = data.get("asset_name", "")
        asset_type_val = data.get("asset_type", "application")
        if not asset_name:
            asset = self.get_asset(org_id, asset_id)
            if asset:
                asset_name = asset.get("asset_name", "")
                asset_type_val = asset.get("asset_type", "application")

        component_version = data.get("component_version", "")
        ecosystem = data.get("ecosystem", "")

        # Auto-generate purl when not supplied
        purl = (data.get("purl") or "").strip()
        if not purl:
            purl = _build_purl(component_type, component_name, component_version, ecosystem)

        known_vulns = data.get("known_vulns", [])
        if isinstance(known_vulns, str):
            try:
                known_vulns = json.loads(known_vulns)
            except (json.JSONDecodeError, ValueError):
                known_vulns = []
        if not isinstance(known_vulns, list):
            known_vulns = []

        vuln_count = len(known_vulns)
        # risk_score: caller may supply; otherwise derive from vuln count (2 pts/vuln, max 10)
        risk_score = float(data.get("risk_score", min(vuln_count * 2.0, 10.0)))

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "asset_name": asset_name,
            "asset_type": asset_type_val,
            "component_name": component_name,
            "component_version": component_version,
            "component_type": component_type,
            "purl": purl,
            "cpe": data.get("cpe", ""),
            "license": data.get("license", ""),
            "supplier": data.get("supplier", ""),
            "known_vulns": json.dumps(known_vulns),
            "risk_score": risk_score,
            "created_at": now,
            "updated_at": now,
        }

        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO sbom_components
                       (id, org_id, asset_id, asset_name, asset_type, component_name,
                        component_version, component_type, purl, cpe, license, supplier,
                        known_vulns, risk_score, created_at, updated_at)
                       VALUES (:id, :org_id, :asset_id, :asset_name, :asset_type,
                               :component_name, :component_version, :component_type,
                               :purl, :cpe, :license, :supplier, :known_vulns,
                               :risk_score, :created_at, :updated_at)""",
                    record,
                )
                conn.execute(
                    """UPDATE sbom_assets
                       SET component_count = component_count + 1,
                           last_scan = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, org_id, asset_id),
                )

        # Upsert license_risks
        lic = record["license"]
        if lic:
            self._upsert_license_risk(org_id, lic, now)

        return record

    def _upsert_license_risk(self, org_id: str, lic: str, now: str) -> None:
        risk_lvl = _license_risk(lic)
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                existing = conn.execute(
                    "SELECT id FROM license_risks WHERE org_id = ? AND license_spdx = ?",
                    (org_id, lic),
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE license_risks SET count = count + 1 WHERE id = ?",
                        (existing["id"],),
                    )
                else:
                    conn.execute(
                        """INSERT INTO license_risks
                           (id, org_id, license_spdx, risk_level, count, first_seen, created_at)
                           VALUES (?, ?, ?, ?, 1, ?, ?)""",
                        (str(uuid.uuid4()), org_id, lic, risk_lvl, now, now),
                    )

    def list_components(
        self,
        org_id: str,
        asset_id: Optional[str] = None,
        has_vulns: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List components with optional asset_id and has_vulns filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM sbom_components WHERE org_id = ?"
        params: list = [org_id]
        if asset_id:
            sql += " AND asset_id = ?"
            params.append(asset_id)
        sql += " ORDER BY created_at DESC"

        with self._conn(org_id) as conn:
            rows = conn.execute(sql, params).fetchall()

        results: List[Dict[str, Any]] = []
        for row in rows:
            d = self._row(row)
            try:
                vulns = json.loads(d.get("known_vulns") or "[]")
            except (json.JSONDecodeError, TypeError):
                vulns = []
            d["known_vulns"] = vulns

            if has_vulns is True and not vulns:
                continue
            if has_vulns is False and vulns:
                continue
            results.append(d)

        return results

    # ------------------------------------------------------------------
    # CycloneDX 1.4 export
    # ------------------------------------------------------------------

    def generate_cyclonedx(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Generate a CycloneDX 1.4 JSON SBOM for an asset."""
        self._ensure_db(org_id)
        asset = self.get_asset(org_id, asset_id)
        if not asset:
            raise ValueError(f"Asset not found: {asset_id}")

        components_raw = self.list_components(org_id, asset_id=asset_id)

        cdx_components: List[Dict[str, Any]] = []
        for c in components_raw:
            entry: Dict[str, Any] = {
                "type": c.get("component_type", "library"),
                "name": c.get("component_name", ""),
                "version": c.get("component_version", ""),
            }
            if c.get("purl"):
                entry["purl"] = c["purl"]
            if c.get("cpe"):
                entry["cpe"] = c["cpe"]
            lic = c.get("license", "")
            if lic:
                entry["licenses"] = [{"license": {"id": lic}}]
            if c.get("supplier"):
                entry["supplier"] = {"name": c["supplier"]}
            cdx_components.append(entry)

        # Build vulnerability entries from known_vulns across all components
        cdx_vulns: List[Dict[str, Any]] = []
        seen_cves: set = set()
        for c in components_raw:
            vulns = c.get("known_vulns", [])
            if isinstance(vulns, str):
                try:
                    vulns = json.loads(vulns)
                except (json.JSONDecodeError, TypeError):
                    vulns = []
            rs = float(c.get("risk_score") or 0.0)
            sev = (
                "critical" if rs >= 9.0
                else "high" if rs >= 7.0
                else "medium" if rs >= 4.0
                else "low"
            )
            ref = c.get("purl") or c.get("component_name", "")
            for cve in vulns:
                if cve and cve not in seen_cves:
                    seen_cves.add(cve)
                    cdx_vulns.append({
                        "id": cve,
                        "affects": [{"ref": ref}],
                        "ratings": [{"severity": sev}],
                    })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": _now_iso(),
                "component": {
                    "name": asset.get("asset_name", ""),
                    "version": asset.get("asset_version", ""),
                    "type": asset.get("asset_type", "application"),
                },
            },
            "components": cdx_components,
            "vulnerabilities": cdx_vulns,
        }

    # ------------------------------------------------------------------
    # SPDX 2.3 export
    # ------------------------------------------------------------------

    def generate_spdx(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Generate an SPDX 2.3 JSON SBOM for an asset."""
        self._ensure_db(org_id)
        asset = self.get_asset(org_id, asset_id)
        if not asset:
            raise ValueError(f"Asset not found: {asset_id}")

        components_raw = self.list_components(org_id, asset_id=asset_id)
        doc_namespace = f"https://aldeci.io/sbom/{uuid.uuid4()}"

        packages: List[Dict[str, Any]] = []
        for i, c in enumerate(components_raw):
            lic = c.get("license", "")
            pkg: Dict[str, Any] = {
                "SPDXID": f"SPDXRef-{i}",
                "name": c.get("component_name", ""),
                "versionInfo": c.get("component_version", ""),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": lic if lic else "NOASSERTION",
                "licenseDeclared": lic if lic else "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
            ext_refs = []
            purl = c.get("purl", "")
            if purl:
                ext_refs.append({
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                })
            cpe = c.get("cpe", "")
            if cpe:
                ext_refs.append({
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": cpe,
                })
            if ext_refs:
                pkg["externalRefs"] = ext_refs
            supplier = c.get("supplier", "")
            if supplier:
                pkg["supplier"] = f"Organization: {supplier}"
            packages.append(pkg)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": asset.get("asset_name", ""),
            "documentNamespace": doc_namespace,
            "documentDescribes": ["SPDXRef-DOCUMENT"],
            "packages": packages,
            "creationInfo": {
                "created": _now_iso(),
                "creators": ["Tool: ALDECI SBOM Engine 1.0"],
            },
        }

    # ------------------------------------------------------------------
    # Export persistence
    # ------------------------------------------------------------------

    def save_export(
        self,
        org_id: str,
        asset_id: str,
        format: str,
        content: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Persist an SBOM export to sbom_exports table."""
        self._ensure_db(org_id)
        fmt = format.lower()
        spec_version = "1.4" if fmt == "cyclonedx" else "2.3"
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "format": fmt,
            "spec_version": spec_version,
            "sbom_content": json.dumps(content),
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO sbom_exports
                       (id, org_id, asset_id, format, spec_version, sbom_content, created_at)
                       VALUES (:id, :org_id, :asset_id, :format, :spec_version,
                               :sbom_content, :created_at)""",
                    record,
                )
        record["sbom_content"] = content  # return parsed dict, not JSON string
        return record

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_license_summary(self, org_id: str) -> Dict[str, Any]:
        """Return license risk breakdown for the org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            rows = conn.execute(
                """SELECT license_spdx, risk_level, count
                   FROM license_risks WHERE org_id = ?
                   ORDER BY count DESC""",
                (org_id,),
            ).fetchall()

        summary: Dict[str, Any] = {
            "high": [], "medium": [], "low": [], "total_unique": 0,
        }
        for row in rows:
            entry = {"license": row["license_spdx"], "count": row["count"]}
            risk = row["risk_level"]
            if risk in summary:
                summary[risk].append(entry)
            summary["total_unique"] += 1

        summary["high_count"] = sum(e["count"] for e in summary["high"])
        summary["medium_count"] = sum(e["count"] for e in summary["medium"])
        summary["low_count"] = sum(e["count"] for e in summary["low"])
        return summary

    def get_vuln_exposure(self, org_id: str) -> Dict[str, Any]:
        """Return vulnerability exposure statistics for the org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            rows = conn.execute(
                "SELECT known_vulns, risk_score FROM sbom_components WHERE org_id = ?",
                (org_id,),
            ).fetchall()

        total_components = len(rows)
        vulnerable_components = 0
        all_vulns: Dict[str, Dict[str, Any]] = {}
        by_severity: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        }

        for row in rows:
            try:
                vulns = json.loads(row["known_vulns"] or "[]")
            except (json.JSONDecodeError, TypeError):
                vulns = []

            if vulns:
                vulnerable_components += 1

            rs = float(row["risk_score"] or 0.0)
            sev = (
                "critical" if rs >= 9.0
                else "high" if rs >= 7.0
                else "medium" if rs >= 4.0
                else "low"
            )

            for cve in vulns:
                if cve not in all_vulns:
                    all_vulns[cve] = {"cve_id": cve, "severity": sev, "affected_count": 0}
                all_vulns[cve]["affected_count"] += 1
                by_severity[sev] = by_severity.get(sev, 0) + 1

        top_vulns = sorted(
            all_vulns.values(),
            key=lambda x: x["affected_count"],
            reverse=True,
        )[:10]

        return {
            "total_components": total_components,
            "vulnerable_components": vulnerable_components,
            "by_severity": by_severity,
            "top_vulns": top_vulns,
        }

    def get_sbom_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated SBOM stats for the org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM sbom_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_components = conn.execute(
                "SELECT COUNT(*) FROM sbom_components WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            asset_ids_with_vulns: set = set()
            vuln_rows = conn.execute(
                "SELECT asset_id, known_vulns FROM sbom_components WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            for vr in vuln_rows:
                try:
                    if json.loads(vr["known_vulns"] or "[]"):
                        asset_ids_with_vulns.add(vr["asset_id"])
                except (json.JSONDecodeError, TypeError):
                    pass

            license_risk_high = conn.execute(
                """SELECT COALESCE(SUM(count), 0)
                   FROM license_risks WHERE org_id = ? AND risk_level = 'high'""",
                (org_id,),
            ).fetchone()[0]

            formats_exported_rows = conn.execute(
                "SELECT DISTINCT format FROM sbom_exports WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            formats_exported = [r["format"] for r in formats_exported_rows]

        return {
            "total_assets": total_assets,
            "total_components": total_components,
            "assets_with_vulns": len(asset_ids_with_vulns),
            "license_risk_high": int(license_risk_high),
            "formats_exported": formats_exported,
        }
