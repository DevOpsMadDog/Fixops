"""
SBOM Engine — ALDECI.

Software Bill of Materials generation, import, and analysis engine.

Capabilities:
- Generate SBOMs in CycloneDX v1.4 (JSON) or SPDX 2.3 (JSON) format
- Detect installed Python packages and derive components from requirements.txt
- Import external SBOMs (CycloneDX or SPDX)
- Cross-reference components with CVE enrichment data
- License distribution summary
- Dependency graph (DAG) with risk scores

Storage: SQLite WAL at data/sbom.db (thread-local connections)

Compliance: NTIA SBOM minimum elements, EO 14028, NIST SSDF
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Database path
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = "data/sbom.db"

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS sboms (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL DEFAULT 'default',
    asset_id    TEXT NOT NULL DEFAULT '',
    format      TEXT NOT NULL DEFAULT 'cyclonedx',
    name        TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '1',
    component_count INTEGER NOT NULL DEFAULT 0,
    sbom_json   TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'generated'
);
CREATE INDEX IF NOT EXISTS idx_sboms_org  ON sboms(org_id);
CREATE INDEX IF NOT EXISTS idx_sboms_asset ON sboms(org_id, asset_id);

CREATE TABLE IF NOT EXISTS sbom_components (
    id          TEXT PRIMARY KEY,
    sbom_id     TEXT NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    org_id      TEXT NOT NULL DEFAULT 'default',
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    purl        TEXT NOT NULL DEFAULT '',
    license     TEXT NOT NULL DEFAULT 'NOASSERTION',
    component_type TEXT NOT NULL DEFAULT 'library',
    metadata    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_comp_sbom  ON sbom_components(sbom_id);
CREATE INDEX IF NOT EXISTS idx_comp_org   ON sbom_components(org_id);
CREATE INDEX IF NOT EXISTS idx_comp_name  ON sbom_components(org_id, name);
"""

# ---------------------------------------------------------------------------
# Internal DB helper
# ---------------------------------------------------------------------------


class _SBOMDb:
    """Thread-local SQLite connection wrapper."""

    def __init__(self, db_path: str) -> None:
        self._path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_schema(self) -> None:
        conn = self._conn()
        conn.executescript(_DDL)
        conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self._conn().execute(sql, params)

    def executemany(self, sql: str, params_seq: list) -> None:
        self._conn().executemany(sql, params_seq)

    def commit(self) -> None:
        self._conn().commit()


# ---------------------------------------------------------------------------
# Component discovery helpers
# ---------------------------------------------------------------------------


def _discover_installed_packages() -> List[Dict[str, Any]]:
    """Return installed Python packages as component dicts."""
    components: List[Dict[str, Any]] = []
    try:
        for dist in importlib_metadata.distributions():
            name = dist.metadata.get("Name", "unknown")
            version = dist.metadata.get("Version", "0.0.0")
            license_val = dist.metadata.get("License", "NOASSERTION") or "NOASSERTION"
            purl = f"pkg:pypi/{name.lower()}@{version}"
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "licenses": [{"license": {"id": license_val}}],
            })
    except Exception as exc:
        _logger.warning("package_discovery_failed", error=str(exc))
    return components


def _parse_requirements(req_path: str) -> List[Dict[str, Any]]:
    """Parse a requirements.txt file into component dicts."""
    components: List[Dict[str, Any]] = []
    try:
        path = Path(req_path)
        if not path.exists():
            return components
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle ==, >=, <=, ~= specifiers
            for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                if sep in line:
                    name, version = line.split(sep, 1)
                    name = name.strip()
                    version = version.strip().split(",")[0].strip()
                    break
            else:
                name, version = line, "unknown"
            purl = f"pkg:pypi/{name.lower()}@{version}"
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "licenses": [{"license": {"id": "NOASSERTION"}}],
            })
    except Exception as exc:
        _logger.warning("requirements_parse_failed", path=req_path, error=str(exc))
    return components


# ---------------------------------------------------------------------------
# Format builders
# ---------------------------------------------------------------------------


def _build_cyclonedx(asset_id: str, components: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a CycloneDX 1.4 JSON SBOM document."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": now,
            "component": {
                "type": "application",
                "name": asset_id or "unknown",
                "version": "1.0.0",
            },
        },
        "components": [
            {
                "type": c.get("type", "library"),
                "name": c.get("name", ""),
                "version": c.get("version", ""),
                "purl": c.get("purl", ""),
                "licenses": c.get("licenses", []),
            }
            for c in components
        ],
    }


def _build_spdx(asset_id: str, components: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build an SPDX 2.3 JSON SBOM document."""
    now = datetime.now(timezone.utc).isoformat()
    doc_name = asset_id or "unknown"
    packages = []
    for idx, c in enumerate(components):
        spdx_id = f"SPDXRef-Package-{idx}"
        license_val = "NOASSERTION"
        if c.get("licenses"):
            lic = c["licenses"][0]
            if isinstance(lic, dict):
                license_val = (
                    lic.get("license", {}).get("id")
                    or lic.get("expression")
                    or "NOASSERTION"
                )
        packages.append({
            "SPDXID": spdx_id,
            "name": c.get("name", ""),
            "versionInfo": c.get("version", ""),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": license_val,
            "licenseDeclared": license_val,
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.get("purl", ""),
                }
            ] if c.get("purl") else [],
        })
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": f"https://aldeci.local/sbom/{uuid.uuid4()}",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: ALDECI SBOM Engine"],
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": f"SPDXRef-Package-{i}",
            }
            for i in range(len(packages))
        ],
    }


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------


class SBOMEngine:
    """
    SBOM generation and management engine for ALDECI.

    Generates SBOMs by discovering installed Python packages and parsing
    requirements.txt (if present). Supports CycloneDX 1.4 and SPDX 2.3.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._db = _SBOMDb(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_sbom(
        self,
        org_id: str,
        asset_id: str,
        fmt: str = "cyclonedx",
        requirements_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate an SBOM for an asset.

        Discovers components from installed Python packages and optionally
        from a requirements.txt. Stores the result in SQLite.

        Args:
            org_id:            Organisation identifier.
            asset_id:          Asset / application identifier.
            fmt:               Output format — "cyclonedx" (default) or "spdx".
            requirements_path: Optional path to requirements.txt. If None,
                               defaults to "requirements.txt" in cwd.

        Returns:
            Full SBOM document (CycloneDX or SPDX JSON dict).
        """
        fmt = fmt.lower()
        if fmt not in ("cyclonedx", "spdx"):
            raise ValueError(f"Unsupported format '{fmt}'. Use 'cyclonedx' or 'spdx'.")

        # Discover components
        req_path = requirements_path or "requirements.txt"
        components = _parse_requirements(req_path)
        if not components:
            components = _discover_installed_packages()

        # Build the SBOM document
        if fmt == "spdx":
            sbom_doc = _build_spdx(asset_id, components)
            name = sbom_doc.get("name", asset_id)
        else:
            sbom_doc = _build_cyclonedx(asset_id, components)
            name = sbom_doc.get("metadata", {}).get("component", {}).get("name", asset_id)

        sbom_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Persist SBOM record
        self._db.execute(
            """
            INSERT INTO sboms (id, org_id, asset_id, format, name, version,
                               component_count, sbom_json, created_at, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sbom_id,
                org_id,
                asset_id,
                fmt,
                name,
                "1",
                len(components),
                json.dumps(sbom_doc),
                now,
                "generated",
            ),
        )

        # Persist components
        rows = [
            (
                str(uuid.uuid4()),
                sbom_id,
                org_id,
                c.get("name", ""),
                c.get("version", ""),
                c.get("purl", ""),
                (
                    (c.get("licenses") or [{}])[0]
                    .get("license", {})
                    .get("id", "NOASSERTION")
                    if c.get("licenses") else "NOASSERTION"
                ),
                c.get("type", "library"),
                "{}",
            )
            for c in components
        ]
        self._db.executemany(
            """
            INSERT INTO sbom_components
                (id, sbom_id, org_id, name, version, purl, license, component_type, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self._db.commit()

        sbom_doc["_sbom_id"] = sbom_id
        _logger.info(
            "sbom_generated",
            org_id=org_id,
            asset_id=asset_id,
            fmt=fmt,
            components=len(components),
        )
        return sbom_doc

    def list_sboms(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all SBOMs for *org_id* (metadata only, no full JSON)."""
        rows = self._db.execute(
            """
            SELECT id, org_id, asset_id, format, name, version,
                   component_count, created_at, source
            FROM sboms
            WHERE org_id = ?
            ORDER BY created_at DESC
            """,
            (org_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_sbom(self, sbom_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return the full SBOM JSON for *sbom_id* within *org_id*."""
        row = self._db.execute(
            "SELECT sbom_json, id, org_id, asset_id, format, created_at "
            "FROM sboms WHERE id = ? AND org_id = ?",
            (sbom_id, org_id),
        ).fetchone()
        if row is None:
            return None
        doc = json.loads(row["sbom_json"])
        doc["_sbom_id"] = row["id"]
        doc["_asset_id"] = row["asset_id"]
        doc["_format"] = row["format"]
        doc["_created_at"] = row["created_at"]
        return doc

    def import_sbom(self, org_id: str, sbom_data: Dict[str, Any]) -> str:
        """
        Import an external SBOM (CycloneDX or SPDX).

        Detects format from *sbom_data*, extracts components, and stores
        everything in SQLite.

        Returns:
            The new sbom_id (UUID string).
        """
        sbom_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Detect format and extract metadata + components
        if sbom_data.get("bomFormat", "").lower() == "cyclonedx":
            fmt = "cyclonedx"
            meta = sbom_data.get("metadata", {})
            name = meta.get("component", {}).get("name", "imported")
            version = str(sbom_data.get("version", "1"))
            raw_components = sbom_data.get("components", [])
            components = [
                {
                    "name": c.get("name", ""),
                    "version": c.get("version", ""),
                    "purl": c.get("purl", ""),
                    "type": c.get("type", "library"),
                    "licenses": c.get("licenses", []),
                }
                for c in raw_components
            ]
        elif sbom_data.get("spdxVersion", "").startswith("SPDX-"):
            fmt = "spdx"
            name = sbom_data.get("name", "imported")
            version = "1"
            raw_packages = sbom_data.get("packages", [])
            components = [
                {
                    "name": p.get("name", ""),
                    "version": p.get("versionInfo", ""),
                    "purl": next(
                        (
                            r.get("referenceLocator", "")
                            for r in p.get("externalRefs", [])
                            if r.get("referenceType") == "purl"
                        ),
                        "",
                    ),
                    "type": "library",
                    "licenses": [
                        {"license": {"id": p.get("licenseConcluded", "NOASSERTION")}}
                    ],
                }
                for p in raw_packages
            ]
        else:
            raise ValueError(
                "Unrecognised SBOM format. Expected CycloneDX (bomFormat) "
                "or SPDX (spdxVersion) JSON."
            )

        self._db.execute(
            """
            INSERT INTO sboms (id, org_id, asset_id, format, name, version,
                               component_count, sbom_json, created_at, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sbom_id,
                org_id,
                "",
                fmt,
                name,
                version,
                len(components),
                json.dumps(sbom_data),
                now,
                "imported",
            ),
        )

        rows = [
            (
                str(uuid.uuid4()),
                sbom_id,
                org_id,
                c.get("name", ""),
                c.get("version", ""),
                c.get("purl", ""),
                (
                    (c.get("licenses") or [{}])[0]
                    .get("license", {})
                    .get("id", "NOASSERTION")
                    if c.get("licenses") else "NOASSERTION"
                ),
                c.get("type", "library"),
                "{}",
            )
            for c in components
        ]
        if rows:
            self._db.executemany(
                """
                INSERT INTO sbom_components
                    (id, sbom_id, org_id, name, version, purl, license, component_type, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        self._db.commit()

        _logger.info(
            "sbom_imported",
            org_id=org_id,
            sbom_id=sbom_id,
            fmt=fmt,
            components=len(components),
        )
        return sbom_id

    def get_vulnerable_components(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Return components with known CVEs.

        Cross-references SBOM component names/versions against the CVE
        enrichment database (core.cve_enrichment) when available. Falls back
        to a best-effort name-match against common vulnerable packages.
        """
        components = self._db.execute(
            """
            SELECT sc.id, sc.name, sc.version, sc.purl, sc.license,
                   sc.component_type, s.asset_id, s.org_id
            FROM sbom_components sc
            JOIN sboms s ON sc.sbom_id = s.id
            WHERE sc.org_id = ?
            """,
            (org_id,),
        ).fetchall()

        vulnerable: List[Dict[str, Any]] = []

        # Try to use CVE enrichment engine if available
        cve_engine = None
        try:
            from core.cve_enrichment import CVEEnrichmentEngine  # type: ignore
            cve_engine = CVEEnrichmentEngine()
        except Exception:
            pass

        # Well-known vulnerable packages (fallback heuristic)
        _KNOWN_VULN_PACKAGES = {
            "log4j": "CVE-2021-44228",
            "log4j-core": "CVE-2021-44228",
            "log4shell": "CVE-2021-44228",
            "spring-core": "CVE-2022-22965",
            "struts2-core": "CVE-2017-5638",
            "openssl": "CVE-2022-0778",
            "requests": None,  # flag for version-based check
            "django": None,
            "flask": None,
            "pyyaml": None,
        }

        for row in components:
            comp = dict(row)
            name_lower = comp["name"].lower()
            cves_found: List[str] = []

            if cve_engine is not None:
                try:
                    result = cve_engine.search_cves(
                        query=f"{comp['name']} {comp['version']}",
                        limit=5,
                    )
                    cves_found = [
                        c.get("cve_id", "") for c in (result.get("cves") or [])
                    ]
                except Exception:
                    pass

            # Fallback heuristic
            if not cves_found:
                for pkg, cve in _KNOWN_VULN_PACKAGES.items():
                    if pkg in name_lower and cve:
                        cves_found.append(cve)

            if cves_found:
                comp["cves"] = cves_found
                comp["risk"] = "high" if len(cves_found) >= 2 else "medium"
                vulnerable.append(comp)

        return vulnerable

    def get_license_summary(self, org_id: str) -> Dict[str, int]:
        """Return license distribution: {license_id: count, ...}."""
        rows = self._db.execute(
            """
            SELECT license, COUNT(*) as cnt
            FROM sbom_components
            WHERE org_id = ?
            GROUP BY license
            ORDER BY cnt DESC
            """,
            (org_id,),
        ).fetchall()
        return {row["license"]: row["cnt"] for row in rows}

    def get_dependency_graph(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """
        Return a DAG of dependencies with basic risk scores.

        Looks up the most recent SBOM for *asset_id* and constructs nodes
        and edges. Risk score is heuristic: GPL = higher, unknown version = medium.
        """
        row = self._db.execute(
            """
            SELECT id FROM sboms
            WHERE org_id = ? AND asset_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (org_id, asset_id),
        ).fetchone()

        if row is None:
            return {"nodes": [], "edges": [], "asset_id": asset_id, "org_id": org_id}

        sbom_id = row["id"]
        components = self._db.execute(
            """
            SELECT id, name, version, purl, license, component_type
            FROM sbom_components
            WHERE sbom_id = ?
            """,
            (sbom_id,),
        ).fetchall()

        nodes = []
        for comp in components:
            c = dict(comp)
            # Simple heuristic risk scoring
            lic = (c.get("license") or "NOASSERTION").upper()
            if "GPL" in lic and "LGPL" not in lic:
                risk_score = 60
                risk_level = "medium"
            elif c.get("version", "") in ("unknown", "", "0.0.0"):
                risk_score = 50
                risk_level = "medium"
            else:
                risk_score = 20
                risk_level = "low"
            nodes.append({
                "id": c["id"],
                "name": c["name"],
                "version": c["version"],
                "purl": c["purl"],
                "license": c["license"],
                "type": c["component_type"],
                "risk_score": risk_score,
                "risk_level": risk_level,
            })

        # Edges: each component -> asset (flat SBOM — no transitive info)
        edges = [
            {"source": asset_id, "target": n["id"], "relationship": "depends_on"}
            for n in nodes
        ]

        return {
            "asset_id": asset_id,
            "org_id": org_id,
            "sbom_id": sbom_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[SBOMEngine] = None
_engine_lock = threading.Lock()


def get_sbom_engine(db_path: str = _DEFAULT_DB_PATH) -> SBOMEngine:
    """Return the process-level SBOMEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = SBOMEngine(db_path=db_path)
    return _engine_instance
