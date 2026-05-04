"""
SBOM (Software Bill of Materials) Manager for ALDECI.

Provides lifecycle management for SBOMs: import/export (CycloneDX, SPDX),
vulnerability mapping, license compliance checking, and version diffing.

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
License: Proprietary (ALdeci).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SBOMFormat(str, Enum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    CUSTOM = "custom"


class LicenseRisk(str, Enum):
    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    COMMERCIAL = "commercial"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class Component(BaseModel):
    name: str
    version: str = ""
    purl: Optional[str] = None
    type: str = "library"  # library, framework, application
    licenses: List[str] = Field(default_factory=list)
    supplier: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict)


class SBOM(BaseModel):
    id: str
    format: SBOMFormat
    spec_version: str = ""
    created_at: str
    project_name: str
    project_version: str = ""
    components: List[Component] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    org_id: str = "default"


class VulnerableComponent(BaseModel):
    component: Component
    cve_ids: List[str] = Field(default_factory=list)
    severity: str = "unknown"
    fix_version: Optional[str] = None
    risk_score: float = 0.0


# ---------------------------------------------------------------------------
# License classification data
# ---------------------------------------------------------------------------

_PERMISSIVE = {
    "mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "isc",
    "0bsd", "unlicense", "wtfpl", "cc0-1.0",
}
_WEAK_COPYLEFT = {
    "lgpl-2.1", "lgpl-3.0", "mpl-2.0", "epl-2.0", "epl-1.0",
    "lgpl-2.1-or-later", "lgpl-3.0-or-later",
}
_STRONG_COPYLEFT = {
    "gpl-2.0", "gpl-3.0", "agpl-3.0",
    "gpl-2.0-only", "gpl-3.0-only", "agpl-3.0-only",
    "gpl-2.0-or-later", "gpl-3.0-or-later",
}

# ---------------------------------------------------------------------------
# Mock CVE data for vulnerability mapping (in production would query NVD/OSV)
# ---------------------------------------------------------------------------

_KNOWN_VULNERABILITIES: Dict[str, List[Dict[str, Any]]] = {
    "log4j-core": [
        {"cve_id": "CVE-2021-44228", "severity": "critical", "fix_version": "2.17.1"},
        {"cve_id": "CVE-2021-45046", "severity": "critical", "fix_version": "2.17.1"},
    ],
    "spring-core": [
        {"cve_id": "CVE-2022-22965", "severity": "critical", "fix_version": "5.3.18"},
    ],
    "lodash": [
        {"cve_id": "CVE-2021-23337", "severity": "high", "fix_version": "4.17.21"},
    ],
    "axios": [
        {"cve_id": "CVE-2023-45857", "severity": "medium", "fix_version": "1.6.0"},
    ],
    "openssl": [
        {"cve_id": "CVE-2022-0778", "severity": "high", "fix_version": "1.1.1n"},
    ],
}


# ---------------------------------------------------------------------------
# SBOMManager
# ---------------------------------------------------------------------------

class SBOMManager:
    """SQLite-backed SBOM lifecycle manager."""

    def __init__(self, db_path: str = "data/sbom.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sboms (
                    id TEXT PRIMARY KEY,
                    format TEXT NOT NULL,
                    spec_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    project_version TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    org_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sbom_components (
                    id TEXT PRIMARY KEY,
                    sbom_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    purl TEXT,
                    type TEXT NOT NULL,
                    licenses TEXT NOT NULL,
                    supplier TEXT,
                    hashes TEXT NOT NULL,
                    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_sbom_components_sbom_id
                    ON sbom_components(sbom_id);
                CREATE INDEX IF NOT EXISTS idx_sboms_org_id
                    ON sboms(org_id);
                CREATE INDEX IF NOT EXISTS idx_sboms_project_name
                    ON sboms(project_name);
                """
            )

    def _row_to_sbom(self, row: sqlite3.Row, components: List[Component]) -> SBOM:
        return SBOM(
            id=row["id"],
            format=SBOMFormat(row["format"]),
            spec_version=row["spec_version"],
            created_at=row["created_at"],
            project_name=row["project_name"],
            project_version=row["project_version"],
            components=components,
            metadata=json.loads(row["metadata"]),
            org_id=row["org_id"],
        )

    def _load_components(self, sbom_id: str) -> List[Component]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM sbom_components WHERE sbom_id = ?", (sbom_id,)
            ).fetchall()
        return [
            Component(
                name=r["name"],
                version=r["version"],
                purl=r["purl"],
                type=r["type"],
                licenses=json.loads(r["licenses"]),
                supplier=r["supplier"],
                hashes=json.loads(r["hashes"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def import_sbom(
        self,
        content: str,
        format: SBOMFormat,
        project_name: str,
        org_id: str = "default",
    ) -> SBOM:
        """Parse CycloneDX or SPDX JSON and persist as SBOM."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON content: {exc}") from exc

        if format == SBOMFormat.CYCLONEDX:
            components, spec_version, project_version, metadata = self._parse_cyclonedx(data)
        elif format == SBOMFormat.SPDX:
            components, spec_version, project_version, metadata = self._parse_spdx(data)
        else:
            # CUSTOM: try to extract a components list generically
            components = []
            spec_version = data.get("specVersion", "")
            project_version = data.get("version", "")
            metadata = {}

        sbom_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        sbom = SBOM(
            id=sbom_id,
            format=format,
            spec_version=spec_version,
            created_at=created_at,
            project_name=project_name,
            project_version=project_version,
            components=components,
            metadata=metadata,
            org_id=org_id,
        )

        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO sboms
                   (id, format, spec_version, created_at, project_name,
                    project_version, metadata, org_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sbom.id,
                    sbom.format.value,
                    sbom.spec_version,
                    sbom.created_at,
                    sbom.project_name,
                    sbom.project_version,
                    json.dumps(sbom.metadata),
                    sbom.org_id,
                ),
            )
            # FIX #1: executemany — single round-trip instead of N individual INSERTs
            conn.executemany(
                """INSERT INTO sbom_components
                   (id, sbom_id, name, version, purl, type, licenses, supplier, hashes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        str(uuid.uuid4()),
                        sbom_id,
                        comp.name,
                        comp.version,
                        comp.purl,
                        comp.type,
                        json.dumps(comp.licenses),
                        comp.supplier,
                        json.dumps(comp.hashes),
                    )
                    for comp in components
                ],
            )

        logger.info("Imported SBOM %s (%s) with %d components", sbom_id, format.value, len(components))
        _emit_event("sbom_manager.sbom_imported", {
            "sbom_id": sbom_id,
            "org_id": org_id,
            "project_name": project_name,
            "format": format.value,
            "component_count": len(components),
        })
        return sbom

    def _parse_cyclonedx(
        self, data: Dict[str, Any]
    ) -> tuple[List[Component], str, str, Dict[str, Any]]:
        """Parse CycloneDX JSON format."""
        spec_version = data.get("specVersion", "1.4")
        metadata_raw = data.get("metadata", {})
        project_version = ""
        if isinstance(metadata_raw, dict):
            comp_meta = metadata_raw.get("component", {})
            if isinstance(comp_meta, dict):
                project_version = comp_meta.get("version", "")

        raw_components = data.get("components", [])
        components: List[Component] = []
        for c in raw_components:
            if not isinstance(c, dict):
                continue
            licenses: List[str] = []
            for lic_entry in c.get("licenses", []):
                if isinstance(lic_entry, dict):
                    lic = lic_entry.get("license", {})
                    if isinstance(lic, dict):
                        lic_id = lic.get("id") or lic.get("name", "")
                        if lic_id:
                            licenses.append(lic_id)
                    elif isinstance(lic, str):
                        licenses.append(lic)

            hashes: Dict[str, str] = {}
            for h in c.get("hashes", []):
                if isinstance(h, dict):
                    alg = h.get("alg", "")
                    val = h.get("content", "")
                    if alg and val:
                        hashes[alg] = val

            components.append(
                Component(
                    name=c.get("name", ""),
                    version=c.get("version", ""),
                    purl=c.get("purl"),
                    type=c.get("type", "library"),
                    licenses=licenses,
                    supplier=c.get("supplier", {}).get("name") if isinstance(c.get("supplier"), dict) else c.get("supplier"),
                    hashes=hashes,
                )
            )

        return components, spec_version, project_version, metadata_raw if isinstance(metadata_raw, dict) else {}

    def _parse_spdx(
        self, data: Dict[str, Any]
    ) -> tuple[List[Component], str, str, Dict[str, Any]]:
        """Parse SPDX JSON format."""
        spec_version = data.get("spdxVersion", "SPDX-2.3")
        project_version = data.get("documentNamespace", "")

        packages = data.get("packages", [])
        components: List[Component] = []
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            # Skip the document root package
            if pkg.get("SPDXID") == "SPDXRef-DOCUMENT":
                continue

            licenses: List[str] = []
            declared = pkg.get("licenseDeclared", "NOASSERTION")
            if declared and declared not in ("NOASSERTION", "NONE", ""):
                # Handle SPDX license expressions (simple split on AND/OR)
                for part in declared.replace(" AND ", " ").replace(" OR ", " ").split():
                    part = part.strip("()")
                    if part and part not in ("AND", "OR", "WITH"):
                        licenses.append(part)

            hashes: Dict[str, str] = {}
            for ck in pkg.get("checksums", []):
                if isinstance(ck, dict):
                    alg = ck.get("algorithm", "")
                    val = ck.get("checksumValue", "")
                    if alg and val:
                        hashes[alg] = val

            ext_refs = pkg.get("externalRefs", [])
            purl: Optional[str] = None
            for ref in ext_refs:
                if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
                    break

            components.append(
                Component(
                    name=pkg.get("name", ""),
                    version=pkg.get("versionInfo", ""),
                    purl=purl,
                    type="library",
                    licenses=licenses,
                    supplier=pkg.get("supplier"),
                    hashes=hashes,
                )
            )

        metadata: Dict[str, Any] = {
            "spdxVersion": spec_version,
            "dataLicense": data.get("dataLicense", ""),
            "name": data.get("name", ""),
            "documentNamespace": data.get("documentNamespace", ""),
        }
        return components, spec_version, project_version, metadata

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_sbom(self, sbom_id: str, format: SBOMFormat) -> str:
        """Export an SBOM as CycloneDX or SPDX JSON string."""
        sbom = self.get_sbom(sbom_id)

        if format == SBOMFormat.CYCLONEDX:
            return self._export_cyclonedx(sbom)
        elif format == SBOMFormat.SPDX:
            return self._export_spdx(sbom)
        else:
            return json.dumps(sbom.model_dump(), indent=2)

    def _export_cyclonedx(self, sbom: SBOM) -> str:
        doc: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": sbom.spec_version or "1.4",
            "version": 1,
            "serialNumber": f"urn:uuid:{sbom.id}",
            "metadata": {
                "timestamp": sbom.created_at,
                "component": {
                    "type": "application",
                    "name": sbom.project_name,
                    "version": sbom.project_version,
                },
            },
            "components": [],
        }
        for comp in sbom.components:
            c: Dict[str, Any] = {
                "type": comp.type,
                "name": comp.name,
                "version": comp.version,
            }
            if comp.purl:
                c["purl"] = comp.purl
            if comp.licenses:
                c["licenses"] = [{"license": {"id": lic}} for lic in comp.licenses]
            if comp.supplier:
                c["supplier"] = {"name": comp.supplier}
            if comp.hashes:
                c["hashes"] = [{"alg": alg, "content": val} for alg, val in comp.hashes.items()]
            doc["components"].append(c)
        return json.dumps(doc, indent=2)

    def _export_spdx(self, sbom: SBOM) -> str:
        doc: Dict[str, Any] = {
            "spdxVersion": sbom.spec_version or "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": sbom.project_name,
            "documentNamespace": f"https://spdx.org/spdxdocs/{sbom.id}",
            "packages": [],
        }
        for i, comp in enumerate(sbom.components):
            pkg: Dict[str, Any] = {
                "SPDXID": f"SPDXRef-Package-{i}",
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseDeclared": " AND ".join(comp.licenses) if comp.licenses else "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
            if comp.supplier:
                pkg["supplier"] = comp.supplier
            if comp.hashes:
                pkg["checksums"] = [
                    {"algorithm": alg, "checksumValue": val}
                    for alg, val in comp.hashes.items()
                ]
            if comp.purl:
                pkg["externalRefs"] = [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": comp.purl,
                    }
                ]
            doc["packages"].append(pkg)
        return json.dumps(doc, indent=2)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def get_sbom(self, sbom_id: str) -> SBOM:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM sboms WHERE id = ?", (sbom_id,)
            ).fetchone()
        if not row:
            raise KeyError(f"SBOM {sbom_id!r} not found")
        components = self._load_components(sbom_id)
        return self._row_to_sbom(row, components)

    def list_sboms(
        self,
        org_id: Optional[str] = None,
        project_name: Optional[str] = None,
    ) -> List[SBOM]:
        query = "SELECT * FROM sboms WHERE 1=1"
        params: List[Any] = []
        if org_id:
            query += " AND org_id = ?"
            params.append(org_id)
        if project_name:
            query += " AND project_name = ?"
            params.append(project_name)
        query += " ORDER BY created_at DESC"

        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
            if not rows:
                return []

            # FIX #2: single JOIN query for all components instead of N+1 per-SBOM SELECTs
            sbom_ids = [r["id"] for r in rows]
            placeholders = ",".join("?" * len(sbom_ids))
            comp_rows = conn.execute(
                f"SELECT * FROM sbom_components WHERE sbom_id IN ({placeholders})",
                sbom_ids,
            ).fetchall()

        # Group components by sbom_id in Python (O(M) pass, M = total components)
        from collections import defaultdict
        comp_map: Dict[str, List[Component]] = defaultdict(list)
        for cr in comp_rows:
            comp_map[cr["sbom_id"]].append(
                Component(
                    name=cr["name"],
                    version=cr["version"],
                    purl=cr["purl"],
                    type=cr["type"],
                    licenses=json.loads(cr["licenses"]),
                    supplier=cr["supplier"],
                    hashes=json.loads(cr["hashes"]),
                )
            )

        return [self._row_to_sbom(row, comp_map[row["id"]]) for row in rows]

    def get_components(self, sbom_id: str) -> List[Component]:
        # Validate sbom exists
        self.get_sbom(sbom_id)
        return self._load_components(sbom_id)

    def delete_sbom(self, sbom_id: str) -> None:
        self.get_sbom(sbom_id)  # raises KeyError if not found
        with self._get_conn() as conn:
            conn.execute("DELETE FROM sbom_components WHERE sbom_id = ?", (sbom_id,))
            conn.execute("DELETE FROM sboms WHERE id = ?", (sbom_id,))
        logger.info("Deleted SBOM %s", sbom_id)

    # ------------------------------------------------------------------
    # Vulnerability mapping
    # ------------------------------------------------------------------

    def map_vulnerabilities(self, sbom_id: str) -> List[VulnerableComponent]:
        """Match components against known CVE data."""
        components = self.get_components(sbom_id)
        results: List[VulnerableComponent] = []
        for comp in components:
            key = comp.name.lower()
            vulns = _KNOWN_VULNERABILITIES.get(key, [])
            if not vulns:
                continue
            cve_ids = [v["cve_id"] for v in vulns]
            severity = vulns[0]["severity"]
            fix_version = vulns[0].get("fix_version")
            risk_score = self.get_component_risk_score(comp)
            results.append(
                VulnerableComponent(
                    component=comp,
                    cve_ids=cve_ids,
                    severity=severity,
                    fix_version=fix_version,
                    risk_score=risk_score,
                )
            )
        return results

    # ------------------------------------------------------------------
    # License compliance
    # ------------------------------------------------------------------

    def classify_license(self, license_str: str) -> LicenseRisk:
        """Classify a license string into a risk tier."""
        if not license_str:
            return LicenseRisk.UNKNOWN
        normalized = license_str.strip().lower()
        # Commercial / proprietary check first
        if "commercial" in normalized or "proprietary" in normalized:
            return LicenseRisk.COMMERCIAL
        if normalized in _STRONG_COPYLEFT:
            return LicenseRisk.STRONG_COPYLEFT
        if normalized in _WEAK_COPYLEFT:
            return LicenseRisk.WEAK_COPYLEFT
        if normalized in _PERMISSIVE:
            return LicenseRisk.PERMISSIVE
        return LicenseRisk.UNKNOWN

    def check_licenses(self, sbom_id: str) -> List[Dict[str, Any]]:
        """Return license compliance report for all components."""
        components = self.get_components(sbom_id)
        report: List[Dict[str, Any]] = []
        for comp in components:
            if not comp.licenses:
                report.append(
                    {
                        "component": comp.name,
                        "version": comp.version,
                        "licenses": [],
                        "risk": LicenseRisk.UNKNOWN.value,
                        "flagged": True,
                        "reason": "No license declared",
                    }
                )
                continue
            risks = [self.classify_license(lic) for lic in comp.licenses]
            # Worst risk wins
            risk_order = [
                LicenseRisk.COMMERCIAL,
                LicenseRisk.STRONG_COPYLEFT,
                LicenseRisk.WEAK_COPYLEFT,
                LicenseRisk.UNKNOWN,
                LicenseRisk.PERMISSIVE,
            ]
            worst = LicenseRisk.PERMISSIVE
            for r in risks:
                if risk_order.index(r) < risk_order.index(worst):
                    worst = r
            flagged = worst in (
                LicenseRisk.STRONG_COPYLEFT,
                LicenseRisk.COMMERCIAL,
                LicenseRisk.UNKNOWN,
            )
            reason = ""
            if flagged:
                if worst == LicenseRisk.STRONG_COPYLEFT:
                    reason = "Strong copyleft license requires source disclosure"
                elif worst == LicenseRisk.COMMERCIAL:
                    reason = "Commercial/proprietary license requires review"
                else:
                    reason = "Unknown license — requires legal review"

            report.append(
                {
                    "component": comp.name,
                    "version": comp.version,
                    "licenses": comp.licenses,
                    "risk": worst.value,
                    "flagged": flagged,
                    "reason": reason,
                }
            )
        return report

    # ------------------------------------------------------------------
    # SBOM diff
    # ------------------------------------------------------------------

    def diff_sboms(self, sbom_id_a: str, sbom_id_b: str) -> Dict[str, Any]:
        """Compare two SBOMs and return added/removed/updated components."""
        components_a = {c.name: c for c in self.get_components(sbom_id_a)}
        components_b = {c.name: c for c in self.get_components(sbom_id_b)}

        names_a = set(components_a)
        names_b = set(components_b)

        added = [components_b[n].model_dump() for n in sorted(names_b - names_a)]
        removed = [components_a[n].model_dump() for n in sorted(names_a - names_b)]
        updated: List[Dict[str, Any]] = []
        for name in sorted(names_a & names_b):
            ca = components_a[name]
            cb = components_b[name]
            if ca.version != cb.version:
                updated.append(
                    {
                        "name": name,
                        "old_version": ca.version,
                        "new_version": cb.version,
                        "old": ca.model_dump(),
                        "new": cb.model_dump(),
                    }
                )

        return {
            "sbom_a": sbom_id_a,
            "sbom_b": sbom_id_b,
            "added": added,
            "removed": removed,
            "updated": updated,
            "summary": {
                "added_count": len(added),
                "removed_count": len(removed),
                "updated_count": len(updated),
                "unchanged_count": len(names_a & names_b) - len(updated),
            },
        }

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def get_component_risk_score(self, component: Component) -> float:
        """Compute a 0-10 risk score for a component.

        Factors:
        - Vulnerability presence (+4 per critical, +3 high, +2 medium, +1 low)
        - License risk (+2 strong copyleft/commercial, +1 weak copyleft, +0.5 unknown)
        - Missing purl or version metadata (+0.5)
        """
        score = 0.0

        # Vulnerability factor
        key = component.name.lower()
        vulns = _KNOWN_VULNERABILITIES.get(key, [])
        severity_scores = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}
        for vuln in vulns:
            score += severity_scores.get(vuln.get("severity", ""), 0.5)

        # License factor
        for lic in component.licenses:
            risk = self.classify_license(lic)
            if risk in (LicenseRisk.STRONG_COPYLEFT, LicenseRisk.COMMERCIAL):
                score += 2.0
            elif risk == LicenseRisk.WEAK_COPYLEFT:
                score += 1.0
            elif risk == LicenseRisk.UNKNOWN:
                score += 0.5

        # Metadata quality factor
        if not component.purl:
            score += 0.5
        if not component.version:
            score += 0.5

        return round(min(score, 10.0), 2)
