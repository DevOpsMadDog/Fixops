"""
Bulk Finding Import/Export Engine — CSV, JSON, SARIF, CycloneDX support.

Provides:
- Import: parse → validate → normalise → store findings in SQLite
- Export: filter findings → serialise to CSV/JSON/SARIF
- History: track import/export operations per org
- Scheduled exports (metadata stored; execution is caller's responsibility)
"""

from __future__ import annotations

import csv
import io
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

_DB_PATH = Path("data/bulk_operations.db")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ImportFormat(str, Enum):
    CSV = "csv"
    JSON = "json"
    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"


class ExportFormat(str, Enum):
    CSV = "csv"
    JSON = "json"
    SARIF = "sarif"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ImportValidationError(BaseModel):
    row: int
    field: str
    error: str
    value: Optional[Any] = None


class ImportResult(BaseModel):
    id: str
    total_rows: int
    imported: int
    skipped: int
    errors: List[ImportValidationError] = Field(default_factory=list)
    format: ImportFormat
    imported_at: str
    org_id: str


class ExportResult(BaseModel):
    id: str
    total_records: int
    format: ExportFormat
    file_path: str
    exported_at: str
    filters_applied: Dict[str, Any] = Field(default_factory=dict)
    org_id: str


# ---------------------------------------------------------------------------
# Required fields per import format
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS: Dict[ImportFormat, List[str]] = {
    ImportFormat.CSV: ["title", "severity", "source"],
    ImportFormat.JSON: ["title", "severity", "source"],
    ImportFormat.SARIF: [],          # structural — validated differently
    ImportFormat.CYCLONEDX: [],     # structural — validated differently
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}

# ---------------------------------------------------------------------------
# Field mappings (format → unified schema)
# ---------------------------------------------------------------------------

_FIELD_MAPPINGS: Dict[str, Dict[str, str]] = {
    "csv": {
        "title": "title",
        "severity": "severity",
        "source": "source",
        "description": "description",
        "rule_id": "rule_id",
        "cve_id": "cve_id",
        "cvss_score": "cvss_score",
        "epss_score": "epss_score",
        "exploitable": "exploitable",
        "application_id": "application_id",
        "service_id": "service_id",
        "status": "status",
    },
    "json": {
        "title": "title",
        "severity": "severity",
        "source": "source",
        "description": "description",
        "rule_id": "rule_id",
        "cve_id": "cve_id",
        "cvss_score": "cvss_score",
        "epss_score": "epss_score",
        "exploitable": "exploitable",
        "application_id": "application_id",
        "service_id": "service_id",
        "status": "status",
    },
    "sarif": {
        "ruleId": "rule_id",
        "message.text": "description",
        "level": "severity",
        "locations": "locations",
    },
    "cyclonedx": {
        "id": "rule_id",
        "description": "description",
        "severity": "severity",
        "source.name": "source",
    },
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class BulkOperationsEngine:
    """SQLite-backed bulk import/export engine for findings."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or _DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS bulk_findings (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    description TEXT,
                    rule_id TEXT,
                    cve_id TEXT,
                    cvss_score REAL,
                    epss_score REAL,
                    exploitable INTEGER DEFAULT 0,
                    application_id TEXT,
                    service_id TEXT,
                    status TEXT DEFAULT 'open',
                    metadata TEXT,
                    import_id TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS import_history (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    total_rows INTEGER NOT NULL,
                    imported INTEGER NOT NULL,
                    skipped INTEGER NOT NULL,
                    errors TEXT NOT NULL,
                    format TEXT NOT NULL,
                    imported_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS export_history (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    total_records INTEGER NOT NULL,
                    format TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    exported_at TEXT NOT NULL,
                    filters_applied TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scheduled_exports (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    format TEXT NOT NULL,
                    filters TEXT NOT NULL,
                    frequency TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_run TEXT
                );
            """)

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def import_findings(
        self,
        content: str,
        format: ImportFormat,
        org_id: str,
        source: str = "bulk_import",
    ) -> ImportResult:
        """Parse, validate, and store findings. Returns ImportResult."""
        import_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        rows = self._parse(content, format)
        total_rows = len(rows)

        all_errors: List[ImportValidationError] = []
        imported = 0
        skipped = 0

        with self._get_conn() as conn:
            for idx, row in enumerate(rows):
                row_errors = self._validate_finding(row, format, idx)
                if row_errors:
                    all_errors.extend(row_errors)
                    skipped += 1
                    continue

                normalized = self._normalize_finding(row, format)
                normalized["org_id"] = org_id
                normalized.setdefault("source", source)
                finding_id = str(uuid.uuid4())

                try:
                    conn.execute(
                        """
                        INSERT INTO bulk_findings
                            (id, org_id, title, severity, source, description,
                             rule_id, cve_id, cvss_score, epss_score, exploitable,
                             application_id, service_id, status, metadata, import_id, created_at)
                        VALUES
                            (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            finding_id,
                            org_id,
                            normalized.get("title", ""),
                            normalized.get("severity", "medium"),
                            normalized.get("source", source),
                            normalized.get("description"),
                            normalized.get("rule_id"),
                            normalized.get("cve_id"),
                            normalized.get("cvss_score"),
                            normalized.get("epss_score"),
                            1 if normalized.get("exploitable") else 0,
                            normalized.get("application_id"),
                            normalized.get("service_id"),
                            normalized.get("status", "open"),
                            json.dumps(normalized.get("metadata", {})),
                            import_id,
                            now,
                        ),
                    )
                    imported += 1
                except Exception as exc:
                    logger.warning("Failed to insert finding at row %d: %s", idx, exc)
                    all_errors.append(
                        ImportValidationError(row=idx, field="db", error=str(exc))
                    )
                    skipped += 1

            # Persist history
            conn.execute(
                """
                INSERT INTO import_history
                    (id, org_id, total_rows, imported, skipped, errors, format, imported_at)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    import_id,
                    org_id,
                    total_rows,
                    imported,
                    skipped,
                    json.dumps([e.model_dump() for e in all_errors]),
                    format.value,
                    now,
                ),
            )

        return ImportResult(
            id=import_id,
            total_rows=total_rows,
            imported=imported,
            skipped=skipped,
            errors=all_errors,
            format=format,
            imported_at=now,
            org_id=org_id,
        )

    def validate_import(
        self,
        content: str,
        format: ImportFormat,
    ) -> List[ImportValidationError]:
        """Dry-run validation — returns errors without storing anything."""
        rows = self._parse(content, format)
        errors: List[ImportValidationError] = []
        for idx, row in enumerate(rows):
            errors.extend(self._validate_finding(row, format, idx))
        return errors

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_findings(
        self,
        org_id: str,
        format: ExportFormat,
        filters: Optional[Dict[str, Any]] = None,
    ) -> ExportResult:
        """Query findings, serialise, write file, return ExportResult."""
        filters = filters or {}
        export_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        findings = self._query_findings(org_id, filters)

        if format == ExportFormat.CSV:
            content = self.export_csv(findings)
            ext = "csv"
        elif format == ExportFormat.JSON:
            content = self.export_json(findings)
            ext = "json"
        else:
            content = self.export_sarif(findings)
            ext = "json"

        exports_dir = Path("data/exports")
        exports_dir.mkdir(parents=True, exist_ok=True)
        file_path = str(exports_dir / f"{export_id}.{ext}")
        Path(file_path).write_text(content, encoding="utf-8")

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO export_history
                    (id, org_id, total_records, format, file_path, exported_at, filters_applied)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    export_id,
                    org_id,
                    len(findings),
                    format.value,
                    file_path,
                    now,
                    json.dumps(filters),
                ),
            )

        return ExportResult(
            id=export_id,
            total_records=len(findings),
            format=format,
            file_path=file_path,
            exported_at=now,
            filters_applied=filters,
            org_id=org_id,
        )

    def export_csv(self, findings: List[Dict[str, Any]]) -> str:
        """Serialise findings list to CSV string."""
        if not findings:
            return "id,title,severity,source,description,rule_id,cve_id,status,created_at\n"

        fieldnames = [
            "id", "title", "severity", "source", "description",
            "rule_id", "cve_id", "cvss_score", "epss_score",
            "exploitable", "application_id", "service_id", "status", "created_at",
        ]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            writer.writerow(f)
        return buf.getvalue()

    def export_json(self, findings: List[Dict[str, Any]]) -> str:
        """Serialise findings list to JSON string."""
        return json.dumps({"findings": findings, "total": len(findings)}, default=str, indent=2)

    def export_sarif(self, findings: List[Dict[str, Any]]) -> str:
        """Serialise findings to SARIF 2.1.0 format."""
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []

        seen_rules: Dict[str, bool] = {}

        for f in findings:
            rule_id = f.get("rule_id") or f.get("id", "unknown")
            if rule_id not in seen_rules:
                seen_rules[rule_id] = True
                rules.append({
                    "id": rule_id,
                    "name": f.get("title", rule_id),
                    "shortDescription": {"text": f.get("title", "")},
                    "fullDescription": {"text": f.get("description", "")},
                    "properties": {
                        "severity": f.get("severity", "medium"),
                        "cve": f.get("cve_id"),
                    },
                })

            level = _severity_to_sarif_level(f.get("severity", "medium"))
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f.get("description") or f.get("title", "")},
                "properties": {
                    "source": f.get("source"),
                    "cvss_score": f.get("cvss_score"),
                    "status": f.get("status", "open"),
                },
            })

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ALDECI",
                            "version": "2.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def get_import_history(self, org_id: str) -> List[ImportResult]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM import_history WHERE org_id = ? ORDER BY imported_at DESC",
                (org_id,),
            ).fetchall()
        results = []
        for r in rows:
            errors_raw = json.loads(r["errors"]) if r["errors"] else []
            results.append(
                ImportResult(
                    id=r["id"],
                    org_id=r["org_id"],
                    total_rows=r["total_rows"],
                    imported=r["imported"],
                    skipped=r["skipped"],
                    errors=[ImportValidationError(**e) for e in errors_raw],
                    format=ImportFormat(r["format"]),
                    imported_at=r["imported_at"],
                )
            )
        return results

    def get_export_history(self, org_id: str) -> List[ExportResult]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM export_history WHERE org_id = ? ORDER BY exported_at DESC",
                (org_id,),
            ).fetchall()
        results = []
        for r in rows:
            results.append(
                ExportResult(
                    id=r["id"],
                    org_id=r["org_id"],
                    total_records=r["total_records"],
                    format=ExportFormat(r["format"]),
                    file_path=r["file_path"],
                    exported_at=r["exported_at"],
                    filters_applied=json.loads(r["filters_applied"]) if r["filters_applied"] else {},
                )
            )
        return results

    # ------------------------------------------------------------------
    # Scheduled exports
    # ------------------------------------------------------------------

    def schedule_export(
        self,
        org_id: str,
        format: ExportFormat,
        filters: Optional[Dict[str, Any]] = None,
        frequency: str = "daily",
    ) -> str:
        """Persist a scheduled export configuration. Returns schedule ID."""
        schedule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO scheduled_exports (id, org_id, format, filters, frequency, created_at)
                VALUES (?,?,?,?,?,?)
                """,
                (
                    schedule_id,
                    org_id,
                    format.value,
                    json.dumps(filters or {}),
                    frequency,
                    now,
                ),
            )
        return schedule_id

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_field_mapping(self, format: str) -> Dict[str, str]:
        """Return expected field mapping for the given format."""
        return _FIELD_MAPPINGS.get(format.lower(), {})

    def get_bulk_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate stats for the org's bulk operations."""
        with self._get_conn() as conn:
            finding_count = conn.execute(
                "SELECT COUNT(*) FROM bulk_findings WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            import_count = conn.execute(
                "SELECT COUNT(*) FROM import_history WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            export_count = conn.execute(
                "SELECT COUNT(*) FROM export_history WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            severity_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM bulk_findings WHERE org_id = ?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()

        return {
            "org_id": org_id,
            "total_findings": finding_count,
            "total_imports": import_count,
            "total_exports": export_count,
            "findings_by_severity": {r["severity"]: r["cnt"] for r in severity_rows},
        }

    # ------------------------------------------------------------------
    # Internal parse / validate / normalise / query
    # ------------------------------------------------------------------

    def _parse(self, content: str, format: ImportFormat) -> List[Dict[str, Any]]:
        if format == ImportFormat.CSV:
            return self._parse_csv(content)
        if format == ImportFormat.JSON:
            return self._parse_json(content)
        if format == ImportFormat.SARIF:
            return self._parse_sarif(content)
        if format == ImportFormat.CYCLONEDX:
            return self._parse_cyclonedx(content)
        return []

    def _parse_csv(self, content: str) -> List[Dict[str, Any]]:
        reader = csv.DictReader(io.StringIO(content))
        return [dict(row) for row in reader]

    def _parse_json(self, content: str) -> List[Dict[str, Any]]:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Support {"findings": [...]} wrapper or bare dict as single item
            if "findings" in data:
                return data["findings"]
            return [data]
        return []

    def _parse_sarif(self, content: str) -> List[Dict[str, Any]]:
        data = json.loads(content)
        rows: List[Dict[str, Any]] = []
        for run in data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "sarif")
            rules_index: Dict[str, Dict[str, Any]] = {
                r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])
            }
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule_meta = rules_index.get(rule_id, {})
                severity = _sarif_level_to_severity(result.get("level", "warning"))
                rows.append({
                    "rule_id": rule_id,
                    "title": rule_meta.get("name") or rule_id,
                    "description": (result.get("message") or {}).get("text", ""),
                    "severity": severity,
                    "source": tool_name,
                })
        return rows

    def _parse_cyclonedx(self, content: str) -> List[Dict[str, Any]]:
        data = json.loads(content)
        rows: List[Dict[str, Any]] = []
        for vuln in data.get("vulnerabilities", []):
            ratings = vuln.get("ratings", [{}])
            severity = ratings[0].get("severity", "medium") if ratings else "medium"
            source = (vuln.get("source") or {}).get("name", "cyclonedx")
            rows.append({
                "rule_id": vuln.get("id", "unknown"),
                "title": vuln.get("description", vuln.get("id", "")),
                "description": vuln.get("description", ""),
                "severity": severity,
                "source": source,
                "cve_id": vuln.get("id") if str(vuln.get("id", "")).startswith("CVE-") else None,
            })
        return rows

    def _validate_finding(
        self,
        row: Dict[str, Any],
        format: ImportFormat,
        row_index: int,
    ) -> List[ImportValidationError]:
        errors: List[ImportValidationError] = []
        required = _REQUIRED_FIELDS.get(format, [])

        for field in required:
            value = row.get(field)
            if not value or (isinstance(value, str) and not value.strip()):
                errors.append(
                    ImportValidationError(
                        row=row_index,
                        field=field,
                        error="required field is missing or empty",
                        value=value,
                    )
                )

        # Validate severity when present
        severity = row.get("severity")
        if severity and isinstance(severity, str):
            if severity.lower() not in _VALID_SEVERITIES:
                errors.append(
                    ImportValidationError(
                        row=row_index,
                        field="severity",
                        error=f"invalid severity '{severity}'; must be one of {sorted(_VALID_SEVERITIES)}",
                        value=severity,
                    )
                )

        # Validate numeric fields
        for num_field in ("cvss_score", "epss_score"):
            raw = row.get(num_field)
            if raw is not None and raw != "":
                try:
                    val = float(raw)
                    if num_field == "cvss_score" and not (0.0 <= val <= 10.0):
                        errors.append(
                            ImportValidationError(
                                row=row_index,
                                field=num_field,
                                error="cvss_score must be between 0 and 10",
                                value=raw,
                            )
                        )
                    elif num_field == "epss_score" and not (0.0 <= val <= 1.0):
                        errors.append(
                            ImportValidationError(
                                row=row_index,
                                field=num_field,
                                error="epss_score must be between 0 and 1",
                                value=raw,
                            )
                        )
                except (TypeError, ValueError):
                    errors.append(
                        ImportValidationError(
                            row=row_index,
                            field=num_field,
                            error=f"{num_field} must be a number",
                            value=raw,
                        )
                    )

        return errors

    def _normalize_finding(
        self,
        row: Dict[str, Any],
        format: ImportFormat,
    ) -> Dict[str, Any]:
        """Map raw row fields to unified finding schema."""
        normalized: Dict[str, Any] = {}

        mapping = _FIELD_MAPPINGS.get(format.value, {})
        for src_field, dst_field in mapping.items():
            if src_field in row:
                normalized[dst_field] = row[src_field]

        # Normalise severity casing
        sev = normalized.get("severity", "")
        if isinstance(sev, str):
            normalized["severity"] = _normalise_severity(sev)

        # Normalise exploitable to bool
        raw_exp = normalized.get("exploitable")
        if isinstance(raw_exp, str):
            normalized["exploitable"] = raw_exp.lower() in ("true", "1", "yes")
        elif raw_exp is None:
            normalized["exploitable"] = False

        # Numeric coercion
        for num_field in ("cvss_score", "epss_score"):
            raw = normalized.get(num_field)
            if raw is not None and raw != "":
                try:
                    normalized[num_field] = float(raw)
                except (TypeError, ValueError):
                    normalized.pop(num_field, None)

        return normalized

    def _query_findings(
        self,
        org_id: str,
        filters: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM bulk_findings WHERE org_id = ?"
        params: List[Any] = [org_id]

        if "severity" in filters:
            query += " AND severity = ?"
            params.append(filters["severity"])
        if "status" in filters:
            query += " AND status = ?"
            params.append(filters["status"])
        if "source" in filters:
            query += " AND source = ?"
            params.append(filters["source"])
        if "application_id" in filters:
            query += " AND application_id = ?"
            params.append(filters["application_id"])
        if "import_id" in filters:
            query += " AND import_id = ?"
            params.append(filters["import_id"])

        query += " ORDER BY created_at DESC"

        if "limit" in filters:
            query += " LIMIT ?"
            params.append(int(filters["limit"]))

        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def _normalise_severity(sev: str) -> str:
    sev = sev.lower().strip()
    if sev == "informational":
        return "info"
    if sev in _VALID_SEVERITIES:
        return sev
    return "medium"


def _severity_to_sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
        "informational": "note",
    }.get(severity.lower() if severity else "medium", "warning")


def _sarif_level_to_severity(level: str) -> str:
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }.get(level.lower() if level else "warning", "medium")
