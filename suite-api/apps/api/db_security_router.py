"""Database Security Scanner Router — CIS benchmarks, privilege audit, data exposure.

8 endpoints under /api/v1/db-security covering:
- Database inventory management
- CIS benchmark scanning
- User privilege auditing
- Data exposure detection
- Backup verification
- Connection security assessment
- Query audit log analysis
- Posture summary
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/db-security", tags=["Database Security"])

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

_ALLOWED_DB_TYPES = frozenset({
    "postgresql", "mysql", "mongodb", "redis", "mssql", "oracle", "sqlite", "unknown"
})


class AddDatabaseRequest(BaseModel):
    """Register a database in the inventory."""

    name: str = Field(..., min_length=1, max_length=200)
    db_type: str = Field(..., description="postgresql | mysql | mongodb | redis | mssql | oracle | sqlite")
    version: str = Field(default="unknown", max_length=50)
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(..., ge=1, le=65535)
    tls_enabled: bool = False
    tls_version: Optional[str] = Field(default=None, max_length=20)
    backup_enabled: bool = False
    backup_last_run: Optional[str] = Field(default=None, description="ISO datetime of last backup")
    backup_encrypted: bool = False
    backup_offsite: bool = False
    public_facing: bool = False
    tags: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("db_type")
    @classmethod
    def validate_db_type(cls, v: str) -> str:
        if v.lower() not in _ALLOWED_DB_TYPES:
            raise ValueError(f"db_type must be one of: {', '.join(sorted(_ALLOWED_DB_TYPES))}")
        return v.lower()

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if v is not None and len(v) > 30:
            raise ValueError("tags must not exceed 30 entries")
        return v


class ScanRequest(BaseModel):
    """Trigger a full security scan for a registered database."""

    db_id: str = Field(..., min_length=1)
    users: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of user records for privilege audit",
    )
    schema: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Database schema (table/column list) for data exposure detection",
    )
    query_logs: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Query audit log entries for suspicious query detection",
    )
    cipher_suites: Optional[List[str]] = Field(
        default=None,
        description="Active TLS cipher suites for connection security assessment",
    )
    cert_expiry: Optional[str] = Field(
        default=None,
        description="TLS certificate expiry (ISO datetime)",
    )
    cert_valid: Optional[bool] = None
    mutual_tls: bool = False

    @field_validator("users")
    @classmethod
    def validate_users(cls, v: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        if v is not None and len(v) > 500:
            raise ValueError("users list must not exceed 500 entries")
        return v

    @field_validator("query_logs")
    @classmethod
    def validate_query_logs(cls, v: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        if v is not None and len(v) > 10000:
            raise ValueError("query_logs must not exceed 10,000 entries")
        return v


class PrivilegeAuditRequest(BaseModel):
    """Run a privilege audit for a specific database."""

    db_id: str = Field(..., min_length=1)
    users: List[Dict[str, Any]] = Field(default_factory=list)

    @field_validator("users")
    @classmethod
    def validate_users(cls, v: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if len(v) > 500:
            raise ValueError("users list must not exceed 500 entries")
        return v


class DataExposureRequest(BaseModel):
    """Run data exposure detection on a database schema."""

    db_id: str = Field(..., min_length=1)
    schema: List[Dict[str, Any]] = Field(default_factory=list)

    @field_validator("schema")
    @classmethod
    def validate_schema(cls, v: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if len(v) > 5000:
            raise ValueError("schema must not exceed 5,000 column entries")
        return v


class QueryAuditRequest(BaseModel):
    """Analyze query audit logs for suspicious activity."""

    db_id: str = Field(..., min_length=1)
    query_logs: List[Dict[str, Any]] = Field(default_factory=list)

    @field_validator("query_logs")
    @classmethod
    def validate_query_logs(cls, v: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if len(v) > 10000:
            raise ValueError("query_logs must not exceed 10,000 entries")
        return v


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        from datetime import timezone
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid datetime format: {value}") from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/inventory")
async def add_database(req: AddDatabaseRequest) -> Dict[str, Any]:
    """Register a database in the inventory.

    Tracks type, version, host, port, TLS status, backup configuration,
    and public-facing exposure for downstream scanning.
    """
    from core.db_security import DatabaseType, get_db_security_engine

    engine = get_db_security_engine()
    backup_last_run = _parse_iso_datetime(req.backup_last_run)

    try:
        db_type = DatabaseType(req.db_type)
    except ValueError:
        db_type = DatabaseType.UNKNOWN

    try:
        entry = engine.inventory.add_database(
            name=req.name,
            db_type=db_type,
            version=req.version,
            host=req.host,
            port=req.port,
            tls_enabled=req.tls_enabled,
            tls_version=req.tls_version,
            backup_enabled=req.backup_enabled,
            backup_last_run=backup_last_run,
            backup_encrypted=req.backup_encrypted,
            backup_offsite=req.backup_offsite,
            public_facing=req.public_facing,
            tags=req.tags,
            metadata=req.metadata,
        )
    except Exception as exc:
        _logger.exception("db_inventory_add_error")
        raise HTTPException(status_code=500, detail=f"Failed to register database: {exc}") from exc

    return {"status": "registered", "database": entry.to_dict()}


@router.get("/inventory")
async def list_databases() -> Dict[str, Any]:
    """List all registered databases with inventory summary."""
    from core.db_security import get_db_security_engine

    engine = get_db_security_engine()
    databases = engine.inventory.list_databases()
    return {
        "summary": engine.inventory.summary(),
        "databases": [db.to_dict() for db in databases],
    }


@router.delete("/inventory/{db_id}")
async def remove_database(db_id: str) -> Dict[str, Any]:
    """Remove a database from the inventory."""
    from core.db_security import get_db_security_engine

    engine = get_db_security_engine()
    removed = engine.inventory.remove_database(db_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Database {db_id!r} not found")
    return {"status": "removed", "db_id": db_id}


@router.post("/scan")
async def scan_database(req: ScanRequest) -> Dict[str, Any]:
    """Run a full CIS benchmark + privilege + exposure + backup + connection + query scan.

    Returns a comprehensive scan result with risk score (0-100) and all findings.
    """
    from core.db_security import get_db_security_engine

    engine = get_db_security_engine()
    cert_expiry = _parse_iso_datetime(req.cert_expiry)

    try:
        result = engine.scan_database(
            db_id=req.db_id,
            users=req.users,
            schema=req.schema,
            query_logs=req.query_logs,
            cipher_suites=req.cipher_suites,
            cert_expiry=cert_expiry,
            cert_valid=req.cert_valid,
            mutual_tls=req.mutual_tls,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("db_scan_error")
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    return result.to_dict()


@router.get("/scan/{db_id}")
async def get_scan_result(db_id: str) -> Dict[str, Any]:
    """Retrieve the latest scan result for a database."""
    from core.db_security import get_db_security_engine

    engine = get_db_security_engine()
    result = engine.get_scan_result(db_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No scan result for database {db_id!r}")
    return result.to_dict()


@router.post("/privilege-audit")
async def privilege_audit(req: PrivilegeAuditRequest) -> Dict[str, Any]:
    """Audit database user privileges for over-provisioning, default passwords, shared accounts.

    Returns per-user risk scores and privilege details.
    """
    from core.db_security import UserPrivilegeAuditor

    auditor = UserPrivilegeAuditor()
    try:
        audits = auditor.audit_users(db_id=req.db_id, users=req.users)
    except Exception as exc:
        _logger.exception("privilege_audit_error")
        raise HTTPException(status_code=500, detail=f"Audit failed: {exc}") from exc

    high_risk = [a for a in audits if a.risk_score >= 70]
    return {
        "db_id": req.db_id,
        "total_users": len(audits),
        "high_risk_count": len(high_risk),
        "audits": [a.to_dict() for a in audits],
    }


@router.post("/exposure-detection")
async def exposure_detection(req: DataExposureRequest) -> Dict[str, Any]:
    """Detect PII and sensitive data in unencrypted or unmasked columns.

    Analyzes column names against PII patterns (SSN, credit card, email, passwords, etc.).
    """
    from core.db_security import DataExposureDetector, get_db_security_engine

    engine = get_db_security_engine()
    db = engine.inventory.get_database(req.db_id)
    public_facing = db.public_facing if db else False

    detector = DataExposureDetector()
    try:
        risks = detector.detect(db_id=req.db_id, schema=req.schema, public_facing=public_facing)
    except Exception as exc:
        _logger.exception("exposure_detection_error")
        raise HTTPException(status_code=500, detail=f"Detection failed: {exc}") from exc

    by_classification: Dict[str, int] = {}
    for r in risks:
        by_classification[r.data_classification] = by_classification.get(r.data_classification, 0) + 1

    return {
        "db_id": req.db_id,
        "total_risks": len(risks),
        "by_classification": by_classification,
        "risks": [r.to_dict() for r in risks],
    }


@router.post("/query-audit")
async def query_audit(req: QueryAuditRequest) -> Dict[str, Any]:
    """Analyze query audit logs for suspicious patterns.

    Detects: DROP TABLE, GRANT ALL, bulk SELECT, SQL injection, data exfiltration,
    privilege escalation, and more (14 pattern categories).
    """
    from core.db_security import QueryAuditAnalyzer

    analyzer = QueryAuditAnalyzer()
    try:
        suspicious = analyzer.analyze(db_id=req.db_id, query_logs=req.query_logs)
    except Exception as exc:
        _logger.exception("query_audit_error")
        raise HTTPException(status_code=500, detail=f"Query audit failed: {exc}") from exc

    by_type: Dict[str, int] = {}
    for q in suspicious:
        by_type[q.query_type] = by_type.get(q.query_type, 0) + 1

    critical = [q for q in suspicious if q.severity.value == "critical"]
    return {
        "db_id": req.db_id,
        "total_analyzed": len(req.query_logs),
        "suspicious_count": len(suspicious),
        "critical_count": len(critical),
        "by_type": by_type,
        "suspicious_queries": [q.to_dict() for q in suspicious],
    }


@router.get("/posture")
async def posture_summary() -> Dict[str, Any]:
    """Return aggregate security posture across all scanned databases.

    Includes average risk score, finding counts by severity, and per-database ranking.
    """
    from core.db_security import get_db_security_engine

    engine = get_db_security_engine()
    return engine.posture_summary()
