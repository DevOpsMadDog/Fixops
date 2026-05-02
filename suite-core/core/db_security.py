"""ALDECI Database Security Scanner.

CIS benchmark checks for PostgreSQL/MySQL/MongoDB/Redis, user privilege audits,
data exposure detection, backup verification, connection security, and query
audit log analysis.

Competitive parity: Imperva, DataSunrise, IBM Guardium, McAfee MVISION.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import structlog

log = structlog.get_logger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus:
            bus.emit(event_type, payload)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DatabaseType(str, Enum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MONGODB = "mongodb"
    REDIS = "redis"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


class CheckCategory(str, Enum):
    AUTH_CONFIG = "authentication_configuration"
    TLS_ENCRYPTION = "tls_encryption"
    ACCESS_CONTROL = "access_control"
    LOGGING = "logging"
    ENCRYPTION_AT_REST = "encryption_at_rest"
    BACKUP = "backup"
    NETWORK = "network"
    PATCH_MANAGEMENT = "patch_management"
    PRIVILEGE = "privilege"
    DATA_EXPOSURE = "data_exposure"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class DatabaseEntry:
    """Represents a tracked database in the inventory."""

    db_id: str
    name: str
    db_type: DatabaseType
    version: str
    host: str
    port: int
    tls_enabled: bool
    tls_version: Optional[str]
    backup_enabled: bool
    backup_last_run: Optional[datetime]
    backup_encrypted: bool
    backup_offsite: bool
    public_facing: bool
    tags: Dict[str, str]
    added_at: datetime
    last_scanned: Optional[datetime]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "db_id": self.db_id,
            "name": self.name,
            "db_type": self.db_type.value,
            "version": self.version,
            "host": self.host,
            "port": self.port,
            "tls_enabled": self.tls_enabled,
            "tls_version": self.tls_version,
            "backup_enabled": self.backup_enabled,
            "backup_last_run": self.backup_last_run.isoformat() if self.backup_last_run else None,
            "backup_encrypted": self.backup_encrypted,
            "backup_offsite": self.backup_offsite,
            "public_facing": self.public_facing,
            "tags": self.tags,
            "added_at": self.added_at.isoformat(),
            "last_scanned": self.last_scanned.isoformat() if self.last_scanned else None,
            "metadata": self.metadata,
        }


@dataclass
class BenchmarkFinding:
    """A single CIS benchmark check result."""

    finding_id: str
    db_id: str
    check_id: str
    title: str
    description: str
    severity: Severity
    category: CheckCategory
    status: CheckStatus
    recommendation: str
    evidence: str
    cis_control: str
    remediation_effort: str  # low / medium / high
    detected_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "db_id": self.db_id,
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "status": self.status.value,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "cis_control": self.cis_control,
            "remediation_effort": self.remediation_effort,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class UserPrivilegeAudit:
    """User privilege audit result for a database."""

    audit_id: str
    db_id: str
    username: str
    roles: List[str]
    is_superuser: bool
    has_default_password: bool
    is_shared_account: bool
    last_login: Optional[datetime]
    is_unused: bool  # no login in 90 days
    overprivileged: bool
    privilege_details: List[str]
    risk_score: int  # 0-100
    audited_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "db_id": self.db_id,
            "username": self.username,
            "roles": self.roles,
            "is_superuser": self.is_superuser,
            "has_default_password": self.has_default_password,
            "is_shared_account": self.is_shared_account,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_unused": self.is_unused,
            "overprivileged": self.overprivileged,
            "privilege_details": self.privilege_details,
            "risk_score": self.risk_score,
            "audited_at": self.audited_at.isoformat(),
        }


@dataclass
class DataExposureRisk:
    """Detected data exposure risk in a database."""

    risk_id: str
    db_id: str
    table_name: str
    column_name: str
    data_classification: str  # PII, PCI, PHI, CONFIDENTIAL
    exposure_type: str  # unencrypted_pii, no_masking, public_access
    severity: Severity
    description: str
    recommendation: str
    detected_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_id": self.risk_id,
            "db_id": self.db_id,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "data_classification": self.data_classification,
            "exposure_type": self.exposure_type,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class BackupVerification:
    """Backup health verification result."""

    verification_id: str
    db_id: str
    backup_exists: bool
    last_backup_age_hours: Optional[float]
    backup_recent: bool  # within SLA window
    backup_tested: bool  # restore tested
    backup_encrypted: bool
    backup_offsite: bool
    sla_hours: int
    status: CheckStatus
    issues: List[str]
    verified_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "db_id": self.db_id,
            "backup_exists": self.backup_exists,
            "last_backup_age_hours": self.last_backup_age_hours,
            "backup_recent": self.backup_recent,
            "backup_tested": self.backup_tested,
            "backup_encrypted": self.backup_encrypted,
            "backup_offsite": self.backup_offsite,
            "sla_hours": self.sla_hours,
            "status": self.status.value,
            "issues": self.issues,
            "verified_at": self.verified_at.isoformat(),
        }


@dataclass
class ConnectionSecurityResult:
    """Connection security assessment result."""

    result_id: str
    db_id: str
    tls_version: Optional[str]
    tls_compliant: bool  # TLS 1.2+
    cipher_suites: List[str]
    weak_ciphers: List[str]
    cert_valid: Optional[bool]
    cert_expiry: Optional[datetime]
    cert_days_remaining: Optional[int]
    mutual_tls: bool
    issues: List[str]
    severity: Severity
    assessed_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "db_id": self.db_id,
            "tls_version": self.tls_version,
            "tls_compliant": self.tls_compliant,
            "cipher_suites": self.cipher_suites,
            "weak_ciphers": self.weak_ciphers,
            "cert_valid": self.cert_valid,
            "cert_expiry": self.cert_expiry.isoformat() if self.cert_expiry else None,
            "cert_days_remaining": self.cert_days_remaining,
            "mutual_tls": self.mutual_tls,
            "issues": self.issues,
            "severity": self.severity.value,
            "assessed_at": self.assessed_at.isoformat(),
        }


@dataclass
class SuspiciousQuery:
    """Detected suspicious query from audit log analysis."""

    query_id: str
    db_id: str
    query_text: str
    query_type: str  # DDL_DROP, GRANT_ALL, BULK_SELECT, etc.
    username: str
    source_ip: str
    detected_at: datetime
    severity: Severity
    pattern_matched: str
    risk_description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_id": self.query_id,
            "db_id": self.db_id,
            "query_text": self.query_text,
            "query_type": self.query_type,
            "username": self.username,
            "source_ip": self.source_ip,
            "detected_at": self.detected_at.isoformat(),
            "severity": self.severity.value,
            "pattern_matched": self.pattern_matched,
            "risk_description": self.risk_description,
        }


# ---------------------------------------------------------------------------
# CIS Benchmark check definitions
# ---------------------------------------------------------------------------

# (check_id, title, description, severity, category, recommendation, cis_control, remediation_effort)
_CIS_CHECKS: List[Tuple[str, str, str, Severity, CheckCategory, str, str, str]] = [
    # --- PostgreSQL checks ---
    ("PG-1.1", "Ensure latest PostgreSQL patch is installed", "Running outdated PostgreSQL version exposes known CVEs", Severity.HIGH, CheckCategory.PATCH_MANAGEMENT, "Upgrade PostgreSQL to the latest stable release", "CIS PostgreSQL 14 §1.1", "medium"),
    ("PG-2.1", "Ensure pg_hba.conf does not allow trust auth", "Trust authentication allows connections without passwords", Severity.CRITICAL, CheckCategory.AUTH_CONFIG, "Replace 'trust' with 'scram-sha-256' or 'md5' in pg_hba.conf", "CIS PostgreSQL 14 §2.1", "low"),
    ("PG-2.2", "Ensure password auth uses SCRAM-SHA-256", "MD5 password hashing is weak and vulnerable to offline attacks", Severity.HIGH, CheckCategory.AUTH_CONFIG, "Set password_encryption=scram-sha-256 in postgresql.conf", "CIS PostgreSQL 14 §2.2", "low"),
    ("PG-2.3", "Ensure superuser connections are restricted", "Superuser role should only connect via unix socket", Severity.HIGH, CheckCategory.ACCESS_CONTROL, "Restrict superuser access to local socket in pg_hba.conf", "CIS PostgreSQL 14 §2.3", "low"),
    ("PG-3.1", "Ensure TLS is configured for all connections", "Unencrypted connections expose data in transit", Severity.CRITICAL, CheckCategory.TLS_ENCRYPTION, "Set ssl=on in postgresql.conf and enforce ssl_min_protocol_version=TLSv1.2", "CIS PostgreSQL 14 §3.1", "medium"),
    ("PG-3.2", "Ensure TLS 1.2 or higher is enforced", "TLS 1.0/1.1 have known vulnerabilities (POODLE, BEAST)", Severity.HIGH, CheckCategory.TLS_ENCRYPTION, "Set ssl_min_protocol_version='TLSv1.2' in postgresql.conf", "CIS PostgreSQL 14 §3.2", "low"),
    ("PG-4.1", "Ensure logging is enabled for all connections", "Without connection logging, access cannot be audited", Severity.MEDIUM, CheckCategory.LOGGING, "Set log_connections=on in postgresql.conf", "CIS PostgreSQL 14 §4.1", "low"),
    ("PG-4.2", "Ensure DDL statements are logged", "DDL changes (CREATE/DROP/ALTER) must be audited", Severity.MEDIUM, CheckCategory.LOGGING, "Set log_statement='ddl' in postgresql.conf", "CIS PostgreSQL 14 §4.2", "low"),
    ("PG-4.3", "Ensure failed authentication attempts are logged", "Failed logins indicate brute-force attempts", Severity.MEDIUM, CheckCategory.LOGGING, "Set log_failed_attempts=on and log_connections=on", "CIS PostgreSQL 14 §4.3", "low"),
    ("PG-5.1", "Ensure data directory permissions are restrictive", "World-readable data directory exposes database files", Severity.HIGH, CheckCategory.ENCRYPTION_AT_REST, "Set PGDATA directory permissions to 700", "CIS PostgreSQL 14 §5.1", "low"),
    ("PG-5.2", "Ensure tablespace encryption is enabled", "Unencrypted tablespaces expose data at rest", Severity.HIGH, CheckCategory.ENCRYPTION_AT_REST, "Enable pgcrypto or filesystem-level encryption for tablespaces", "CIS PostgreSQL 14 §5.2", "high"),
    ("PG-6.1", "Ensure PUBLIC schema privileges are revoked", "PUBLIC schema is accessible to all users by default", Severity.MEDIUM, CheckCategory.ACCESS_CONTROL, "REVOKE ALL ON SCHEMA public FROM PUBLIC", "CIS PostgreSQL 14 §6.1", "low"),
    ("PG-6.2", "Ensure role membership is minimal", "Excessive role grants violate least-privilege principle", Severity.MEDIUM, CheckCategory.ACCESS_CONTROL, "Audit and revoke unnecessary role memberships", "CIS PostgreSQL 14 §6.2", "medium"),
    # --- MySQL checks ---
    ("MY-1.1", "Ensure MySQL is using latest stable release", "Outdated MySQL exposes known CVEs", Severity.HIGH, CheckCategory.PATCH_MANAGEMENT, "Upgrade MySQL to latest stable release", "CIS MySQL 8.0 §1.1", "medium"),
    ("MY-2.1", "Ensure default root account is renamed or disabled", "Default 'root' account is a common attack target", Severity.CRITICAL, CheckCategory.AUTH_CONFIG, "Rename or disable the default root account", "CIS MySQL 8.0 §2.1", "low"),
    ("MY-2.2", "Ensure all accounts require password", "Accounts without passwords allow unauthenticated access", Severity.CRITICAL, CheckCategory.AUTH_CONFIG, "Set password for all accounts: ALTER USER ... IDENTIFIED BY ...", "CIS MySQL 8.0 §2.2", "low"),
    ("MY-2.3", "Ensure password complexity is enforced", "Weak passwords are vulnerable to brute-force attacks", Severity.HIGH, CheckCategory.AUTH_CONFIG, "Enable validate_password plugin with STRONG policy", "CIS MySQL 8.0 §2.3", "low"),
    ("MY-3.1", "Ensure TLS is required for all connections", "Unencrypted MySQL connections expose credentials and data", Severity.CRITICAL, CheckCategory.TLS_ENCRYPTION, "Set require_secure_transport=ON in MySQL config", "CIS MySQL 8.0 §3.1", "medium"),
    ("MY-3.2", "Ensure TLS version is 1.2 or higher", "Legacy TLS versions have known vulnerabilities", Severity.HIGH, CheckCategory.TLS_ENCRYPTION, "Set tls_version=TLSv1.2,TLSv1.3 in MySQL config", "CIS MySQL 8.0 §3.2", "low"),
    ("MY-4.1", "Ensure general query log is disabled in production", "General query log can expose sensitive data in log files", Severity.MEDIUM, CheckCategory.LOGGING, "Set general_log=OFF in production MySQL", "CIS MySQL 8.0 §4.1", "low"),
    ("MY-4.2", "Ensure audit log plugin is enabled", "Audit logging required for compliance and forensics", Severity.HIGH, CheckCategory.LOGGING, "Install and configure MySQL Enterprise Audit or MariaDB Audit Plugin", "CIS MySQL 8.0 §4.2", "medium"),
    ("MY-5.1", "Ensure MySQL data files are not world-readable", "World-readable MySQL data files expose database content", Severity.HIGH, CheckCategory.ENCRYPTION_AT_REST, "Set MySQL datadir permissions to 750, owned by mysql:mysql", "CIS MySQL 8.0 §5.1", "low"),
    ("MY-5.2", "Ensure InnoDB encryption is enabled", "Unencrypted InnoDB tablespaces expose data at rest", Severity.HIGH, CheckCategory.ENCRYPTION_AT_REST, "Enable innodb_encrypt_tables and innodb_encrypt_log", "CIS MySQL 8.0 §5.2", "medium"),
    ("MY-6.1", "Ensure SUPER privilege is limited to DBA accounts", "SUPER privilege bypasses access controls", Severity.HIGH, CheckCategory.ACCESS_CONTROL, "Revoke SUPER from application accounts", "CIS MySQL 8.0 §6.1", "low"),
    ("MY-6.2", "Ensure FILE privilege is not granted to app accounts", "FILE privilege allows reading arbitrary files from the server", Severity.HIGH, CheckCategory.ACCESS_CONTROL, "REVOKE FILE ON *.* FROM application_user", "CIS MySQL 8.0 §6.2", "low"),
    # --- MongoDB checks ---
    ("MG-1.1", "Ensure MongoDB authentication is enabled", "MongoDB without auth allows unauthenticated access to all data", Severity.CRITICAL, CheckCategory.AUTH_CONFIG, "Enable --auth flag and set authorization=enabled in mongod.conf", "CIS MongoDB 5 §1.1", "low"),
    ("MG-1.2", "Ensure SCRAM authentication mechanism is used", "MongoDB supports SCRAM-SHA-256 for strong authentication", Severity.HIGH, CheckCategory.AUTH_CONFIG, "Set security.authentication.mechanisms to SCRAM-SHA-256", "CIS MongoDB 5 §1.2", "low"),
    ("MG-2.1", "Ensure TLS is enabled for all MongoDB connections", "Unencrypted MongoDB is a common data breach vector", Severity.CRITICAL, CheckCategory.TLS_ENCRYPTION, "Set net.tls.mode=requireTLS in mongod.conf", "CIS MongoDB 5 §2.1", "medium"),
    ("MG-2.2", "Ensure MongoDB is not bound to 0.0.0.0", "Binding to all interfaces exposes MongoDB to public network", Severity.CRITICAL, CheckCategory.NETWORK, "Set net.bindIp to specific interface IPs in mongod.conf", "CIS MongoDB 5 §2.2", "low"),
    ("MG-3.1", "Ensure MongoDB audit log is enabled", "Audit logging required for detecting unauthorized access", Severity.HIGH, CheckCategory.LOGGING, "Enable auditLog in mongod.conf with appropriate filter", "CIS MongoDB 5 §3.1", "medium"),
    ("MG-4.1", "Ensure MongoDB encryption at rest is enabled", "Unencrypted MongoDB data files are accessible if disk is compromised", Severity.HIGH, CheckCategory.ENCRYPTION_AT_REST, "Enable MongoDB encrypted storage engine (Keyfile or KMIP)", "CIS MongoDB 5 §4.1", "high"),
    ("MG-5.1", "Ensure roles follow least privilege principle", "Overprivileged MongoDB users can access unintended collections", Severity.MEDIUM, CheckCategory.ACCESS_CONTROL, "Assign specific collection-level roles instead of root or dbAdmin", "CIS MongoDB 5 §5.1", "medium"),
    # --- Redis checks ---
    ("RD-1.1", "Ensure Redis requires authentication", "Redis without requirepass allows unauthenticated access", Severity.CRITICAL, CheckCategory.AUTH_CONFIG, "Set requirepass in redis.conf with a strong password", "CIS Redis §1.1", "low"),
    ("RD-1.2", "Ensure Redis ACL is configured", "Redis ACL provides fine-grained user access control", Severity.HIGH, CheckCategory.ACCESS_CONTROL, "Configure Redis ACL rules: user <name> on ><password> ~<keys> +<commands>", "CIS Redis §1.2", "medium"),
    ("RD-2.1", "Ensure Redis is not bound to 0.0.0.0", "Public Redis is frequently targeted by botnets for cryptomining", Severity.CRITICAL, CheckCategory.NETWORK, "Set bind 127.0.0.1 in redis.conf or use firewall rules", "CIS Redis §2.1", "low"),
    ("RD-2.2", "Ensure Redis TLS is enabled", "Unencrypted Redis exposes data and credentials in transit", Severity.HIGH, CheckCategory.TLS_ENCRYPTION, "Configure Redis TLS with tls-port, tls-cert-file, tls-key-file", "CIS Redis §2.2", "medium"),
    ("RD-3.1", "Ensure dangerous commands are renamed or disabled", "Commands like FLUSHALL, CONFIG, DEBUG can destroy data", Severity.HIGH, CheckCategory.ACCESS_CONTROL, "Rename dangerous commands in redis.conf: rename-command FLUSHALL ''", "CIS Redis §3.1", "low"),
    ("RD-3.2", "Ensure Redis protected-mode is enabled", "Protected mode prevents access from external IPs without auth", Severity.HIGH, CheckCategory.NETWORK, "Set protected-mode yes in redis.conf", "CIS Redis §3.2", "low"),
    ("RD-4.1", "Ensure Redis persistence is configured", "Without persistence, Redis data loss occurs on restart", Severity.MEDIUM, CheckCategory.BACKUP, "Configure RDB snapshots or AOF persistence in redis.conf", "CIS Redis §4.1", "low"),
    ("RD-4.2", "Ensure Redis log level is appropriate", "Verbose logging may expose sensitive data; silent misses events", Severity.LOW, CheckCategory.LOGGING, "Set loglevel notice in redis.conf", "CIS Redis §4.2", "low"),
    # --- Cross-database checks ---
    ("GEN-1.1", "Ensure default port is not used", "Using default ports makes databases easier to discover", Severity.LOW, CheckCategory.NETWORK, "Configure non-standard database port", "CIS General §1.1", "low"),
    ("GEN-1.2", "Ensure database is not publicly accessible", "Public-facing databases dramatically increase attack surface", Severity.CRITICAL, CheckCategory.NETWORK, "Place database behind private subnet and restrict ingress via firewall", "CIS General §1.2", "medium"),
    ("GEN-2.1", "Ensure backup is encrypted", "Unencrypted backups expose full database content if media is lost", Severity.HIGH, CheckCategory.BACKUP, "Encrypt backups with AES-256 before storing", "CIS General §2.1", "medium"),
    ("GEN-2.2", "Ensure offsite backup exists", "Backups stored only on-premise are lost in site disaster", Severity.HIGH, CheckCategory.BACKUP, "Configure offsite or cloud backup destination", "CIS General §2.2", "medium"),
    ("GEN-3.1", "Ensure shared accounts are not used", "Shared accounts prevent individual user accountability", Severity.MEDIUM, CheckCategory.AUTH_CONFIG, "Create individual named accounts for each DBA and application", "CIS General §3.1", "low"),
    ("GEN-4.1", "Ensure TLS certificate is valid and not expiring", "Expired or self-signed certs can be bypassed by MitM attackers", Severity.HIGH, CheckCategory.TLS_ENCRYPTION, "Renew TLS certificate; use CA-signed certs from trusted PKI", "CIS General §4.1", "low"),
    ("GEN-4.2", "Ensure weak cipher suites are disabled", "RC4, DES, 3DES, MD5 cipher suites are cryptographically broken", Severity.HIGH, CheckCategory.TLS_ENCRYPTION, "Configure allowed cipher suites to AES-GCM or ChaCha20-Poly1305 only", "CIS General §4.2", "low"),
    ("GEN-5.1", "Ensure database version is documented and tracked", "Unknown versions make patch management impossible", Severity.LOW, CheckCategory.PATCH_MANAGEMENT, "Maintain a database inventory with version tracking", "CIS General §5.1", "low"),
    ("GEN-5.2", "Ensure unused database features are disabled", "Enabled but unused features increase attack surface", Severity.LOW, CheckCategory.ACCESS_CONTROL, "Disable unused database extensions, plugins, and features", "CIS General §5.2", "low"),
]

# Default ports per database type
_DEFAULT_PORTS: Dict[DatabaseType, int] = {
    DatabaseType.POSTGRESQL: 5432,
    DatabaseType.MYSQL: 3306,
    DatabaseType.MONGODB: 27017,
    DatabaseType.REDIS: 6379,
    DatabaseType.MSSQL: 1433,
    DatabaseType.ORACLE: 1521,
}

# Default/well-known credentials to flag
_DEFAULT_CREDENTIALS: frozenset = frozenset({
    "root", "admin", "administrator", "postgres", "mysql",
    "oracle", "sa", "dbadmin", "dba", "test", "guest",
    "user", "password", "mongodb", "redis",
})

# PII column name patterns
_PII_COLUMN_PATTERNS: List[Tuple[str, str]] = [
    (r"(?i)(ssn|social_security|national_id)", "SSN/National ID"),
    (r"(?i)(credit_card|card_number|cc_num|pan)", "Payment Card Number"),
    (r"(?i)(passport_num|passport_number)", "Passport Number"),
    (r"(?i)(dob|date_of_birth|birth_date|birthdate)", "Date of Birth"),
    (r"(?i)(phone|mobile|cell_phone|telephone)", "Phone Number"),
    (r"(?i)\bemail\b", "Email Address"),
    (r"(?i)(password|passwd|pwd|secret)", "Password/Secret"),
    (r"(?i)(ip_address|client_ip|user_ip)", "IP Address"),
    (r"(?i)(bank_account|routing_number|iban|swift)", "Bank Account"),
    (r"(?i)(health_record|diagnosis|medication|prescription)", "Health Record (PHI)"),
    (r"(?i)(salary|compensation|wage|income)", "Financial/Compensation"),
    (r"(?i)(address|street|zip_code|postal_code)", "Physical Address"),
    (r"(?i)(api_key|access_token|auth_token|private_key)", "API Key/Token"),
]

# Suspicious query patterns
_SUSPICIOUS_QUERY_PATTERNS: List[Tuple[str, str, Severity, str]] = [
    (r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b", "DDL_DROP", Severity.CRITICAL, "Destructive DDL: DROP statement detected"),
    (r"(?i)\bGRANT\s+ALL\b", "GRANT_ALL", Severity.CRITICAL, "Overpermissive GRANT ALL detected — potential privilege escalation"),
    (r"(?i)\bSELECT\s+\*\s+FROM\b.{0,200}(WHERE\s+1\s*=\s*1|LIMIT\s+\d{5,})", "BULK_SELECT", Severity.HIGH, "Bulk data extraction pattern: unbounded SELECT or tautology WHERE clause"),
    (r"(?i)\bTRUNCATE\s+TABLE\b", "DDL_TRUNCATE", Severity.HIGH, "Destructive DDL: TRUNCATE TABLE detected"),
    (r"(?i)\bDROP\s+USER\b|\bDELETE\s+FROM\s+mysql\.user\b", "USER_DELETION", Severity.CRITICAL, "Database user deletion detected"),
    (r"(?i)\bxp_cmdshell\b|\bsp_executesql\b", "RCE_ATTEMPT", Severity.CRITICAL, "Potential remote code execution via stored procedure"),
    (r"(?i)\bINTO\s+OUTFILE\b|\bINTO\s+DUMPFILE\b", "DATA_EXFIL", Severity.CRITICAL, "Data exfiltration: writing query results to file"),
    (r"(?i)\bLOAD_FILE\b|\bLOAD\s+DATA\s+INFILE\b", "FILE_READ", Severity.HIGH, "File read attempt via SQL"),
    (r"(?i)\bUNION\s+(ALL\s+)?SELECT\b", "SQL_INJECTION", Severity.HIGH, "UNION-based SQL injection pattern detected"),
    (r"(?i)\bSLEEP\s*\(\s*\d+\s*\)|\bWAITFOR\s+DELAY\b", "BLIND_INJECTION", Severity.HIGH, "Time-based blind SQL injection pattern detected"),
    (r"(?i)\bALTER\s+USER.{0,100}IDENTIFIED\s+BY\b", "PASSWORD_CHANGE", Severity.HIGH, "Database user password change detected"),
    (r"(?i)\bREVOKE\s+ALL\b", "REVOKE_ALL", Severity.MEDIUM, "Mass privilege revocation detected"),
    (r"(?i)\bCREATE\s+USER.{0,50}IDENTIFIED\s+BY\s+['\"]?\w{1,8}['\"]?", "WEAK_PASSWORD", Severity.MEDIUM, "New database user created with potentially weak password"),
    (r"(?i)SELECT.{0,500}(password|passwd|secret|token|api_key)", "SENSITIVE_SELECT", Severity.HIGH, "Query selecting sensitive credential columns"),
]

# Weak cipher suites
_WEAK_CIPHERS: frozenset = frozenset({
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "RC2", "IDEA",
    "TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_DES_CBC_SHA", "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "SSL_CK_DES_192_EDE3_CBC_WITH_MD5", "SSL_CK_RC4_128_WITH_MD5",
})

_COMPLIANT_TLS_VERSIONS: frozenset = frozenset({"TLSv1.2", "TLSv1.3", "1.2", "1.3"})


# ---------------------------------------------------------------------------
# Database Inventory Manager
# ---------------------------------------------------------------------------


class DatabaseInventory:
    """In-memory database inventory store."""

    def __init__(self) -> None:
        self._databases: Dict[str, DatabaseEntry] = {}

    def add_database(
        self,
        name: str,
        db_type: DatabaseType,
        version: str,
        host: str,
        port: int,
        tls_enabled: bool = False,
        tls_version: Optional[str] = None,
        backup_enabled: bool = False,
        backup_last_run: Optional[datetime] = None,
        backup_encrypted: bool = False,
        backup_offsite: bool = False,
        public_facing: bool = False,
        tags: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DatabaseEntry:
        db_id = str(uuid.uuid4())
        entry = DatabaseEntry(
            db_id=db_id,
            name=name,
            db_type=db_type,
            version=version,
            host=host,
            port=port,
            tls_enabled=tls_enabled,
            tls_version=tls_version,
            backup_enabled=backup_enabled,
            backup_last_run=backup_last_run,
            backup_encrypted=backup_encrypted,
            backup_offsite=backup_offsite,
            public_facing=public_facing,
            tags=tags or {},
            added_at=datetime.now(timezone.utc),
            last_scanned=None,
            metadata=metadata or {},
        )
        self._databases[db_id] = entry
        log.info("db_inventory_add", db_id=db_id, name=name, db_type=db_type.value)
        _tg_emit("db_security.database_added", {"db_id": db_id, "name": name, "db_type": db_type.value, "host": host})
        return entry

    def get_database(self, db_id: str) -> Optional[DatabaseEntry]:
        return self._databases.get(db_id)

    def remove_database(self, db_id: str) -> bool:
        if db_id in self._databases:
            del self._databases[db_id]
            log.info("db_inventory_remove", db_id=db_id)
            return True
        return False

    def list_databases(self) -> List[DatabaseEntry]:
        return list(self._databases.values())

    def update_last_scanned(self, db_id: str) -> None:
        if db_id in self._databases:
            self._databases[db_id].last_scanned = datetime.now(timezone.utc)

    def summary(self) -> Dict[str, Any]:
        dbs = self.list_databases()
        by_type: Dict[str, int] = {}
        for db in dbs:
            by_type[db.db_type.value] = by_type.get(db.db_type.value, 0) + 1
        return {
            "total": len(dbs),
            "by_type": by_type,
            "tls_enabled_count": sum(1 for d in dbs if d.tls_enabled),
            "public_facing_count": sum(1 for d in dbs if d.public_facing),
            "backup_enabled_count": sum(1 for d in dbs if d.backup_enabled),
        }


# ---------------------------------------------------------------------------
# CIS Benchmark Checker
# ---------------------------------------------------------------------------


class CISBenchmarkChecker:
    """Runs CIS benchmark checks against a DatabaseEntry."""

    def run_checks(self, db: DatabaseEntry) -> List[BenchmarkFinding]:
        findings: List[BenchmarkFinding] = []
        now = datetime.now(timezone.utc)

        for check_id, title, description, severity, category, recommendation, cis_control, effort in _CIS_CHECKS:
            status, evidence = self._evaluate_check(check_id, db)
            if status in (CheckStatus.FAIL, CheckStatus.WARN):
                findings.append(BenchmarkFinding(
                    finding_id=str(uuid.uuid4()),
                    db_id=db.db_id,
                    check_id=check_id,
                    title=title,
                    description=description,
                    severity=severity,
                    category=category,
                    status=status,
                    recommendation=recommendation,
                    evidence=evidence,
                    cis_control=cis_control,
                    remediation_effort=effort,
                    detected_at=now,
                ))

        log.info("cis_benchmark_complete", db_id=db.db_id, findings=len(findings))
        _tg_emit("db_security.cis_benchmark_complete", {"db_id": db.db_id, "findings_count": len(findings)})
        return findings

    def _evaluate_check(self, check_id: str, db: DatabaseEntry) -> Tuple[CheckStatus, str]:
        """Evaluate a single CIS check, returning (status, evidence)."""

        # TLS checks
        if check_id in ("PG-3.1", "MY-3.1", "MG-2.1", "RD-2.2"):
            if not db.tls_enabled:
                return CheckStatus.FAIL, f"TLS is disabled on {db.host}:{db.port}"
            return CheckStatus.PASS, "TLS is enabled"

        if check_id in ("PG-3.2", "MY-3.2"):
            if not db.tls_enabled:
                return CheckStatus.FAIL, "TLS is not enabled; cannot verify version"
            if db.tls_version and db.tls_version not in _COMPLIANT_TLS_VERSIONS:
                return CheckStatus.FAIL, f"TLS version {db.tls_version} is not compliant (require TLS 1.2+)"
            return CheckStatus.PASS, f"TLS version: {db.tls_version}"

        # Public-facing checks
        if check_id in ("MG-2.2", "RD-2.1", "GEN-1.2"):
            if db.public_facing:
                return CheckStatus.FAIL, f"Database {db.name} is publicly accessible"
            return CheckStatus.PASS, "Database is not public-facing"

        # Default port check
        if check_id == "GEN-1.1":
            default_port = _DEFAULT_PORTS.get(db.db_type)
            if default_port and db.port == default_port:
                return CheckStatus.WARN, f"Using default port {db.port} for {db.db_type.value}"
            return CheckStatus.PASS, f"Non-default port {db.port} in use"

        # Backup checks
        if check_id == "GEN-2.1":
            if not db.backup_encrypted:
                return CheckStatus.FAIL, "Backup encryption is not enabled"
            return CheckStatus.PASS, "Backup encryption is enabled"

        if check_id == "GEN-2.2":
            if not db.backup_offsite:
                return CheckStatus.FAIL, "No offsite backup configured"
            return CheckStatus.PASS, "Offsite backup is configured"

        if check_id == "RD-4.1":
            if not db.backup_enabled:
                return CheckStatus.FAIL, "Redis persistence is not configured"
            return CheckStatus.PASS, "Persistence is configured"

        # DB-type specific checks — skip if not applicable
        prefix = check_id.split("-")[0]
        type_map = {
            "PG": DatabaseType.POSTGRESQL,
            "MY": DatabaseType.MYSQL,
            "MG": DatabaseType.MONGODB,
            "RD": DatabaseType.REDIS,
        }
        required_type = type_map.get(prefix)
        if required_type and db.db_type != required_type:
            return CheckStatus.SKIP, f"Check {check_id} does not apply to {db.db_type.value}"

        # Generic checks that require config inspection — flag as WARN (requires manual review)
        return CheckStatus.WARN, f"Manual verification required for {check_id} — configuration not directly inspectable"


# ---------------------------------------------------------------------------
# User Privilege Auditor
# ---------------------------------------------------------------------------


class UserPrivilegeAuditor:
    """Audits database user accounts for privilege issues."""

    def audit_users(
        self,
        db_id: str,
        users: List[Dict[str, Any]],
    ) -> List[UserPrivilegeAudit]:
        """Audit a list of user records.

        Expected user dict keys:
            username (str), roles (List[str]), is_superuser (bool),
            last_login (Optional[str] ISO datetime), metadata (Dict)
        """
        results: List[UserPrivilegeAudit] = []
        now = datetime.now(timezone.utc)
        ninety_days_ago = now - timedelta(days=90)

        # Detect shared accounts: same role set used by multiple users
        role_fingerprints: Dict[str, int] = {}
        for user in users:
            key = hashlib.md5(str(sorted(user.get("roles", []))).encode(), usedforsecurity=False).hexdigest()
            role_fingerprints[key] = role_fingerprints.get(key, 0) + 1

        for user in users:
            username = user.get("username", "unknown")
            roles: List[str] = user.get("roles", [])
            is_superuser: bool = user.get("is_superuser", False)
            last_login_raw: Optional[str] = user.get("last_login")
            last_login: Optional[datetime] = None
            if last_login_raw:
                try:
                    last_login = datetime.fromisoformat(last_login_raw)
                    if last_login.tzinfo is None:
                        last_login = last_login.replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            is_unused = last_login is None or last_login < ninety_days_ago
            has_default_password = username.lower() in _DEFAULT_CREDENTIALS

            # Shared account detection: multiple users share identical role fingerprint
            role_key = hashlib.md5(str(sorted(roles)).encode(), usedforsecurity=False).hexdigest()
            is_shared = role_fingerprints.get(role_key, 0) > 1

            overprivileged, privilege_details = self._check_overprivileged(
                username, roles, is_superuser
            )

            risk_score = self._compute_risk_score(
                is_superuser=is_superuser,
                has_default_password=has_default_password,
                is_unused=is_unused,
                is_shared=is_shared,
                overprivileged=overprivileged,
            )

            results.append(UserPrivilegeAudit(
                audit_id=str(uuid.uuid4()),
                db_id=db_id,
                username=username,
                roles=roles,
                is_superuser=is_superuser,
                has_default_password=has_default_password,
                is_shared_account=is_shared,
                last_login=last_login,
                is_unused=is_unused,
                overprivileged=overprivileged,
                privilege_details=privilege_details,
                risk_score=risk_score,
                audited_at=now,
            ))

        log.info("privilege_audit_complete", db_id=db_id, users=len(results))
        _tg_emit("db_security.privilege_audit_complete", {"db_id": db_id, "users_audited": len(results)})
        return results

    def _check_overprivileged(
        self, username: str, roles: List[str], is_superuser: bool
    ) -> Tuple[bool, List[str]]:
        details: List[str] = []
        overprivileged = False

        if is_superuser:
            details.append("Account has superuser/DBA privileges")
            overprivileged = True

        for role in roles:
            if any(hp in role.lower() for hp in ("all privileges", "grant all", "superuser", "dba", "sysadmin")):
                details.append(f"High-privilege role assigned: {role}")
                overprivileged = True

        return overprivileged, details

    def _compute_risk_score(
        self,
        is_superuser: bool,
        has_default_password: bool,
        is_unused: bool,
        is_shared: bool,
        overprivileged: bool,
    ) -> int:
        score = 0
        if is_superuser:
            score += 40
        if has_default_password:
            score += 30
        if is_unused:
            score += 15
        if is_shared:
            score += 10
        if overprivileged and not is_superuser:
            score += 15
        return min(score, 100)


# ---------------------------------------------------------------------------
# Data Exposure Detector
# ---------------------------------------------------------------------------


class DataExposureDetector:
    """Detects PII and sensitive data exposure in database schema definitions."""

    def detect(
        self,
        db_id: str,
        schema: List[Dict[str, Any]],
        public_facing: bool = False,
    ) -> List[DataExposureRisk]:
        """Analyze schema for data exposure risks.

        Expected schema item keys:
            table_name (str), column_name (str),
            encrypted (bool), masked (bool),
            data_type (str, optional)
        """
        risks: List[DataExposureRisk] = []
        now = datetime.now(timezone.utc)

        for col in schema:
            table = col.get("table_name", "unknown")
            column = col.get("column_name", "unknown")
            encrypted: bool = col.get("encrypted", False)
            masked: bool = col.get("masked", False)

            for pattern, classification in _PII_COLUMN_PATTERNS:
                if re.search(pattern, column):
                    exposure_type = None
                    severity = Severity.MEDIUM
                    description = ""
                    recommendation = ""

                    if not encrypted:
                        exposure_type = "unencrypted_pii"
                        severity = Severity.HIGH
                        description = f"Column '{table}.{column}' contains {classification} data and is not encrypted at rest"
                        recommendation = f"Enable column-level encryption for {table}.{column} (e.g., pgcrypto, Always Encrypted)"

                    elif not masked and public_facing:
                        exposure_type = "no_masking_public"
                        severity = Severity.HIGH
                        description = f"Column '{table}.{column}' ({classification}) is unmasked in a public-facing database"
                        recommendation = f"Apply dynamic data masking to {table}.{column}"

                    elif not masked:
                        exposure_type = "no_masking"
                        severity = Severity.MEDIUM
                        description = f"Column '{table}.{column}' ({classification}) has no data masking configured"
                        recommendation = f"Apply data masking policies to {table}.{column}"

                    if exposure_type:
                        risks.append(DataExposureRisk(
                            risk_id=str(uuid.uuid4()),
                            db_id=db_id,
                            table_name=table,
                            column_name=column,
                            data_classification=classification,
                            exposure_type=exposure_type,
                            severity=severity,
                            description=description,
                            recommendation=recommendation,
                            detected_at=now,
                        ))
                    break  # one match per column

        log.info("data_exposure_scan_complete", db_id=db_id, risks=len(risks))
        return risks


# ---------------------------------------------------------------------------
# Backup Verifier
# ---------------------------------------------------------------------------


class BackupVerifier:
    """Verifies backup health for a database."""

    DEFAULT_SLA_HOURS: Dict[str, int] = {
        DatabaseType.POSTGRESQL.value: 24,
        DatabaseType.MYSQL.value: 24,
        DatabaseType.MONGODB.value: 24,
        DatabaseType.REDIS.value: 72,
        "default": 48,
    }

    def verify(self, db: DatabaseEntry) -> BackupVerification:
        now = datetime.now(timezone.utc)
        issues: List[str] = []
        sla_hours = self.DEFAULT_SLA_HOURS.get(db.db_type.value, self.DEFAULT_SLA_HOURS["default"])

        backup_exists = db.backup_enabled and db.backup_last_run is not None
        last_backup_age_hours: Optional[float] = None
        backup_recent = False

        if db.backup_last_run:
            age = now - db.backup_last_run
            last_backup_age_hours = age.total_seconds() / 3600
            backup_recent = last_backup_age_hours <= sla_hours

        if not backup_exists:
            issues.append("No backup configured or backup never run")
        if not backup_recent and backup_exists:
            issues.append(f"Last backup exceeds SLA ({sla_hours}h). Age: {last_backup_age_hours:.1f}h")
        if not db.backup_encrypted:
            issues.append("Backup encryption is disabled")
        if not db.backup_offsite:
            issues.append("No offsite/remote backup destination configured")

        # Backup tested is inferred from metadata
        backup_tested: bool = db.metadata.get("backup_tested", False)
        if not backup_tested:
            issues.append("Backup restore has not been tested")

        if not issues:
            status = CheckStatus.PASS
        elif any("No backup" in i or "SLA" in i for i in issues):
            status = CheckStatus.FAIL
        else:
            status = CheckStatus.WARN

        result = BackupVerification(
            verification_id=str(uuid.uuid4()),
            db_id=db.db_id,
            backup_exists=backup_exists,
            last_backup_age_hours=last_backup_age_hours,
            backup_recent=backup_recent,
            backup_tested=backup_tested,
            backup_encrypted=db.backup_encrypted,
            backup_offsite=db.backup_offsite,
            sla_hours=sla_hours,
            status=status,
            issues=issues,
            verified_at=now,
        )
        log.info("backup_verification_complete", db_id=db.db_id, status=status.value)
        return result


# ---------------------------------------------------------------------------
# Connection Security Assessor
# ---------------------------------------------------------------------------


class ConnectionSecurityAssessor:
    """Assesses TLS and connection security for a database."""

    def assess(
        self,
        db: DatabaseEntry,
        cipher_suites: Optional[List[str]] = None,
        cert_expiry: Optional[datetime] = None,
        cert_valid: Optional[bool] = None,
        mutual_tls: bool = False,
    ) -> ConnectionSecurityResult:
        now = datetime.now(timezone.utc)
        issues: List[str] = []
        cipher_suites = cipher_suites or []

        tls_compliant = False
        if db.tls_enabled and db.tls_version:
            tls_compliant = db.tls_version in _COMPLIANT_TLS_VERSIONS
        elif not db.tls_enabled:
            issues.append("TLS is not enabled — all data transmitted in plaintext")

        if db.tls_enabled and not tls_compliant:
            issues.append(f"TLS version {db.tls_version} is non-compliant (require TLS 1.2+)")

        weak_ciphers = [c for c in cipher_suites if any(wc in c.upper() for wc in _WEAK_CIPHERS)]
        if weak_ciphers:
            issues.append(f"Weak cipher suites detected: {', '.join(weak_ciphers)}")

        cert_days_remaining: Optional[int] = None
        if cert_expiry:
            delta = cert_expiry - now
            cert_days_remaining = delta.days
            if cert_days_remaining < 0:
                issues.append(f"TLS certificate has expired {abs(cert_days_remaining)} days ago")
            elif cert_days_remaining < 30:
                issues.append(f"TLS certificate expires in {cert_days_remaining} days")

        if cert_valid is False:
            issues.append("TLS certificate is invalid or self-signed")

        # Determine severity
        severity: Severity
        if not db.tls_enabled:
            severity = Severity.CRITICAL
        elif not tls_compliant or (cert_valid is False):
            severity = Severity.HIGH
        elif weak_ciphers or (cert_days_remaining is not None and cert_days_remaining < 30):
            severity = Severity.MEDIUM
        elif issues:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        result = ConnectionSecurityResult(
            result_id=str(uuid.uuid4()),
            db_id=db.db_id,
            tls_version=db.tls_version,
            tls_compliant=tls_compliant,
            cipher_suites=cipher_suites,
            weak_ciphers=weak_ciphers,
            cert_valid=cert_valid,
            cert_expiry=cert_expiry,
            cert_days_remaining=cert_days_remaining,
            mutual_tls=mutual_tls,
            issues=issues,
            severity=severity,
            assessed_at=now,
        )
        log.info("connection_security_assessment_complete", db_id=db.db_id, severity=severity.value)
        return result


# ---------------------------------------------------------------------------
# Query Audit Log Analyzer
# ---------------------------------------------------------------------------


class QueryAuditAnalyzer:
    """Analyzes query audit logs for suspicious activity."""

    def analyze(
        self,
        db_id: str,
        query_logs: List[Dict[str, Any]],
    ) -> List[SuspiciousQuery]:
        """Analyze query log entries.

        Expected log entry keys:
            query (str), username (str), source_ip (str),
            timestamp (str ISO datetime)
        """
        suspicious: List[SuspiciousQuery] = []
        now = datetime.now(timezone.utc)

        for entry in query_logs:
            query_text = entry.get("query", "")
            username = entry.get("username", "unknown")
            source_ip = entry.get("source_ip", "unknown")
            ts_raw = entry.get("timestamp")

            try:
                detected_at = datetime.fromisoformat(ts_raw) if ts_raw else now
                if detected_at.tzinfo is None:
                    detected_at = detected_at.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                detected_at = now

            for pattern, query_type, severity, risk_desc in _SUSPICIOUS_QUERY_PATTERNS:
                match = re.search(pattern, query_text)
                if match:
                    suspicious.append(SuspiciousQuery(
                        query_id=str(uuid.uuid4()),
                        db_id=db_id,
                        query_text=query_text[:1000],  # truncate for safety
                        query_type=query_type,
                        username=username,
                        source_ip=source_ip,
                        detected_at=detected_at,
                        severity=severity,
                        pattern_matched=pattern,
                        risk_description=risk_desc,
                    ))
                    break  # first matching pattern wins per query

        log.info("query_audit_analysis_complete", db_id=db_id, suspicious=len(suspicious), total=len(query_logs))
        return suspicious


# ---------------------------------------------------------------------------
# Scan Result
# ---------------------------------------------------------------------------


@dataclass
class DatabaseScanResult:
    """Full scan result for a single database."""

    db_id: str
    db_name: str
    scanned_at: datetime
    benchmark_findings: List[BenchmarkFinding]
    privilege_audits: List[UserPrivilegeAudit]
    exposure_risks: List[DataExposureRisk]
    backup_verification: Optional[BackupVerification]
    connection_security: Optional[ConnectionSecurityResult]
    suspicious_queries: List[SuspiciousQuery]

    @property
    def risk_score(self) -> int:
        """0-100 composite risk score."""
        score = 0
        severity_weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        for f in self.benchmark_findings:
            score += severity_weights.get(f.severity, 0)
        for u in self.privilege_audits:
            score += u.risk_score // 10
        for e in self.exposure_risks:
            score += severity_weights.get(e.severity, 0)
        if self.connection_security and self.connection_security.severity == Severity.CRITICAL:
            score += 20
        return min(score, 100)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "db_id": self.db_id,
            "db_name": self.db_name,
            "scanned_at": self.scanned_at.isoformat(),
            "risk_score": self.risk_score,
            "benchmark_findings": [f.to_dict() for f in self.benchmark_findings],
            "privilege_audits": [u.to_dict() for u in self.privilege_audits],
            "exposure_risks": [e.to_dict() for e in self.exposure_risks],
            "backup_verification": self.backup_verification.to_dict() if self.backup_verification else None,
            "connection_security": self.connection_security.to_dict() if self.connection_security else None,
            "suspicious_queries": [q.to_dict() for q in self.suspicious_queries],
            "summary": {
                "benchmark_findings_count": len(self.benchmark_findings),
                "privilege_issues_count": len(self.privilege_audits),
                "exposure_risks_count": len(self.exposure_risks),
                "suspicious_queries_count": len(self.suspicious_queries),
                "by_severity": self._by_severity(),
            },
        }

    def _by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.benchmark_findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        for e in self.exposure_risks:
            counts[e.severity.value] = counts.get(e.severity.value, 0) + 1
        for q in self.suspicious_queries:
            counts[q.severity.value] = counts.get(q.severity.value, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Database Security Engine (singleton)
# ---------------------------------------------------------------------------


class DatabaseSecurityEngine:
    """Main engine orchestrating all database security scan components."""

    def __init__(self) -> None:
        self._inventory = DatabaseInventory()
        self._benchmark_checker = CISBenchmarkChecker()
        self._privilege_auditor = UserPrivilegeAuditor()
        self._exposure_detector = DataExposureDetector()
        self._backup_verifier = BackupVerifier()
        self._connection_assessor = ConnectionSecurityAssessor()
        self._query_analyzer = QueryAuditAnalyzer()
        self._scan_results: Dict[str, DatabaseScanResult] = {}

    # -- Inventory ----------------------------------------------------------

    @property
    def inventory(self) -> DatabaseInventory:
        return self._inventory

    # -- Scanning -----------------------------------------------------------

    def scan_database(
        self,
        db_id: str,
        users: Optional[List[Dict[str, Any]]] = None,
        schema: Optional[List[Dict[str, Any]]] = None,
        query_logs: Optional[List[Dict[str, Any]]] = None,
        cipher_suites: Optional[List[str]] = None,
        cert_expiry: Optional[datetime] = None,
        cert_valid: Optional[bool] = None,
        mutual_tls: bool = False,
    ) -> DatabaseScanResult:
        db = self._inventory.get_database(db_id)
        if db is None:
            raise KeyError(f"Database {db_id!r} not found in inventory")

        now = datetime.now(timezone.utc)
        benchmark_findings = self._benchmark_checker.run_checks(db)
        privilege_audits = self._privilege_auditor.audit_users(db_id, users or [])
        exposure_risks = self._exposure_detector.detect(db_id, schema or [], db.public_facing)
        backup_verification = self._backup_verifier.verify(db)
        connection_security = self._connection_assessor.assess(
            db, cipher_suites=cipher_suites, cert_expiry=cert_expiry,
            cert_valid=cert_valid, mutual_tls=mutual_tls,
        )
        suspicious_queries = self._query_analyzer.analyze(db_id, query_logs or [])

        result = DatabaseScanResult(
            db_id=db_id,
            db_name=db.name,
            scanned_at=now,
            benchmark_findings=benchmark_findings,
            privilege_audits=privilege_audits,
            exposure_risks=exposure_risks,
            backup_verification=backup_verification,
            connection_security=connection_security,
            suspicious_queries=suspicious_queries,
        )
        self._scan_results[db_id] = result
        self._inventory.update_last_scanned(db_id)
        log.info("db_security_scan_complete", db_id=db_id, risk_score=result.risk_score)
        return result

    def get_scan_result(self, db_id: str) -> Optional[DatabaseScanResult]:
        return self._scan_results.get(db_id)

    def get_all_scan_results(self) -> List[DatabaseScanResult]:
        return list(self._scan_results.values())

    def get_all_benchmark_findings(self) -> List[BenchmarkFinding]:
        findings: List[BenchmarkFinding] = []
        for result in self._scan_results.values():
            findings.extend(result.benchmark_findings)
        return findings

    def get_all_suspicious_queries(self) -> List[SuspiciousQuery]:
        queries: List[SuspiciousQuery] = []
        for result in self._scan_results.values():
            queries.extend(result.suspicious_queries)
        return queries

    def posture_summary(self) -> Dict[str, Any]:
        results = self.get_all_scan_results()
        if not results:
            return {"total_databases": 0, "average_risk_score": 0, "findings": {}}

        total_risk = sum(r.risk_score for r in results)
        all_findings = self.get_all_benchmark_findings()
        by_severity: Dict[str, int] = {}
        for f in all_findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

        return {
            "total_databases": len(results),
            "average_risk_score": round(total_risk / len(results), 1),
            "findings": {
                "total": len(all_findings),
                "by_severity": by_severity,
            },
            "databases": [
                {"db_id": r.db_id, "db_name": r.db_name, "risk_score": r.risk_score}
                for r in sorted(results, key=lambda x: x.risk_score, reverse=True)
            ],
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine: Optional[DatabaseSecurityEngine] = None


def get_db_security_engine() -> DatabaseSecurityEngine:
    global _engine
    if _engine is None:
        _engine = DatabaseSecurityEngine()
        log.info("db_security_engine_initialized")
    return _engine
