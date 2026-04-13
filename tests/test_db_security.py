"""Comprehensive tests for ALDECI Database Security Scanner.

Tests cover:
- Database inventory (add, list, remove, summary)
- CIS benchmark checker (PostgreSQL, MySQL, MongoDB, Redis, cross-DB)
- User privilege auditor (superuser, default password, unused, shared, risk score)
- Data exposure detector (PII patterns, unencrypted, unmasked, public-facing)
- Backup verifier (exists, recent, encrypted, offsite, tested, SLA)
- Connection security assessor (TLS version, weak ciphers, cert expiry)
- Query audit log analyzer (DROP TABLE, GRANT ALL, bulk SELECT, SQL injection, etc.)
- DatabaseScanResult (risk score, by_severity, to_dict)
- DatabaseSecurityEngine (scan_database, posture_summary, get_all_* methods)
- FastAPI router endpoints (all 8 routes)
- Edge cases: empty inputs, unknown db type, missing fields, large inputs

Run with: python -m pytest tests/test_db_security.py -v --timeout=30
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# Environment setup (must precede app imports)
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-that-is-long-enough-32chars")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.db_security import (
    BackupVerifier,
    BenchmarkFinding,
    CheckCategory,
    CheckStatus,
    CISBenchmarkChecker,
    ConnectionSecurityAssessor,
    DataExposureDetector,
    DataExposureRisk,
    DatabaseEntry,
    DatabaseInventory,
    DatabaseSecurityEngine,
    DatabaseType,
    QueryAuditAnalyzer,
    Severity,
    SuspiciousQuery,
    UserPrivilegeAudit,
    UserPrivilegeAuditor,
    get_db_security_engine,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_db_entry(
    db_type: DatabaseType = DatabaseType.POSTGRESQL,
    tls_enabled: bool = True,
    tls_version: str = "TLSv1.3",
    backup_enabled: bool = True,
    backup_encrypted: bool = True,
    backup_offsite: bool = True,
    public_facing: bool = False,
    port: int = 5433,
    backup_last_run: Optional[datetime] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> DatabaseEntry:
    return DatabaseEntry(
        db_id="test-db-001",
        name="test-postgres",
        db_type=db_type,
        version="14.5",
        host="db.internal",
        port=port,
        tls_enabled=tls_enabled,
        tls_version=tls_version,
        backup_enabled=backup_enabled,
        backup_last_run=backup_last_run or datetime.now(timezone.utc) - timedelta(hours=12),
        backup_encrypted=backup_encrypted,
        backup_offsite=backup_offsite,
        public_facing=public_facing,
        tags={"env": "prod"},
        added_at=datetime.now(timezone.utc),
        last_scanned=None,
        metadata=metadata or {"backup_tested": True},
    )


def _make_users(count: int = 3) -> List[Dict[str, Any]]:
    users = [
        {
            "username": "app_user",
            "roles": ["SELECT", "INSERT"],
            "is_superuser": False,
            "last_login": datetime.now(timezone.utc).isoformat(),
        },
        {
            "username": "postgres",
            "roles": ["superuser"],
            "is_superuser": True,
            "last_login": datetime.now(timezone.utc).isoformat(),
        },
        {
            "username": "old_user",
            "roles": ["SELECT"],
            "is_superuser": False,
            "last_login": (datetime.now(timezone.utc) - timedelta(days=120)).isoformat(),
        },
    ]
    return users[:count]


def _make_schema() -> List[Dict[str, Any]]:
    return [
        {"table_name": "users", "column_name": "email", "encrypted": False, "masked": False},
        {"table_name": "users", "column_name": "password", "encrypted": True, "masked": True},
        {"table_name": "orders", "column_name": "credit_card", "encrypted": False, "masked": False},
        {"table_name": "customers", "column_name": "ssn", "encrypted": False, "masked": False},
        {"table_name": "profiles", "column_name": "date_of_birth", "encrypted": True, "masked": False},
        {"table_name": "sessions", "column_name": "api_key", "encrypted": False, "masked": False},
        {"table_name": "audit", "column_name": "action_id", "encrypted": False, "masked": False},
    ]


def _make_query_logs() -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc).isoformat()
    return [
        {"query": "SELECT * FROM users WHERE 1=1 LIMIT 100000", "username": "app", "source_ip": "10.0.0.1", "timestamp": now},
        {"query": "DROP TABLE sessions", "username": "dba", "source_ip": "10.0.0.2", "timestamp": now},
        {"query": "GRANT ALL ON *.* TO 'hacker'@'%'", "username": "root", "source_ip": "1.2.3.4", "timestamp": now},
        {"query": "SELECT name, address FROM customers", "username": "app", "source_ip": "10.0.0.1", "timestamp": now},
        {"query": "TRUNCATE TABLE audit_log", "username": "dba", "source_ip": "10.0.0.2", "timestamp": now},
        {"query": "SELECT * FROM users UNION ALL SELECT 1,2,3", "username": "unknown", "source_ip": "5.6.7.8", "timestamp": now},
        {"query": "INSERT INTO products VALUES (1, 'test')", "username": "app", "source_ip": "10.0.0.1", "timestamp": now},
        {"query": "SELECT password, api_key FROM credentials", "username": "app", "source_ip": "10.0.0.1", "timestamp": now},
        {"query": "SELECT SLEEP(5) FROM dual", "username": "unknown", "source_ip": "9.9.9.9", "timestamp": now},
        {"query": "SELECT * FROM employees INTO OUTFILE '/tmp/dump.csv'", "username": "dba", "source_ip": "10.0.0.2", "timestamp": now},
    ]


# ---------------------------------------------------------------------------
# 1. DatabaseInventory tests
# ---------------------------------------------------------------------------


class TestDatabaseInventory:
    def setup_method(self):
        self.inventory = DatabaseInventory()

    def test_add_database_returns_entry(self):
        entry = self.inventory.add_database(
            name="mydb", db_type=DatabaseType.POSTGRESQL, version="14.5",
            host="localhost", port=5433,
        )
        assert entry.db_id
        assert entry.name == "mydb"
        assert entry.db_type == DatabaseType.POSTGRESQL

    def test_list_databases_empty(self):
        assert self.inventory.list_databases() == []

    def test_list_databases_after_add(self):
        self.inventory.add_database("db1", DatabaseType.MYSQL, "8.0", "host1", 3307)
        self.inventory.add_database("db2", DatabaseType.MONGODB, "5.0", "host2", 27018)
        assert len(self.inventory.list_databases()) == 2

    def test_get_database_found(self):
        entry = self.inventory.add_database("pg", DatabaseType.POSTGRESQL, "14", "h", 5432)
        found = self.inventory.get_database(entry.db_id)
        assert found is not None
        assert found.db_id == entry.db_id

    def test_get_database_not_found(self):
        assert self.inventory.get_database("nonexistent") is None

    def test_remove_database(self):
        entry = self.inventory.add_database("pg", DatabaseType.POSTGRESQL, "14", "h", 5432)
        removed = self.inventory.remove_database(entry.db_id)
        assert removed is True
        assert self.inventory.get_database(entry.db_id) is None

    def test_remove_nonexistent_returns_false(self):
        assert self.inventory.remove_database("bogus") is False

    def test_summary_counts(self):
        self.inventory.add_database("pg", DatabaseType.POSTGRESQL, "14", "h", 5432, tls_enabled=True)
        self.inventory.add_database("mg", DatabaseType.MONGODB, "5", "h2", 27017, public_facing=True)
        self.inventory.add_database("rd", DatabaseType.REDIS, "7", "h3", 6379, backup_enabled=True)
        s = self.inventory.summary()
        assert s["total"] == 3
        assert s["tls_enabled_count"] == 1
        assert s["public_facing_count"] == 1
        assert s["backup_enabled_count"] == 1

    def test_update_last_scanned(self):
        entry = self.inventory.add_database("pg", DatabaseType.POSTGRESQL, "14", "h", 5432)
        assert entry.last_scanned is None
        self.inventory.update_last_scanned(entry.db_id)
        updated = self.inventory.get_database(entry.db_id)
        assert updated.last_scanned is not None

    def test_update_last_scanned_nonexistent_noop(self):
        # Should not raise
        self.inventory.update_last_scanned("bogus")

    def test_to_dict_keys(self):
        entry = self.inventory.add_database("pg", DatabaseType.POSTGRESQL, "14", "h", 5432)
        d = entry.to_dict()
        for key in ("db_id", "name", "db_type", "version", "host", "port", "tls_enabled", "backup_enabled"):
            assert key in d

    def test_add_database_with_all_fields(self):
        now = datetime.now(timezone.utc)
        entry = self.inventory.add_database(
            name="full",
            db_type=DatabaseType.MYSQL,
            version="8.0.32",
            host="10.0.0.5",
            port=3307,
            tls_enabled=True,
            tls_version="TLSv1.3",
            backup_enabled=True,
            backup_last_run=now - timedelta(hours=6),
            backup_encrypted=True,
            backup_offsite=True,
            public_facing=False,
            tags={"env": "prod", "team": "platform"},
            metadata={"backup_tested": True},
        )
        assert entry.tls_version == "TLSv1.3"
        assert entry.backup_offsite is True
        assert entry.tags["env"] == "prod"


# ---------------------------------------------------------------------------
# 2. CISBenchmarkChecker tests
# ---------------------------------------------------------------------------


class TestCISBenchmarkChecker:
    def setup_method(self):
        self.checker = CISBenchmarkChecker()

    def test_tls_disabled_produces_critical_finding(self):
        db = _make_db_entry(tls_enabled=False)
        findings = self.checker.run_checks(db)
        tls_findings = [f for f in findings if f.category == CheckCategory.TLS_ENCRYPTION]
        assert len(tls_findings) > 0
        severities = {f.severity for f in tls_findings}
        assert Severity.CRITICAL in severities or Severity.HIGH in severities

    def test_tls_noncompliant_version_fails(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.0")
        findings = self.checker.run_checks(db)
        tls_ver_findings = [f for f in findings if "TLS version" in f.title or "TLS 1.2" in f.title]
        assert len(tls_ver_findings) > 0

    def test_public_facing_flagged(self):
        db = _make_db_entry(public_facing=True)
        findings = self.checker.run_checks(db)
        public_findings = [f for f in findings if "public" in f.title.lower() or "0.0.0.0" in f.title.lower() or "publicly" in f.description.lower()]
        assert len(public_findings) > 0

    def test_default_port_warn(self):
        db = _make_db_entry(db_type=DatabaseType.POSTGRESQL, port=5432)
        findings = self.checker.run_checks(db)
        port_findings = [f for f in findings if f.check_id == "GEN-1.1"]
        assert len(port_findings) > 0

    def test_non_default_port_no_warn(self):
        db = _make_db_entry(db_type=DatabaseType.POSTGRESQL, port=5433)
        findings = self.checker.run_checks(db)
        port_findings = [f for f in findings if f.check_id == "GEN-1.1"]
        assert len(port_findings) == 0

    def test_backup_not_encrypted_fails(self):
        db = _make_db_entry(backup_encrypted=False)
        findings = self.checker.run_checks(db)
        backup_findings = [f for f in findings if f.check_id == "GEN-2.1"]
        assert len(backup_findings) > 0
        assert backup_findings[0].status == CheckStatus.FAIL

    def test_no_offsite_backup_fails(self):
        db = _make_db_entry(backup_offsite=False)
        findings = self.checker.run_checks(db)
        offsite_findings = [f for f in findings if f.check_id == "GEN-2.2"]
        assert len(offsite_findings) > 0
        assert offsite_findings[0].status == CheckStatus.FAIL

    def test_finding_to_dict_has_required_keys(self):
        db = _make_db_entry(tls_enabled=False)
        findings = self.checker.run_checks(db)
        assert len(findings) > 0
        d = findings[0].to_dict()
        for key in ("finding_id", "db_id", "check_id", "title", "severity", "category", "status", "recommendation"):
            assert key in d

    def test_mysql_checks_skip_on_postgresql(self):
        db = _make_db_entry(db_type=DatabaseType.POSTGRESQL)
        findings = self.checker.run_checks(db)
        mysql_only_ids = {f.check_id for f in findings if f.check_id.startswith("MY-")}
        assert len(mysql_only_ids) == 0

    def test_redis_checks_skip_on_mysql(self):
        db = _make_db_entry(db_type=DatabaseType.MYSQL, port=3307)
        findings = self.checker.run_checks(db)
        redis_only_ids = {f.check_id for f in findings if f.check_id.startswith("RD-")}
        assert len(redis_only_ids) == 0

    def test_redis_no_backup_fails(self):
        db = _make_db_entry(db_type=DatabaseType.REDIS, backup_enabled=False, port=6380)
        findings = self.checker.run_checks(db)
        persist_findings = [f for f in findings if f.check_id == "RD-4.1"]
        assert len(persist_findings) > 0

    def test_fully_secure_db_has_fewer_failures(self):
        db = _make_db_entry(
            tls_enabled=True, tls_version="TLSv1.3",
            backup_encrypted=True, backup_offsite=True,
            public_facing=False, port=5433,
        )
        findings = self.checker.run_checks(db)
        fail_findings = [f for f in findings if f.status == CheckStatus.FAIL]
        # Secure config should have no FAIL-status findings for the directly evaluable checks
        direct_fail_ids = {"PG-3.1", "PG-3.2", "GEN-1.1", "GEN-1.2", "GEN-2.1", "GEN-2.2"}
        direct_fails = [f for f in fail_findings if f.check_id in direct_fail_ids]
        assert len(direct_fails) == 0


# ---------------------------------------------------------------------------
# 3. UserPrivilegeAuditor tests
# ---------------------------------------------------------------------------


class TestUserPrivilegeAuditor:
    def setup_method(self):
        self.auditor = UserPrivilegeAuditor()
        self.db_id = "test-db-001"

    def test_superuser_flagged(self):
        users = [{"username": "dba", "roles": ["superuser"], "is_superuser": True,
                  "last_login": datetime.now(timezone.utc).isoformat()}]
        audits = self.auditor.audit_users(self.db_id, users)
        assert audits[0].is_superuser is True
        assert audits[0].overprivileged is True
        assert audits[0].risk_score >= 40

    def test_default_password_detected(self):
        users = [{"username": "postgres", "roles": [], "is_superuser": False,
                  "last_login": datetime.now(timezone.utc).isoformat()}]
        audits = self.auditor.audit_users(self.db_id, users)
        assert audits[0].has_default_password is True
        assert audits[0].risk_score >= 30

    def test_unused_account_detected(self):
        old_login = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        users = [{"username": "old_user", "roles": [], "is_superuser": False, "last_login": old_login}]
        audits = self.auditor.audit_users(self.db_id, users)
        assert audits[0].is_unused is True
        assert audits[0].risk_score >= 15

    def test_never_logged_in_is_unused(self):
        users = [{"username": "ghost", "roles": [], "is_superuser": False, "last_login": None}]
        audits = self.auditor.audit_users(self.db_id, users)
        assert audits[0].is_unused is True

    def test_shared_account_detected(self):
        # Two users with identical role set → shared
        same_roles = ["SELECT", "INSERT"]
        users = [
            {"username": "app1", "roles": same_roles, "is_superuser": False,
             "last_login": datetime.now(timezone.utc).isoformat()},
            {"username": "app2", "roles": same_roles, "is_superuser": False,
             "last_login": datetime.now(timezone.utc).isoformat()},
        ]
        audits = self.auditor.audit_users(self.db_id, users)
        assert all(a.is_shared_account for a in audits)

    def test_unique_roles_not_shared(self):
        users = [
            {"username": "u1", "roles": ["SELECT"], "is_superuser": False,
             "last_login": datetime.now(timezone.utc).isoformat()},
            {"username": "u2", "roles": ["INSERT", "UPDATE"], "is_superuser": False,
             "last_login": datetime.now(timezone.utc).isoformat()},
        ]
        audits = self.auditor.audit_users(self.db_id, users)
        assert not any(a.is_shared_account for a in audits)

    def test_clean_user_low_risk(self):
        users = [{"username": "app_service", "roles": ["SELECT"], "is_superuser": False,
                  "last_login": datetime.now(timezone.utc).isoformat()}]
        audits = self.auditor.audit_users(self.db_id, users)
        assert audits[0].risk_score < 20

    def test_empty_users_returns_empty(self):
        audits = self.auditor.audit_users(self.db_id, [])
        assert audits == []

    def test_audit_to_dict_keys(self):
        users = _make_users(1)
        audits = self.auditor.audit_users(self.db_id, users)
        d = audits[0].to_dict()
        for key in ("audit_id", "db_id", "username", "roles", "is_superuser", "risk_score", "audited_at"):
            assert key in d

    def test_overprivileged_roles_detected(self):
        users = [{"username": "dbadmin", "roles": ["dba", "all privileges"], "is_superuser": False,
                  "last_login": datetime.now(timezone.utc).isoformat()}]
        audits = self.auditor.audit_users(self.db_id, users)
        assert audits[0].overprivileged is True

    def test_risk_score_capped_at_100(self):
        users = [{
            "username": "postgres",
            "roles": ["superuser", "dba", "all privileges"],
            "is_superuser": True,
            "last_login": None,
        }]
        audits = self.auditor.audit_users(self.db_id, users)
        assert audits[0].risk_score <= 100

    def test_invalid_last_login_date_handled(self):
        users = [{"username": "u", "roles": [], "is_superuser": False, "last_login": "not-a-date"}]
        # Should not raise
        audits = self.auditor.audit_users(self.db_id, users)
        assert audits[0].is_unused is True


# ---------------------------------------------------------------------------
# 4. DataExposureDetector tests
# ---------------------------------------------------------------------------


class TestDataExposureDetector:
    def setup_method(self):
        self.detector = DataExposureDetector()
        self.db_id = "test-db-001"

    def test_email_unencrypted_detected(self):
        schema = [{"table_name": "users", "column_name": "email", "encrypted": False, "masked": False}]
        risks = self.detector.detect(self.db_id, schema)
        assert len(risks) == 1
        assert risks[0].data_classification == "Email Address"
        assert risks[0].exposure_type == "unencrypted_pii"

    def test_credit_card_unencrypted(self):
        schema = [{"table_name": "payments", "column_name": "credit_card", "encrypted": False, "masked": False}]
        risks = self.detector.detect(self.db_id, schema)
        assert len(risks) == 1
        assert risks[0].severity == Severity.HIGH

    def test_encrypted_unmasked_public_facing_flagged(self):
        schema = [{"table_name": "users", "column_name": "email", "encrypted": True, "masked": False}]
        risks = self.detector.detect(self.db_id, schema, public_facing=True)
        assert len(risks) == 1
        assert risks[0].exposure_type == "no_masking_public"
        assert risks[0].severity == Severity.HIGH

    def test_encrypted_unmasked_not_public_medium_severity(self):
        schema = [{"table_name": "users", "column_name": "email", "encrypted": True, "masked": False}]
        risks = self.detector.detect(self.db_id, schema, public_facing=False)
        assert len(risks) == 1
        assert risks[0].exposure_type == "no_masking"
        assert risks[0].severity == Severity.MEDIUM

    def test_encrypted_and_masked_no_risk(self):
        schema = [{"table_name": "users", "column_name": "email", "encrypted": True, "masked": True}]
        risks = self.detector.detect(self.db_id, schema)
        assert risks == []

    def test_non_pii_column_no_risk(self):
        schema = [{"table_name": "products", "column_name": "product_name", "encrypted": False, "masked": False}]
        risks = self.detector.detect(self.db_id, schema)
        assert risks == []

    def test_multiple_pii_columns(self):
        risks = self.detector.detect(self.db_id, _make_schema())
        # email (unencrypted), credit_card (unencrypted), ssn (unencrypted), api_key (unencrypted)
        assert len(risks) >= 4

    def test_empty_schema_no_risks(self):
        assert self.detector.detect(self.db_id, []) == []

    def test_ssn_detected(self):
        schema = [{"table_name": "employees", "column_name": "ssn", "encrypted": False, "masked": False}]
        risks = self.detector.detect(self.db_id, schema)
        assert any(r.data_classification == "SSN/National ID" for r in risks)

    def test_risk_to_dict_keys(self):
        schema = [{"table_name": "users", "column_name": "email", "encrypted": False, "masked": False}]
        risks = self.detector.detect(self.db_id, schema)
        d = risks[0].to_dict()
        for key in ("risk_id", "db_id", "table_name", "column_name", "data_classification", "severity", "detected_at"):
            assert key in d

    def test_api_key_column_detected(self):
        schema = [{"table_name": "sessions", "column_name": "api_key", "encrypted": False, "masked": False}]
        risks = self.detector.detect(self.db_id, schema)
        assert len(risks) == 1
        assert "API Key" in risks[0].data_classification

    def test_password_column_detected(self):
        schema = [{"table_name": "auth", "column_name": "password", "encrypted": False, "masked": False}]
        risks = self.detector.detect(self.db_id, schema)
        assert len(risks) == 1


# ---------------------------------------------------------------------------
# 5. BackupVerifier tests
# ---------------------------------------------------------------------------


class TestBackupVerifier:
    def setup_method(self):
        self.verifier = BackupVerifier()

    def test_good_backup_passes(self):
        db = _make_db_entry(
            backup_enabled=True,
            backup_encrypted=True,
            backup_offsite=True,
            backup_last_run=datetime.now(timezone.utc) - timedelta(hours=6),
            metadata={"backup_tested": True},
        )
        result = self.verifier.verify(db)
        assert result.status == CheckStatus.PASS
        assert result.backup_exists is True
        assert result.backup_recent is True

    def test_no_backup_fails(self):
        db = _make_db_entry(backup_enabled=False, backup_last_run=None, metadata={})
        db.backup_last_run = None
        result = self.verifier.verify(db)
        assert result.status == CheckStatus.FAIL
        assert result.backup_exists is False

    def test_stale_backup_fails(self):
        db = _make_db_entry(
            backup_enabled=True,
            backup_last_run=datetime.now(timezone.utc) - timedelta(hours=48),
            metadata={"backup_tested": True},
        )
        result = self.verifier.verify(db)
        assert result.backup_recent is False
        assert result.status == CheckStatus.FAIL

    def test_not_encrypted_warns(self):
        db = _make_db_entry(backup_encrypted=False, metadata={"backup_tested": True})
        result = self.verifier.verify(db)
        assert any("encryption" in i.lower() for i in result.issues)

    def test_no_offsite_warns(self):
        db = _make_db_entry(backup_offsite=False, metadata={"backup_tested": True})
        result = self.verifier.verify(db)
        assert any("offsite" in i.lower() for i in result.issues)

    def test_not_tested_warns(self):
        db = _make_db_entry(metadata={"backup_tested": False})
        result = self.verifier.verify(db)
        assert any("tested" in i.lower() for i in result.issues)

    def test_verification_to_dict_keys(self):
        db = _make_db_entry()
        result = self.verifier.verify(db)
        d = result.to_dict()
        for key in ("verification_id", "db_id", "backup_exists", "backup_recent", "sla_hours", "status", "issues"):
            assert key in d

    def test_redis_sla_longer(self):
        db = _make_db_entry(db_type=DatabaseType.REDIS, port=6380)
        sla = self.verifier.DEFAULT_SLA_HOURS.get(DatabaseType.REDIS.value, 48)
        assert sla >= 48  # Redis default is 72h

    def test_age_hours_computed_correctly(self):
        db = _make_db_entry(backup_last_run=datetime.now(timezone.utc) - timedelta(hours=10))
        result = self.verifier.verify(db)
        assert result.last_backup_age_hours is not None
        assert 9.5 < result.last_backup_age_hours < 10.5


# ---------------------------------------------------------------------------
# 6. ConnectionSecurityAssessor tests
# ---------------------------------------------------------------------------


class TestConnectionSecurityAssessor:
    def setup_method(self):
        self.assessor = ConnectionSecurityAssessor()

    def test_no_tls_critical(self):
        db = _make_db_entry(tls_enabled=False)
        result = self.assessor.assess(db)
        assert result.severity == Severity.CRITICAL
        assert result.tls_compliant is False
        assert any("plaintext" in i.lower() or "not enabled" in i.lower() for i in result.issues)

    def test_tls12_compliant(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.2")
        result = self.assessor.assess(db)
        assert result.tls_compliant is True

    def test_tls13_compliant(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.3")
        result = self.assessor.assess(db)
        assert result.tls_compliant is True

    def test_tls10_noncompliant(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.0")
        result = self.assessor.assess(db)
        assert result.tls_compliant is False
        assert result.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_weak_ciphers_detected(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.3")
        result = self.assessor.assess(db, cipher_suites=["TLS_AES_256_GCM_SHA384", "RC4-MD5"])
        assert len(result.weak_ciphers) > 0
        assert result.severity in (Severity.MEDIUM, Severity.HIGH)

    def test_no_weak_ciphers_clean(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.3")
        result = self.assessor.assess(db, cipher_suites=["TLS_AES_256_GCM_SHA384"])
        assert result.weak_ciphers == []

    def test_expired_cert_flagged(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.3")
        expired = datetime.now(timezone.utc) - timedelta(days=5)
        result = self.assessor.assess(db, cert_expiry=expired, cert_valid=False)
        assert any("expired" in i.lower() for i in result.issues)

    def test_cert_expiring_soon_warns(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.3")
        expiring = datetime.now(timezone.utc) + timedelta(days=15)
        result = self.assessor.assess(db, cert_expiry=expiring, cert_valid=True)
        assert result.cert_days_remaining is not None
        assert result.cert_days_remaining < 30

    def test_invalid_cert_flagged(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.3")
        result = self.assessor.assess(db, cert_valid=False)
        assert any("invalid" in i.lower() or "self-signed" in i.lower() for i in result.issues)

    def test_clean_connection_info_severity(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.3")
        future = datetime.now(timezone.utc) + timedelta(days=365)
        result = self.assessor.assess(db, cert_expiry=future, cert_valid=True, mutual_tls=True)
        assert result.severity == Severity.INFO

    def test_to_dict_keys(self):
        db = _make_db_entry(tls_enabled=True, tls_version="TLSv1.3")
        result = self.assessor.assess(db)
        d = result.to_dict()
        for key in ("result_id", "db_id", "tls_version", "tls_compliant", "cipher_suites", "severity"):
            assert key in d


# ---------------------------------------------------------------------------
# 7. QueryAuditAnalyzer tests
# ---------------------------------------------------------------------------


class TestQueryAuditAnalyzer:
    def setup_method(self):
        self.analyzer = QueryAuditAnalyzer()
        self.db_id = "test-db-001"

    def test_drop_table_detected(self):
        logs = [{"query": "DROP TABLE users", "username": "dba", "source_ip": "10.0.0.1",
                 "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert len(suspicious) == 1
        assert suspicious[0].query_type == "DDL_DROP"
        assert suspicious[0].severity == Severity.CRITICAL

    def test_grant_all_detected(self):
        logs = [{"query": "GRANT ALL ON *.* TO 'user'@'%'", "username": "root", "source_ip": "1.2.3.4",
                 "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert any(s.query_type == "GRANT_ALL" for s in suspicious)

    def test_bulk_select_detected(self):
        logs = [{"query": "SELECT * FROM users WHERE 1=1 LIMIT 999999", "username": "app",
                 "source_ip": "10.0.0.1", "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert any(s.query_type == "BULK_SELECT" for s in suspicious)

    def test_truncate_detected(self):
        logs = [{"query": "TRUNCATE TABLE audit_log", "username": "dba", "source_ip": "10.0.0.2",
                 "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert any(s.query_type == "DDL_TRUNCATE" for s in suspicious)

    def test_sql_injection_union_detected(self):
        logs = [{"query": "SELECT id FROM users UNION ALL SELECT 1,2,3", "username": "anon",
                 "source_ip": "5.5.5.5", "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert any(s.query_type == "SQL_INJECTION" for s in suspicious)

    def test_data_exfil_into_outfile(self):
        logs = [{"query": "SELECT * FROM users INTO OUTFILE '/tmp/out.csv'", "username": "dba",
                 "source_ip": "10.0.0.2", "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert any(s.query_type == "DATA_EXFIL" for s in suspicious)

    def test_blind_injection_sleep(self):
        logs = [{"query": "SELECT SLEEP(10) FROM dual", "username": "anon", "source_ip": "9.9.9.9",
                 "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert any(s.query_type == "BLIND_INJECTION" for s in suspicious)

    def test_sensitive_select_detected(self):
        logs = [{"query": "SELECT username, password FROM users", "username": "app",
                 "source_ip": "10.0.0.1", "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert any(s.query_type == "SENSITIVE_SELECT" for s in suspicious)

    def test_benign_query_not_flagged(self):
        logs = [{"query": "SELECT id, name FROM products WHERE category='books'", "username": "app",
                 "source_ip": "10.0.0.1", "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert suspicious == []

    def test_empty_logs_returns_empty(self):
        assert self.analyzer.analyze(self.db_id, []) == []

    def test_suspicious_to_dict_keys(self):
        logs = [{"query": "DROP TABLE users", "username": "dba", "source_ip": "10.0.0.1",
                 "timestamp": datetime.now(timezone.utc).isoformat()}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        d = suspicious[0].to_dict()
        for key in ("query_id", "db_id", "query_text", "query_type", "username", "severity", "detected_at"):
            assert key in d

    def test_multiple_logs_multiple_detections(self):
        suspicious = self.analyzer.analyze(self.db_id, _make_query_logs())
        # Should detect at least 6 of the 10 queries as suspicious
        assert len(suspicious) >= 6

    def test_invalid_timestamp_handled(self):
        logs = [{"query": "DROP TABLE users", "username": "dba", "source_ip": "10.0.0.1",
                 "timestamp": "not-a-date"}]
        # Should not raise
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert len(suspicious) == 1

    def test_missing_timestamp_handled(self):
        logs = [{"query": "GRANT ALL ON *.* TO 'u'@'%'", "username": "root", "source_ip": "1.2.3.4"}]
        suspicious = self.analyzer.analyze(self.db_id, logs)
        assert len(suspicious) == 1


# ---------------------------------------------------------------------------
# 8. DatabaseSecurityEngine integration tests
# ---------------------------------------------------------------------------


class TestDatabaseSecurityEngine:
    def setup_method(self):
        self.engine = DatabaseSecurityEngine()

    def _register_db(self, **kwargs) -> str:
        entry = self.engine.inventory.add_database(
            name=kwargs.get("name", "test-pg"),
            db_type=kwargs.get("db_type", DatabaseType.POSTGRESQL),
            version=kwargs.get("version", "14.5"),
            host=kwargs.get("host", "db.internal"),
            port=kwargs.get("port", 5433),
            tls_enabled=kwargs.get("tls_enabled", True),
            tls_version=kwargs.get("tls_version", "TLSv1.3"),
            backup_enabled=kwargs.get("backup_enabled", True),
            backup_last_run=kwargs.get("backup_last_run", datetime.now(timezone.utc) - timedelta(hours=6)),
            backup_encrypted=kwargs.get("backup_encrypted", True),
            backup_offsite=kwargs.get("backup_offsite", True),
            public_facing=kwargs.get("public_facing", False),
            metadata=kwargs.get("metadata", {"backup_tested": True}),
        )
        return entry.db_id

    def test_scan_missing_db_raises_key_error(self):
        with pytest.raises(KeyError):
            self.engine.scan_database("nonexistent")

    def test_full_scan_returns_result(self):
        db_id = self._register_db()
        result = self.engine.scan_database(
            db_id=db_id,
            users=_make_users(),
            schema=_make_schema(),
            query_logs=_make_query_logs(),
        )
        assert result.db_id == db_id
        assert result.scanned_at is not None
        assert isinstance(result.benchmark_findings, list)
        assert isinstance(result.privilege_audits, list)
        assert isinstance(result.exposure_risks, list)
        assert isinstance(result.suspicious_queries, list)

    def test_risk_score_0_to_100(self):
        db_id = self._register_db()
        result = self.engine.scan_database(db_id)
        assert 0 <= result.risk_score <= 100

    def test_risk_score_higher_for_insecure_db(self):
        secure_id = self._register_db(tls_enabled=True, tls_version="TLSv1.3", public_facing=False)
        insecure_id = self._register_db(
            name="insecure-pg",
            tls_enabled=False, public_facing=True,
            backup_encrypted=False, backup_offsite=False,
        )
        secure_result = self.engine.scan_database(secure_id)
        insecure_result = self.engine.scan_database(insecure_id)
        # Insecure DB must have more FAIL-status benchmark findings than the secure one
        secure_fails = [f for f in secure_result.benchmark_findings if f.status.value == "fail"]
        insecure_fails = [f for f in insecure_result.benchmark_findings if f.status.value == "fail"]
        assert len(insecure_fails) > len(secure_fails)

    def test_get_scan_result_after_scan(self):
        db_id = self._register_db()
        self.engine.scan_database(db_id)
        result = self.engine.get_scan_result(db_id)
        assert result is not None
        assert result.db_id == db_id

    def test_get_scan_result_before_scan_returns_none(self):
        db_id = self._register_db()
        assert self.engine.get_scan_result(db_id) is None

    def test_get_all_scan_results(self):
        id1 = self._register_db(name="db1", host="h1")
        id2 = self._register_db(name="db2", host="h2")
        self.engine.scan_database(id1)
        self.engine.scan_database(id2)
        assert len(self.engine.get_all_scan_results()) == 2

    def test_get_all_benchmark_findings(self):
        db_id = self._register_db(tls_enabled=False, public_facing=True)
        self.engine.scan_database(db_id)
        findings = self.engine.get_all_benchmark_findings()
        assert len(findings) > 0

    def test_get_all_suspicious_queries(self):
        db_id = self._register_db()
        self.engine.scan_database(db_id, query_logs=_make_query_logs())
        queries = self.engine.get_all_suspicious_queries()
        assert len(queries) > 0

    def test_posture_summary_empty(self):
        summary = self.engine.posture_summary()
        assert summary["total_databases"] == 0

    def test_posture_summary_after_scan(self):
        db_id = self._register_db()
        self.engine.scan_database(db_id)
        summary = self.engine.posture_summary()
        assert summary["total_databases"] == 1
        assert "average_risk_score" in summary
        assert "findings" in summary

    def test_scan_result_to_dict(self):
        db_id = self._register_db()
        result = self.engine.scan_database(db_id, users=_make_users(), schema=_make_schema())
        d = result.to_dict()
        for key in ("db_id", "db_name", "scanned_at", "risk_score", "summary",
                    "benchmark_findings", "privilege_audits", "exposure_risks"):
            assert key in d

    def test_last_scanned_updated_after_scan(self):
        db_id = self._register_db()
        db = self.engine.inventory.get_database(db_id)
        assert db.last_scanned is None
        self.engine.scan_database(db_id)
        db = self.engine.inventory.get_database(db_id)
        assert db.last_scanned is not None

    def test_singleton_get_db_security_engine(self):
        e1 = get_db_security_engine()
        e2 = get_db_security_engine()
        assert e1 is e2


# ---------------------------------------------------------------------------
# 9. FastAPI Router endpoint tests
# ---------------------------------------------------------------------------


from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_test_app() -> FastAPI:
    app = FastAPI()
    from apps.api.db_security_router import router
    app.include_router(router)
    return app


@pytest.fixture(scope="module")
def client():
    app = _make_test_app()
    with TestClient(app) as c:
        yield c


class TestDbSecurityRouter:
    def test_list_inventory_empty(self, client):
        resp = client.get("/api/v1/db-security/inventory")
        assert resp.status_code == 200
        data = resp.json()
        assert "databases" in data
        assert "summary" in data

    def test_add_database(self, client):
        payload = {
            "name": "test-pg",
            "db_type": "postgresql",
            "version": "14.5",
            "host": "db.internal",
            "port": 5433,
            "tls_enabled": True,
            "tls_version": "TLSv1.3",
            "backup_enabled": True,
            "backup_encrypted": True,
            "backup_offsite": True,
        }
        resp = client.post("/api/v1/db-security/inventory", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert "database" in data
        assert data["database"]["db_id"]

    def test_add_database_invalid_type(self, client):
        payload = {"name": "bad", "db_type": "cassandra", "version": "1.0", "host": "h", "port": 5432}
        resp = client.post("/api/v1/db-security/inventory", json=payload)
        assert resp.status_code == 422

    def test_add_database_invalid_port(self, client):
        payload = {"name": "bad", "db_type": "postgresql", "version": "14", "host": "h", "port": 99999}
        resp = client.post("/api/v1/db-security/inventory", json=payload)
        assert resp.status_code == 422

    def test_list_inventory_after_add(self, client):
        client.post("/api/v1/db-security/inventory", json={
            "name": "inv-test", "db_type": "mysql", "version": "8.0", "host": "myhost", "port": 3307,
        })
        resp = client.get("/api/v1/db-security/inventory")
        data = resp.json()
        assert data["summary"]["total"] >= 1

    def test_remove_database_not_found(self, client):
        resp = client.delete("/api/v1/db-security/inventory/nonexistent-id")
        assert resp.status_code == 404

    def test_remove_database_success(self, client):
        add_resp = client.post("/api/v1/db-security/inventory", json={
            "name": "to-remove", "db_type": "redis", "version": "7.0", "host": "rhost", "port": 6380,
        })
        db_id = add_resp.json()["database"]["db_id"]
        del_resp = client.delete(f"/api/v1/db-security/inventory/{db_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "removed"

    def test_scan_not_found(self, client):
        resp = client.post("/api/v1/db-security/scan", json={"db_id": "nonexistent"})
        assert resp.status_code == 404

    def test_full_scan(self, client):
        add_resp = client.post("/api/v1/db-security/inventory", json={
            "name": "scan-target", "db_type": "postgresql", "version": "14",
            "host": "scanhost", "port": 5434, "tls_enabled": True, "tls_version": "TLSv1.3",
            "backup_enabled": True, "backup_encrypted": True, "backup_offsite": True,
            "metadata": {"backup_tested": True},
        })
        db_id = add_resp.json()["database"]["db_id"]
        scan_resp = client.post("/api/v1/db-security/scan", json={
            "db_id": db_id,
            "users": _make_users(),
            "schema": _make_schema(),
            "query_logs": _make_query_logs()[:3],
        })
        assert scan_resp.status_code == 200
        data = scan_resp.json()
        assert "risk_score" in data
        assert "benchmark_findings" in data
        assert "privilege_audits" in data
        assert "exposure_risks" in data

    def test_get_scan_result_after_scan(self, client):
        add_resp = client.post("/api/v1/db-security/inventory", json={
            "name": "get-scan-test", "db_type": "mysql", "version": "8.0",
            "host": "mysqlhost", "port": 3308,
        })
        db_id = add_resp.json()["database"]["db_id"]
        client.post("/api/v1/db-security/scan", json={"db_id": db_id})
        get_resp = client.get(f"/api/v1/db-security/scan/{db_id}")
        assert get_resp.status_code == 200

    def test_get_scan_result_not_found(self, client):
        add_resp = client.post("/api/v1/db-security/inventory", json={
            "name": "unscannable", "db_type": "mongodb", "version": "5.0",
            "host": "mghost", "port": 27018,
        })
        db_id = add_resp.json()["database"]["db_id"]
        resp = client.get(f"/api/v1/db-security/scan/{db_id}")
        assert resp.status_code == 404

    def test_privilege_audit_endpoint(self, client):
        resp = client.post("/api/v1/db-security/privilege-audit", json={
            "db_id": "any-db-id",
            "users": _make_users(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "total_users" in data
        assert "audits" in data

    def test_privilege_audit_empty_users(self, client):
        resp = client.post("/api/v1/db-security/privilege-audit", json={"db_id": "x", "users": []})
        assert resp.status_code == 200
        assert resp.json()["total_users"] == 0

    def test_exposure_detection_endpoint(self, client):
        resp = client.post("/api/v1/db-security/exposure-detection", json={
            "db_id": "any-db-id",
            "schema": _make_schema(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "total_risks" in data
        assert data["total_risks"] >= 4

    def test_exposure_detection_empty_schema(self, client):
        resp = client.post("/api/v1/db-security/exposure-detection", json={"db_id": "x", "schema": []})
        assert resp.status_code == 200
        assert resp.json()["total_risks"] == 0

    def test_query_audit_endpoint(self, client):
        resp = client.post("/api/v1/db-security/query-audit", json={
            "db_id": "any-db-id",
            "query_logs": _make_query_logs(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "suspicious_count" in data
        assert data["suspicious_count"] >= 6

    def test_query_audit_empty(self, client):
        resp = client.post("/api/v1/db-security/query-audit", json={"db_id": "x", "query_logs": []})
        assert resp.status_code == 200
        assert resp.json()["suspicious_count"] == 0

    def test_posture_endpoint(self, client):
        resp = client.get("/api/v1/db-security/posture")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_databases" in data

    def test_scan_with_cert_expiry(self, client):
        add_resp = client.post("/api/v1/db-security/inventory", json={
            "name": "cert-test", "db_type": "postgresql", "version": "14",
            "host": "certhost", "port": 5435, "tls_enabled": True, "tls_version": "TLSv1.3",
        })
        db_id = add_resp.json()["database"]["db_id"]
        expiry = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        resp = client.post("/api/v1/db-security/scan", json={
            "db_id": db_id,
            "cert_expiry": expiry,
            "cert_valid": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["connection_security"]["cert_days_remaining"] is not None
