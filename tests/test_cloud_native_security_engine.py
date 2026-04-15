"""
Tests for CloudNativeSecurityEngine — 30+ tests covering init, CRUD, org isolation, stats.
"""
import pytest
from core.cloud_native_security_engine import CloudNativeSecurityEngine


@pytest.fixture
def engine(tmp_path):
    return CloudNativeSecurityEngine(db_path=str(tmp_path / "cloud_native.db"))


@pytest.fixture
def account(engine):
    return engine.register_cloud_account("org1", {
        "provider": "aws",
        "account_id": "123456789012",
        "account_name": "prod-account",
        "region": "us-east-1",
        "environment": "prod",
    })


@pytest.fixture
def misconfig(engine, account):
    return engine.record_misconfiguration("org1", {
        "account_id": account["id"],
        "provider": "aws",
        "service": "s3",
        "check_name": "S3 Public Access Block Disabled",
        "severity": "critical",
        "resource_id": "my-bucket",
        "resource_name": "my-bucket",
        "description": "Public access block disabled",
        "remediation": "Enable S3 Block Public Access",
        "compliant": False,
    })


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_creates_db(self, tmp_path):
        import os
        db = str(tmp_path / "sub" / "cloud_native.db")
        CloudNativeSecurityEngine(db_path=db)
        assert os.path.exists(db)

    def test_init_creates_tables(self, tmp_path):
        import sqlite3
        db = str(tmp_path / "cloud_native.db")
        CloudNativeSecurityEngine(db_path=db)
        conn = sqlite3.connect(db)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "cloud_accounts" in tables
        assert "cloud_misconfigurations" in tables
        conn.close()

    def test_init_idempotent(self, tmp_path):
        db = str(tmp_path / "cloud_native.db")
        CloudNativeSecurityEngine(db_path=db)
        CloudNativeSecurityEngine(db_path=db)


# ---------------------------------------------------------------------------
# Account registration
# ---------------------------------------------------------------------------

class TestRegisterAccount:
    def test_register_returns_dict(self, engine):
        result = engine.register_cloud_account("org1", {"provider": "aws"})
        assert isinstance(result, dict)

    def test_register_has_uuid_id(self, engine):
        result = engine.register_cloud_account("org1", {})
        assert "id" in result
        assert len(result["id"]) == 36

    def test_register_stores_org_id(self, engine):
        result = engine.register_cloud_account("org-xyz", {})
        assert result["org_id"] == "org-xyz"

    def test_register_default_provider_aws(self, engine):
        result = engine.register_cloud_account("org1", {})
        assert result["provider"] == "aws"

    def test_register_valid_provider_azure(self, engine):
        result = engine.register_cloud_account("org1", {"provider": "azure"})
        assert result["provider"] == "azure"

    def test_register_valid_provider_gcp(self, engine):
        result = engine.register_cloud_account("org1", {"provider": "gcp"})
        assert result["provider"] == "gcp"

    def test_register_invalid_provider_defaults_to_aws(self, engine):
        result = engine.register_cloud_account("org1", {"provider": "oracle"})
        assert result["provider"] == "aws"

    def test_register_default_environment_prod(self, engine):
        result = engine.register_cloud_account("org1", {})
        assert result["environment"] == "prod"

    def test_register_invalid_environment_defaults_to_prod(self, engine):
        result = engine.register_cloud_account("org1", {"environment": "uat"})
        assert result["environment"] == "prod"

    def test_register_stores_account_name(self, engine):
        result = engine.register_cloud_account("org1", {"account_name": "my-account"})
        assert result["account_name"] == "my-account"

    def test_register_stores_region(self, engine):
        result = engine.register_cloud_account("org1", {"region": "eu-west-1"})
        assert result["region"] == "eu-west-1"

    def test_register_has_timestamps(self, engine):
        result = engine.register_cloud_account("org1", {})
        assert "created_at" in result
        assert "updated_at" in result


# ---------------------------------------------------------------------------
# List accounts
# ---------------------------------------------------------------------------

class TestListAccounts:
    def test_list_empty(self, engine):
        assert engine.list_accounts("org1") == []

    def test_list_returns_registered(self, engine, account):
        result = engine.list_accounts("org1")
        assert len(result) == 1
        assert result[0]["id"] == account["id"]

    def test_list_multiple(self, engine):
        engine.register_cloud_account("org1", {"provider": "aws"})
        engine.register_cloud_account("org1", {"provider": "gcp"})
        assert len(engine.list_accounts("org1")) == 2

    def test_filter_by_provider(self, engine):
        engine.register_cloud_account("org1", {"provider": "aws"})
        engine.register_cloud_account("org1", {"provider": "gcp"})
        result = engine.list_accounts("org1", provider="aws")
        assert len(result) == 1
        assert result[0]["provider"] == "aws"

    def test_org_isolation(self, engine):
        engine.register_cloud_account("org1", {})
        engine.register_cloud_account("org2", {})
        assert len(engine.list_accounts("org1")) == 1
        assert len(engine.list_accounts("org2")) == 1
        assert len(engine.list_accounts("org3")) == 0


# ---------------------------------------------------------------------------
# Misconfigurations
# ---------------------------------------------------------------------------

class TestRecordMisconfiguration:
    def test_record_returns_dict(self, engine, account):
        result = engine.record_misconfiguration("org1", {
            "account_id": account["id"],
            "service": "iam",
            "check_name": "IAM Root Account MFA Disabled",
        })
        assert isinstance(result, dict)

    def test_record_has_uuid_id(self, engine, account):
        result = engine.record_misconfiguration("org1", {"account_id": account["id"]})
        assert "id" in result
        assert len(result["id"]) == 36

    def test_record_default_compliant_false(self, engine, account):
        result = engine.record_misconfiguration("org1", {"account_id": account["id"]})
        assert result["compliant"] is False

    def test_record_compliant_true(self, engine, account):
        result = engine.record_misconfiguration("org1", {
            "account_id": account["id"],
            "compliant": True,
        })
        assert result["compliant"] is True

    def test_record_invalid_service_defaults_to_s3(self, engine, account):
        result = engine.record_misconfiguration("org1", {
            "account_id": account["id"],
            "service": "invalid-service",
        })
        assert result["service"] == "s3"

    def test_record_invalid_severity_defaults_to_medium(self, engine, account):
        result = engine.record_misconfiguration("org1", {
            "account_id": account["id"],
            "severity": "extreme",
        })
        assert result["severity"] == "medium"

    def test_record_stores_check_name(self, engine, account):
        result = engine.record_misconfiguration("org1", {
            "account_id": account["id"],
            "check_name": "S3 Bucket Logging Disabled",
        })
        assert result["check_name"] == "S3 Bucket Logging Disabled"


class TestListMisconfigurations:
    def test_list_empty(self, engine):
        assert engine.list_misconfigurations("org1") == []

    def test_list_returns_non_compliant_by_default(self, engine, misconfig):
        result = engine.list_misconfigurations("org1")
        assert len(result) == 1

    def test_compliant_findings_hidden_by_default(self, engine, account):
        engine.record_misconfiguration("org1", {
            "account_id": account["id"],
            "compliant": True,
        })
        result = engine.list_misconfigurations("org1")
        assert len(result) == 0

    def test_include_all_with_compliant_true(self, engine, account):
        engine.record_misconfiguration("org1", {"account_id": account["id"], "compliant": True})
        engine.record_misconfiguration("org1", {"account_id": account["id"], "compliant": False})
        result = engine.list_misconfigurations("org1", compliant=True)
        assert len(result) == 2

    def test_filter_by_provider(self, engine, account):
        engine.record_misconfiguration("org1", {"account_id": account["id"], "provider": "aws"})
        engine.record_misconfiguration("org1", {"account_id": account["id"], "provider": "gcp"})
        result = engine.list_misconfigurations("org1", provider="gcp", compliant=True)
        assert len(result) == 1
        assert result[0]["provider"] == "gcp"

    def test_filter_by_service(self, engine, account):
        engine.record_misconfiguration("org1", {"account_id": account["id"], "service": "iam"})
        engine.record_misconfiguration("org1", {"account_id": account["id"], "service": "rds"})
        result = engine.list_misconfigurations("org1", service="iam", compliant=True)
        assert len(result) == 1

    def test_filter_by_severity(self, engine, account):
        engine.record_misconfiguration("org1", {"account_id": account["id"], "severity": "critical"})
        engine.record_misconfiguration("org1", {"account_id": account["id"], "severity": "low"})
        result = engine.list_misconfigurations("org1", severity="critical", compliant=True)
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_org_isolation(self, engine, account):
        engine.record_misconfiguration("org1", {"account_id": account["id"]})
        assert engine.list_misconfigurations("org2") == []


class TestMarkCompliant:
    def test_mark_compliant_sets_flag(self, engine, misconfig):
        result = engine.mark_compliant("org1", misconfig["id"], "security-team")
        assert result["compliant"] is True

    def test_mark_compliant_sets_fixed_by(self, engine, misconfig):
        result = engine.mark_compliant("org1", misconfig["id"], "security-team")
        assert result["fixed_by"] == "security-team"

    def test_mark_compliant_sets_fixed_at(self, engine, misconfig):
        result = engine.mark_compliant("org1", misconfig["id"], "security-team")
        assert result["fixed_at"] is not None

    def test_mark_compliant_wrong_org_raises(self, engine, misconfig):
        with pytest.raises(ValueError):
            engine.mark_compliant("org-other", misconfig["id"], "admin")

    def test_mark_compliant_nonexistent_raises(self, engine):
        with pytest.raises(ValueError):
            engine.mark_compliant("org1", "nonexistent-id", "admin")


# ---------------------------------------------------------------------------
# Posture Check
# ---------------------------------------------------------------------------

class TestPostureCheck:
    def test_returns_dict(self, engine, account):
        result = engine.run_posture_check("org1", account["id"])
        assert isinstance(result, dict)

    def test_has_score(self, engine, account):
        result = engine.run_posture_check("org1", account["id"])
        assert "score_pct" in result
        assert 0.0 <= result["score_pct"] <= 100.0

    def test_has_total_checks(self, engine, account):
        result = engine.run_posture_check("org1", account["id"])
        assert "total_checks" in result
        assert result["total_checks"] > 0

    def test_has_passed_failed(self, engine, account):
        result = engine.run_posture_check("org1", account["id"])
        assert result["passed"] + result["failed"] == result["total_checks"]

    def test_open_misconfiguration_fails_check(self, engine, account):
        # Record a known check as non-compliant
        engine.record_misconfiguration("org1", {
            "account_id": account["id"],
            "check_name": "S3 Public Access Block Disabled",
            "service": "s3",
            "severity": "critical",
            "compliant": False,
        })
        result = engine.run_posture_check("org1", account["id"])
        assert result["failed"] >= 1

    def test_has_top_risks(self, engine, account):
        result = engine.run_posture_check("org1", account["id"])
        assert "top_risks" in result
        assert isinstance(result["top_risks"], list)

    def test_wrong_account_raises(self, engine):
        with pytest.raises(ValueError):
            engine.run_posture_check("org1", "no-such-account")

    def test_wrong_org_raises(self, engine, account):
        with pytest.raises(ValueError):
            engine.run_posture_check("org-other", account["id"])


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestCloudStats:
    def test_empty_org_stats(self, engine):
        result = engine.get_cloud_stats("org1")
        assert result["total_accounts"] == 0
        assert result["total_checks"] == 0
        assert result["compliance_pct"] == 100.0

    def test_counts_accounts(self, engine):
        engine.register_cloud_account("org1", {"provider": "aws"})
        engine.register_cloud_account("org1", {"provider": "gcp"})
        result = engine.get_cloud_stats("org1")
        assert result["total_accounts"] == 2

    def test_by_provider_breakdown(self, engine):
        engine.register_cloud_account("org1", {"provider": "aws"})
        engine.register_cloud_account("org1", {"provider": "aws"})
        engine.register_cloud_account("org1", {"provider": "gcp"})
        result = engine.get_cloud_stats("org1")
        assert result["by_provider"]["aws"] == 2
        assert result["by_provider"]["gcp"] == 1

    def test_counts_total_checks(self, engine, account, misconfig):
        result = engine.get_cloud_stats("org1")
        assert result["total_checks"] >= 1

    def test_failed_count(self, engine, account, misconfig):
        result = engine.get_cloud_stats("org1")
        assert result["failed_count"] >= 1

    def test_passed_count_after_mark_compliant(self, engine, account, misconfig):
        engine.mark_compliant("org1", misconfig["id"], "admin")
        result = engine.get_cloud_stats("org1")
        assert result["passed_count"] >= 1

    def test_critical_findings(self, engine, account, misconfig):
        # fixture misconfig has severity=critical
        result = engine.get_cloud_stats("org1")
        assert result["critical_findings"] >= 1

    def test_compliance_pct_all_passed(self, engine, account, misconfig):
        engine.mark_compliant("org1", misconfig["id"], "admin")
        result = engine.get_cloud_stats("org1")
        assert result["compliance_pct"] == 100.0

    def test_org_isolation_in_stats(self, engine):
        engine.register_cloud_account("org1", {})
        result = engine.get_cloud_stats("org2")
        assert result["total_accounts"] == 0
