"""Comprehensive tests for IaCDB, SecretsDB, IntegrationDB modules.

Covers CRUD operations for all three database managers:
- IaCDB: create, get, list, update findings
- SecretsDB: create, get, list, update secret findings
- IntegrationDB: create, get, list, update, delete integrations
"""

import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "suite-core"))

from core.iac_db import IaCDB
from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider
from core.integration_db import IntegrationDB
from core.integration_models import Integration, IntegrationStatus, IntegrationType
from core.secrets_db import SecretsDB
from core.secrets_models import SecretFinding, SecretStatus, SecretType


# ===========================================================================
# IaCDB
# ===========================================================================


class TestIaCDB:
    """Test IaC database CRUD operations."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = IaCDB(db_path=os.path.join(self.tmpdir, "test_iac.db"))

    def _make_finding(self, **overrides) -> IaCFinding:
        defaults = dict(
            id="",
            provider=IaCProvider.TERRAFORM,
            status=IaCFindingStatus.OPEN,
            severity="high",
            title="S3 bucket public",
            description="S3 bucket allows public access",
            file_path="main.tf",
            line_number=42,
            resource_type="aws_s3_bucket",
            resource_name="data_bucket",
            rule_id="AWS-S3-001",
            remediation="Set block_public_access to true",
        )
        defaults.update(overrides)
        return IaCFinding(**defaults)

    def test_create_finding(self):
        finding = self._make_finding()
        result = self.db.create_finding(finding)
        assert result.id  # Should get an ID assigned
        assert result.title == "S3 bucket public"

    def test_get_finding(self):
        finding = self._make_finding()
        created = self.db.create_finding(finding)
        retrieved = self.db.get_finding(created.id)
        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.title == "S3 bucket public"

    def test_get_nonexistent_finding(self):
        result = self.db.get_finding("nonexistent-id")
        assert result is None

    def test_list_findings_empty(self):
        results = self.db.list_findings()
        assert results == []

    def test_list_findings_with_data(self):
        self.db.create_finding(self._make_finding(title="Finding 1"))
        self.db.create_finding(self._make_finding(title="Finding 2"))
        results = self.db.list_findings()
        assert len(results) == 2

    def test_list_findings_with_provider_filter(self):
        self.db.create_finding(self._make_finding(provider=IaCProvider.TERRAFORM))
        self.db.create_finding(self._make_finding(provider=IaCProvider.CLOUDFORMATION))
        results = self.db.list_findings(provider="terraform")
        assert len(results) == 1

    def test_list_findings_pagination(self):
        for i in range(5):
            self.db.create_finding(self._make_finding(title=f"Finding {i}"))
        results = self.db.list_findings(limit=2, offset=0)
        assert len(results) == 2
        results2 = self.db.list_findings(limit=2, offset=2)
        assert len(results2) == 2

    def test_update_finding(self):
        finding = self._make_finding()
        created = self.db.create_finding(finding)
        created.status = IaCFindingStatus.RESOLVED
        created.resolved_at = datetime.utcnow()
        updated = self.db.update_finding(created)
        assert updated.status == IaCFindingStatus.RESOLVED

        # Verify persistence
        retrieved = self.db.get_finding(created.id)
        assert retrieved.status == IaCFindingStatus.RESOLVED


# ===========================================================================
# SecretsDB
# ===========================================================================


class TestSecretsDB:
    """Test secrets database CRUD operations."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = SecretsDB(db_path=os.path.join(self.tmpdir, "test_secrets.db"))

    def _make_finding(self, **overrides) -> SecretFinding:
        defaults = dict(
            id="",
            secret_type=SecretType.API_KEY,
            status=SecretStatus.ACTIVE,
            file_path="config.py",
            line_number=15,
            repository="org/myapp",
            branch="main",
            commit_hash="abc123",
            matched_pattern="AKIA[0-9A-Z]{16}",
            entropy_score=4.5,
        )
        defaults.update(overrides)
        return SecretFinding(**defaults)

    def test_create_finding(self):
        finding = self._make_finding()
        result = self.db.create_finding(finding)
        assert result.id
        assert result.secret_type == SecretType.API_KEY

    def test_get_finding(self):
        created = self.db.create_finding(self._make_finding())
        retrieved = self.db.get_finding(created.id)
        assert retrieved is not None
        assert retrieved.id == created.id

    def test_get_nonexistent(self):
        result = self.db.get_finding("nonexistent")
        assert result is None

    def test_list_findings_empty(self):
        assert self.db.list_findings() == []

    def test_list_findings_with_data(self):
        self.db.create_finding(self._make_finding())
        self.db.create_finding(self._make_finding())
        results = self.db.list_findings()
        assert len(results) == 2

    def test_list_findings_by_repository(self):
        self.db.create_finding(self._make_finding(repository="org/app1"))
        self.db.create_finding(self._make_finding(repository="org/app2"))
        results = self.db.list_findings(repository="org/app1")
        assert len(results) == 1

    def test_update_finding(self):
        created = self.db.create_finding(self._make_finding())
        created.status = SecretStatus.RESOLVED
        created.resolved_at = datetime.utcnow()
        updated = self.db.update_finding(created)
        assert updated.status == SecretStatus.RESOLVED


# ===========================================================================
# IntegrationDB
# ===========================================================================


class TestIntegrationDB:
    """Test integration database CRUD operations."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db = IntegrationDB(
            db_path=os.path.join(self.tmpdir, "test_integrations.db")
        )

    def _make_integration(self, **overrides) -> Integration:
        defaults = dict(
            id="",
            name="test-jira",
            integration_type=IntegrationType.JIRA,
            status=IntegrationStatus.ACTIVE,
            config={"url": "https://jira.example.com", "project": "SEC"},
        )
        defaults.update(overrides)
        return Integration(**defaults)

    def test_create_integration(self):
        integration = self._make_integration()
        result = self.db.create_integration(integration)
        assert result.id
        assert result.name == "test-jira"

    def test_get_integration(self):
        created = self.db.create_integration(self._make_integration())
        retrieved = self.db.get_integration(created.id)
        assert retrieved is not None
        assert retrieved.name == "test-jira"

    def test_get_nonexistent(self):
        result = self.db.get_integration("nonexistent")
        assert result is None

    def test_list_integrations_empty(self):
        assert self.db.list_integrations() == []

    def test_list_integrations_with_data(self):
        self.db.create_integration(self._make_integration(name="jira-1"))
        self.db.create_integration(self._make_integration(name="jira-2"))
        results = self.db.list_integrations()
        assert len(results) == 2

    def test_list_integrations_by_type(self):
        self.db.create_integration(
            self._make_integration(name="jira-1", integration_type=IntegrationType.JIRA)
        )
        self.db.create_integration(
            self._make_integration(
                name="slack-1", integration_type=IntegrationType.SLACK
            )
        )
        results = self.db.list_integrations(integration_type="jira")
        assert len(results) == 1

    def test_update_integration(self):
        created = self.db.create_integration(self._make_integration())
        created.status = IntegrationStatus.INACTIVE
        updated = self.db.update_integration(created)
        assert updated.status == IntegrationStatus.INACTIVE

    def test_delete_integration(self):
        created = self.db.create_integration(self._make_integration())
        result = self.db.delete_integration(created.id)
        assert result is True
        assert self.db.get_integration(created.id) is None
