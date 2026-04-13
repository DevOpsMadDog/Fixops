"""
Tests for the Security Policy Document Generator.

Covers:
- PolicyType enum values (10 types)
- PolicyDocument Pydantic model
- PolicyGenerator: generate, list, get, update, approve, archive, due-review, export
- Router endpoints (8 endpoints)
- Template content verification
- Edge cases: not-found, invalid format, org isolation

Run with: python -m pytest tests/test_policy_generator.py -v --timeout=15
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite paths are on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.policy_generator import (
    PolicyDocument,
    PolicyGenerator,
    PolicyStatus,
    PolicyType,
    _POLICY_TEMPLATES,
    _POLICY_TITLES,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def generator():
    """PolicyGenerator backed by in-memory SQLite."""
    return PolicyGenerator(db_path=":memory:")


@pytest.fixture
def org_id():
    return f"org-{uuid.uuid4().hex[:8]}"


# ===========================================================================
# PolicyType enum tests
# ===========================================================================


class TestPolicyTypeEnum:
    def test_all_ten_types_exist(self):
        expected = {
            "acceptable_use",
            "data_classification",
            "incident_response",
            "access_control",
            "encryption",
            "patch_management",
            "vendor_management",
            "change_management",
            "business_continuity",
            "password",
        }
        actual = {pt.value for pt in PolicyType}
        assert actual == expected

    def test_str_returns_value(self):
        assert str(PolicyType.ACCEPTABLE_USE) == "acceptable_use"
        assert str(PolicyType.PASSWORD) == "password"

    def test_from_string(self):
        assert PolicyType("acceptable_use") == PolicyType.ACCEPTABLE_USE
        assert PolicyType("password") == PolicyType.PASSWORD


# ===========================================================================
# PolicyDocument model tests
# ===========================================================================


class TestPolicyDocument:
    def test_default_id_generated(self):
        doc = PolicyDocument(type=PolicyType.PASSWORD, title="Test", content="Body")
        assert doc.id
        assert len(doc.id) > 10

    def test_default_status_draft(self):
        doc = PolicyDocument(type=PolicyType.ENCRYPTION, title="T", content="B")
        assert doc.status == PolicyStatus.DRAFT

    def test_default_version(self):
        doc = PolicyDocument(type=PolicyType.ACCESS_CONTROL, title="T", content="B")
        assert doc.version == "1.0"

    def test_org_id_default(self):
        doc = PolicyDocument(type=PolicyType.PASSWORD, title="T", content="B")
        assert doc.org_id == "default"

    def test_all_fields_settable(self):
        now = datetime.now(timezone.utc)
        doc = PolicyDocument(
            id="custom-id",
            type=PolicyType.INCIDENT_RESPONSE,
            title="IR Policy",
            version="2.1",
            content="## Content",
            approved_by="CISO",
            effective_date=now,
            review_date=now + timedelta(days=365),
            status=PolicyStatus.ACTIVE,
            org_id="acme",
        )
        assert doc.id == "custom-id"
        assert doc.approved_by == "CISO"
        assert doc.status == PolicyStatus.ACTIVE


# ===========================================================================
# PolicyGenerator core tests
# ===========================================================================


class TestPolicyGeneratorGenerate:
    def test_generate_returns_policy_document(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        assert isinstance(policy, PolicyDocument)

    def test_generate_sets_correct_type(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ENCRYPTION, org_id=org_id)
        assert policy.type == PolicyType.ENCRYPTION

    def test_generate_status_is_draft(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ACCESS_CONTROL, org_id=org_id)
        assert policy.status == PolicyStatus.DRAFT

    def test_generate_has_content(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PATCH_MANAGEMENT, org_id=org_id)
        assert len(policy.content) > 100

    def test_generate_sets_review_date(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id, review_days=30)
        assert policy.review_date is not None
        delta = policy.review_date - datetime.now(timezone.utc)
        assert 28 <= delta.days <= 31

    def test_generate_custom_title(self, generator, org_id):
        policy = generator.generate_policy(
            PolicyType.PASSWORD, org_id=org_id, custom_title="My Custom Password Policy"
        )
        assert policy.title == "My Custom Password Policy"

    def test_generate_default_title(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        assert policy.title == "Password Policy"

    def test_generate_org_id_stored(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.VENDOR_MANAGEMENT, org_id=org_id)
        assert policy.org_id == org_id

    def test_generate_all_ten_types(self, generator, org_id):
        for policy_type in PolicyType:
            policy = generator.generate_policy(policy_type, org_id=org_id)
            assert policy.type == policy_type
            assert len(policy.content) > 50


class TestPolicyGeneratorList:
    def test_list_empty_org(self, generator):
        result = generator.list_policies(org_id="nonexistent-org")
        assert result == []

    def test_list_returns_generated_policies(self, generator, org_id):
        generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        generator.generate_policy(PolicyType.ENCRYPTION, org_id=org_id)
        result = generator.list_policies(org_id=org_id)
        assert len(result) == 2

    def test_list_org_isolation(self, generator):
        org1 = "org-aaa"
        org2 = "org-bbb"
        generator.generate_policy(PolicyType.PASSWORD, org_id=org1)
        generator.generate_policy(PolicyType.ENCRYPTION, org_id=org2)
        assert len(generator.list_policies(org_id=org1)) == 1
        assert len(generator.list_policies(org_id=org2)) == 1

    def test_list_returns_policy_documents(self, generator, org_id):
        generator.generate_policy(PolicyType.ACCESS_CONTROL, org_id=org_id)
        result = generator.list_policies(org_id=org_id)
        assert all(isinstance(p, PolicyDocument) for p in result)


class TestPolicyGeneratorGet:
    def test_get_existing_policy(self, generator, org_id):
        created = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        fetched = generator.get_policy(created.id)
        assert fetched is not None
        assert fetched.id == created.id

    def test_get_nonexistent_returns_none(self, generator):
        result = generator.get_policy("does-not-exist")
        assert result is None

    def test_get_preserves_content(self, generator, org_id):
        created = generator.generate_policy(PolicyType.ENCRYPTION, org_id=org_id)
        fetched = generator.get_policy(created.id)
        assert fetched.content == created.content


class TestPolicyGeneratorUpdate:
    def test_update_changes_content(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        new_content = "# Updated Policy\n\nNew content here."
        updated = generator.update_policy(policy.id, content=new_content)
        assert updated is not None
        assert updated.content == new_content

    def test_update_nonexistent_returns_none(self, generator):
        result = generator.update_policy("no-such-id", content="content")
        assert result is None

    def test_update_reflects_in_get(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ACCESS_CONTROL, org_id=org_id)
        generator.update_policy(policy.id, content="# New Content")
        fetched = generator.get_policy(policy.id)
        assert fetched.content == "# New Content"

    def test_update_bumps_updated_at(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ENCRYPTION, org_id=org_id)
        original_updated = policy.updated_at
        updated = generator.update_policy(policy.id, content="New")
        assert updated.updated_at >= original_updated


class TestPolicyGeneratorApprove:
    def test_approve_sets_status_active(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        approved = generator.approve_policy(policy.id, approver="ciso@example.com")
        assert approved.status == PolicyStatus.ACTIVE

    def test_approve_sets_approver(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ENCRYPTION, org_id=org_id)
        approved = generator.approve_policy(policy.id, approver="Jane CISO")
        assert approved.approved_by == "Jane CISO"

    def test_approve_sets_effective_date(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ACCESS_CONTROL, org_id=org_id)
        approved = generator.approve_policy(policy.id, approver="admin")
        assert approved.effective_date is not None

    def test_approve_nonexistent_returns_none(self, generator):
        result = generator.approve_policy("no-such-id", approver="admin")
        assert result is None

    def test_approve_persisted_on_get(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PATCH_MANAGEMENT, org_id=org_id)
        generator.approve_policy(policy.id, approver="CISO")
        fetched = generator.get_policy(policy.id)
        assert fetched.status == PolicyStatus.ACTIVE
        assert fetched.approved_by == "CISO"


class TestPolicyGeneratorArchive:
    def test_archive_sets_status(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        archived = generator.archive_policy(policy.id)
        assert archived.status == PolicyStatus.ARCHIVED

    def test_archive_nonexistent_returns_none(self, generator):
        result = generator.archive_policy("no-such-id")
        assert result is None

    def test_archive_persisted_on_get(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.VENDOR_MANAGEMENT, org_id=org_id)
        generator.archive_policy(policy.id)
        fetched = generator.get_policy(policy.id)
        assert fetched.status == PolicyStatus.ARCHIVED


class TestPolicyGeneratorDueReview:
    def test_no_overdue_policies(self, generator, org_id):
        generator.generate_policy(PolicyType.PASSWORD, org_id=org_id, review_days=365)
        result = generator.get_policies_due_review(org_id=org_id)
        assert result == []

    def test_overdue_policy_returned(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        # Manually backdate review_date
        past = datetime.now(timezone.utc) - timedelta(days=1)
        generator.update_policy(policy.id, content=policy.content)
        # Update review_date directly via SQL
        conn = generator._connect()
        conn.execute(
            "UPDATE policy_documents SET review_date = ? WHERE id = ?",
            (past.isoformat(), policy.id),
        )
        conn.commit()
        result = generator.get_policies_due_review(org_id=org_id)
        assert any(p.id == policy.id for p in result)

    def test_archived_policies_excluded_from_due_review(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ENCRYPTION, org_id=org_id)
        past = datetime.now(timezone.utc) - timedelta(days=1)
        conn = generator._connect()
        conn.execute(
            "UPDATE policy_documents SET review_date = ?, status = 'archived' WHERE id = ?",
            (past.isoformat(), policy.id),
        )
        conn.commit()
        result = generator.get_policies_due_review(org_id=org_id)
        assert not any(p.id == policy.id for p in result)

    def test_due_review_org_isolation(self, generator):
        org1, org2 = "org-x1", "org-x2"
        p1 = generator.generate_policy(PolicyType.PASSWORD, org_id=org1)
        generator.generate_policy(PolicyType.ENCRYPTION, org_id=org2)
        past = datetime.now(timezone.utc) - timedelta(days=1)
        conn = generator._connect()
        conn.execute(
            "UPDATE policy_documents SET review_date = ? WHERE id = ?",
            (past.isoformat(), p1.id),
        )
        conn.commit()
        result_org1 = generator.get_policies_due_review(org_id=org1)
        result_org2 = generator.get_policies_due_review(org_id=org2)
        assert any(p.id == p1.id for p in result_org1)
        assert len(result_org2) == 0


class TestPolicyGeneratorExport:
    def test_export_markdown(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        result = generator.export_policy(policy.id, format="markdown")
        assert result is not None
        assert "---" in result
        assert "Password Policy" in result
        assert policy.id in result

    def test_export_html(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ENCRYPTION, org_id=org_id)
        result = generator.export_policy(policy.id, format="html")
        assert result is not None
        assert "<!DOCTYPE html>" in result
        assert "Encryption Policy" in result
        assert "<table>" in result  # encryption policy has a table

    def test_export_markdown_uppercase(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.ACCESS_CONTROL, org_id=org_id)
        result = generator.export_policy(policy.id, format="Markdown")
        assert result is not None
        assert "---" in result

    def test_export_invalid_format_raises(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.PASSWORD, org_id=org_id)
        with pytest.raises(ValueError, match="Unsupported export format"):
            generator.export_policy(policy.id, format="pdf")

    def test_export_nonexistent_returns_none(self, generator):
        result = generator.export_policy("no-such-id", format="markdown")
        assert result is None

    def test_export_html_contains_metadata(self, generator, org_id):
        policy = generator.generate_policy(PolicyType.VENDOR_MANAGEMENT, org_id=org_id)
        generator.approve_policy(policy.id, approver="CEO")
        result = generator.export_policy(policy.id, format="html")
        assert "CEO" in result
        assert policy.id in result


# ===========================================================================
# Template content tests
# ===========================================================================


class TestPolicyTemplates:
    def test_all_types_have_title(self):
        for pt in PolicyType:
            assert pt in _POLICY_TITLES, f"Missing title for {pt}"
            assert len(_POLICY_TITLES[pt]) > 5

    def test_all_types_have_template(self):
        for pt in PolicyType:
            assert pt in _POLICY_TEMPLATES, f"Missing template for {pt}"
            assert len(_POLICY_TEMPLATES[pt]) > 200

    def test_acceptable_use_template_content(self):
        content = _POLICY_TEMPLATES[PolicyType.ACCEPTABLE_USE]
        assert "Prohibited" in content
        assert "Monitoring" in content

    def test_incident_response_template_content(self):
        content = _POLICY_TEMPLATES[PolicyType.INCIDENT_RESPONSE]
        assert "Containment" in content
        assert "Eradication" in content
        assert "Recovery" in content

    def test_password_template_requirements(self):
        content = _POLICY_TEMPLATES[PolicyType.PASSWORD]
        assert "MFA" in content or "Multi-Factor" in content
        assert "16" in content  # min length

    def test_encryption_template_algorithms(self):
        content = _POLICY_TEMPLATES[PolicyType.ENCRYPTION]
        assert "AES" in content
        assert "TLS" in content

    def test_patch_management_sla_table(self):
        content = _POLICY_TEMPLATES[PolicyType.PATCH_MANAGEMENT]
        assert "Critical" in content
        assert "48 hours" in content

    def test_data_classification_levels(self):
        content = _POLICY_TEMPLATES[PolicyType.DATA_CLASSIFICATION]
        assert "Public" in content
        assert "Confidential" in content
        assert "Restricted" in content


# ===========================================================================
# Router endpoint tests
# ===========================================================================


class TestPolicyGeneratorRouter:
    """Tests for the FastAPI router endpoints via TestClient."""

    @pytest.fixture(autouse=True)
    def setup_client(self):
        try:
            from fastapi.testclient import TestClient
            from fastapi import FastAPI
            from apps.api.policy_generator_router import router, _generator
        except ImportError as exc:
            pytest.skip(f"FastAPI or router not available: {exc}")

        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)
        # Reset singleton for test isolation
        import core.policy_generator as pg_mod
        import apps.api.policy_generator_router as router_mod
        fresh = PolicyGenerator(db_path=":memory:")
        router_mod._generator = fresh
        self._generator = fresh

    def test_generate_endpoint_returns_201(self):
        resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "password", "org_id": "test-org"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["type"] == "password"
        assert data["status"] == "draft"
        assert "id" in data

    def test_generate_all_policy_types(self):
        for pt in PolicyType:
            resp = self.client.post(
                "/api/v1/policy-generator/generate",
                json={"type": pt.value, "org_id": "test-org"},
            )
            assert resp.status_code == 201, f"Failed for {pt.value}: {resp.text}"

    def test_list_policies_endpoint(self):
        self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "password", "org_id": "list-org"},
        )
        resp = self.client.get("/api/v1/policy-generator/policies?org_id=list-org")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_get_policy_endpoint(self):
        gen_resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "encryption", "org_id": "get-org"},
        )
        policy_id = gen_resp.json()["id"]
        resp = self.client.get(f"/api/v1/policy-generator/policies/{policy_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == policy_id

    def test_get_policy_not_found(self):
        resp = self.client.get("/api/v1/policy-generator/policies/does-not-exist")
        assert resp.status_code == 404

    def test_update_policy_endpoint(self):
        gen_resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "access_control", "org_id": "upd-org"},
        )
        policy_id = gen_resp.json()["id"]
        new_content = "# Updated\nNew content."
        resp = self.client.put(
            f"/api/v1/policy-generator/policies/{policy_id}/content",
            json={"content": new_content},
        )
        assert resp.status_code == 200
        assert resp.json()["content"] == new_content

    def test_approve_policy_endpoint(self):
        gen_resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "patch_management", "org_id": "apr-org"},
        )
        policy_id = gen_resp.json()["id"]
        resp = self.client.post(
            f"/api/v1/policy-generator/policies/{policy_id}/approve",
            json={"approver": "CISO Jones"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "active"
        assert data["approved_by"] == "CISO Jones"
        assert data["effective_date"] is not None

    def test_archive_policy_endpoint(self):
        gen_resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "vendor_management", "org_id": "arc-org"},
        )
        policy_id = gen_resp.json()["id"]
        resp = self.client.post(f"/api/v1/policy-generator/policies/{policy_id}/archive")
        assert resp.status_code == 200
        assert resp.json()["status"] == "archived"

    def test_due_review_endpoint_empty(self):
        resp = self.client.get("/api/v1/policy-generator/policies/due-review?org_id=empty-org")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_export_markdown_endpoint(self):
        gen_resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "password", "org_id": "exp-org"},
        )
        policy_id = gen_resp.json()["id"]
        resp = self.client.get(
            f"/api/v1/policy-generator/policies/{policy_id}/export?format=markdown"
        )
        assert resp.status_code == 200
        assert "Password Policy" in resp.text
        assert "---" in resp.text

    def test_export_html_endpoint(self):
        gen_resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "encryption", "org_id": "exp-org"},
        )
        policy_id = gen_resp.json()["id"]
        resp = self.client.get(
            f"/api/v1/policy-generator/policies/{policy_id}/export?format=html"
        )
        assert resp.status_code == 200
        assert "<!DOCTYPE html>" in resp.text
        assert "Encryption Policy" in resp.text

    def test_export_invalid_format_returns_400(self):
        gen_resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={"type": "password", "org_id": "exp-org"},
        )
        policy_id = gen_resp.json()["id"]
        resp = self.client.get(
            f"/api/v1/policy-generator/policies/{policy_id}/export?format=pdf"
        )
        assert resp.status_code == 400

    def test_export_not_found_returns_404(self):
        resp = self.client.get(
            "/api/v1/policy-generator/policies/no-such-id/export?format=markdown"
        )
        assert resp.status_code == 404

    def test_custom_title_via_generate_endpoint(self):
        resp = self.client.post(
            "/api/v1/policy-generator/generate",
            json={
                "type": "change_management",
                "org_id": "cm-org",
                "custom_title": "ACME Change Policy",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["title"] == "ACME Change Policy"
