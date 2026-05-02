"""
Negative-path tests for the 3 hardened routers.

Strategy:
  - Layer 1: Pydantic model tests — instantiate models directly, prove ValidationError
    fires on bad input. No HTTP, no auth, no engine startup needed.
  - Layer 2: HTTP integration tests — use FIXOPS_MODE=dev (auth relaxed) to send
    invalid JSON bodies and confirm FastAPI returns 422 before reaching business logic.

Routers / models under test:
  1. scanner_ingest_router  — _IngestBody (POST /api/v1/scanners/ingest)
  2. scim_router             — ScimCreateUserRequest, ScimCreateGroupRequest
  3. zero_trust_policy_router — CreatePolicyRequest, EvaluateAccessRequest,
                                RecordAccessEventRequest
"""
from __future__ import annotations

import os

import pytest
from pydantic import ValidationError


# ===========================================================================
# 1. scanner_ingest_router — _IngestBody model layer tests
# ===========================================================================

class TestScannerIngestModelValidation:
    """Direct Pydantic model tests for _IngestBody constraints."""

    def _get_model(self):
        import sys
        sys.path.insert(0, "suite-api")
        from apps.api.scanner_ingest_router import _IngestBody
        return _IngestBody

    def test_scanner_type_too_long_raises(self):
        """scanner_type exceeding 64 chars must raise ValidationError."""
        _IngestBody = self._get_model()
        with pytest.raises(ValidationError) as exc_info:
            _IngestBody(
                scanner_type="a" * 65,  # violates max_length=64
                app_id="myapp",
                org_id="default",
            )
        errors = exc_info.value.errors()
        assert any("scanner_type" in str(e) for e in errors), (
            f"Expected scanner_type error, got: {errors}"
        )

    def test_scanner_type_invalid_pattern_raises(self):
        """scanner_type with injection chars must raise ValidationError."""
        _IngestBody = self._get_model()
        with pytest.raises(ValidationError) as exc_info:
            _IngestBody(
                scanner_type="../evil; rm -rf /",  # violates pattern
                app_id="myapp",
                org_id="default",
            )
        errors = exc_info.value.errors()
        assert any("scanner_type" in str(e) for e in errors), (
            f"Expected scanner_type error, got: {errors}"
        )

    def test_org_id_empty_string_raises(self):
        """org_id with min_length=1 must reject empty string."""
        _IngestBody = self._get_model()
        with pytest.raises(ValidationError) as exc_info:
            _IngestBody(
                scanner_type="semgrep",
                app_id="myapp",
                org_id="",  # violates min_length=1
            )
        errors = exc_info.value.errors()
        assert any("org_id" in str(e) for e in errors), (
            f"Expected org_id error, got: {errors}"
        )

    def test_app_id_too_long_raises(self):
        """app_id exceeding 255 chars must raise ValidationError."""
        _IngestBody = self._get_model()
        with pytest.raises(ValidationError) as exc_info:
            _IngestBody(
                scanner_type="trivy",
                app_id="x" * 256,  # violates max_length=255
                org_id="default",
            )
        errors = exc_info.value.errors()
        assert any("app_id" in str(e) for e in errors), (
            f"Expected app_id error, got: {errors}"
        )

    def test_valid_body_accepted(self):
        """Well-formed _IngestBody must instantiate without error."""
        _IngestBody = self._get_model()
        body = _IngestBody(
            scanner_type="semgrep",
            app_id="myapp",
            org_id="default",
            findings=[],
        )
        assert body.scanner_type == "semgrep"
        assert body.org_id == "default"


# ===========================================================================
# 2. scim_router — ScimCreateUserRequest / ScimCreateGroupRequest model tests
# ===========================================================================

class TestScimModelValidation:
    """Direct Pydantic model tests for SCIM request models."""

    def _get_user_model(self):
        import sys
        sys.path.insert(0, "suite-api")
        from apps.api.scim_router import ScimCreateUserRequest
        return ScimCreateUserRequest

    def _get_group_model(self):
        import sys
        sys.path.insert(0, "suite-api")
        from apps.api.scim_router import ScimCreateGroupRequest
        return ScimCreateGroupRequest

    def test_create_user_missing_username_raises(self):
        """userName is required; omitting it must raise ValidationError."""
        ScimCreateUserRequest = self._get_user_model()
        with pytest.raises(ValidationError) as exc_info:
            ScimCreateUserRequest(displayName="Alice")  # no userName
        errors = exc_info.value.errors()
        assert any("userName" in str(e) for e in errors), (
            f"Expected userName error, got: {errors}"
        )

    def test_create_user_username_too_long_raises(self):
        """userName exceeding 254 chars must raise ValidationError."""
        ScimCreateUserRequest = self._get_user_model()
        with pytest.raises(ValidationError) as exc_info:
            ScimCreateUserRequest(userName="u" * 255)  # violates max_length=254
        errors = exc_info.value.errors()
        assert any("userName" in str(e) for e in errors), (
            f"Expected userName error, got: {errors}"
        )

    def test_create_user_invalid_email_raises(self):
        """Email value without '@' must raise ValidationError."""
        ScimCreateUserRequest = self._get_user_model()
        with pytest.raises(ValidationError) as exc_info:
            ScimCreateUserRequest(
                userName="alice@example.com",
                emails=[{"value": "not-an-email"}],  # missing @
            )
        errors = exc_info.value.errors()
        assert len(errors) > 0, f"Expected email validation error, got: {errors}"

    def test_create_group_missing_display_name_raises(self):
        """displayName is required; omitting it must raise ValidationError."""
        ScimCreateGroupRequest = self._get_group_model()
        with pytest.raises(ValidationError) as exc_info:
            ScimCreateGroupRequest(members=[])  # no displayName
        errors = exc_info.value.errors()
        assert any("displayName" in str(e) for e in errors), (
            f"Expected displayName error, got: {errors}"
        )

    def test_create_group_display_name_too_long_raises(self):
        """displayName exceeding 256 chars must raise ValidationError."""
        ScimCreateGroupRequest = self._get_group_model()
        with pytest.raises(ValidationError) as exc_info:
            ScimCreateGroupRequest(displayName="g" * 257)  # violates max_length=256
        errors = exc_info.value.errors()
        assert any("displayName" in str(e) for e in errors), (
            f"Expected displayName error, got: {errors}"
        )

    def test_valid_user_accepted(self):
        """Well-formed ScimCreateUserRequest must instantiate without error."""
        ScimCreateUserRequest = self._get_user_model()
        user = ScimCreateUserRequest(
            userName="alice@example.com",
            displayName="Alice Smith",
            emails=[{"value": "alice@example.com", "type": "work"}],
        )
        assert user.userName == "alice@example.com"

    def test_valid_group_accepted(self):
        """Well-formed ScimCreateGroupRequest must instantiate without error."""
        ScimCreateGroupRequest = self._get_group_model()
        group = ScimCreateGroupRequest(displayName="Engineering")
        assert group.displayName == "Engineering"


# ===========================================================================
# 3. zero_trust_policy_router — model layer tests
# ===========================================================================

class TestZeroTrustModelValidation:
    """Direct Pydantic model tests for Zero Trust request models."""

    def _get_create_model(self):
        import sys
        sys.path.insert(0, "suite-api")
        sys.path.insert(0, "suite-core")
        from apps.api.zero_trust_policy_router import CreatePolicyRequest
        return CreatePolicyRequest

    def _get_evaluate_model(self):
        import sys
        sys.path.insert(0, "suite-api")
        sys.path.insert(0, "suite-core")
        from apps.api.zero_trust_policy_router import EvaluateAccessRequest
        return EvaluateAccessRequest

    def _get_record_model(self):
        import sys
        sys.path.insert(0, "suite-api")
        sys.path.insert(0, "suite-core")
        from apps.api.zero_trust_policy_router import RecordAccessEventRequest
        return RecordAccessEventRequest

    def test_create_policy_missing_name_raises(self):
        """name is required; omitting it must raise ValidationError."""
        CreatePolicyRequest = self._get_create_model()
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(policy_type="network", action="deny")
        errors = exc_info.value.errors()
        assert any("name" in str(e) for e in errors), (
            f"Expected name error, got: {errors}"
        )

    def test_create_policy_name_too_long_raises(self):
        """name exceeding 255 chars must raise ValidationError."""
        CreatePolicyRequest = self._get_create_model()
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(
                name="n" * 256,  # violates max_length=255
                policy_type="network",
                action="deny",
            )
        errors = exc_info.value.errors()
        assert any("name" in str(e) for e in errors), (
            f"Expected name error, got: {errors}"
        )

    def test_create_policy_invalid_policy_type_raises(self):
        """policy_type must be one of the Literal values."""
        CreatePolicyRequest = self._get_create_model()
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(
                name="TestPolicy",
                policy_type="INVALID_TYPE",  # not in Literal
                action="deny",
            )
        errors = exc_info.value.errors()
        assert any("policy_type" in str(e) for e in errors), (
            f"Expected policy_type error, got: {errors}"
        )

    def test_create_policy_invalid_action_raises(self):
        """action must be one of allow|deny|mfa_required."""
        CreatePolicyRequest = self._get_create_model()
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(
                name="TestPolicy",
                policy_type="network",
                action="HACK",  # not in Literal
            )
        errors = exc_info.value.errors()
        assert any("action" in str(e) for e in errors), (
            f"Expected action error, got: {errors}"
        )

    def test_create_policy_priority_out_of_range_raises(self):
        """priority must be 0–1000; negative value must raise ValidationError."""
        CreatePolicyRequest = self._get_create_model()
        with pytest.raises(ValidationError) as exc_info:
            CreatePolicyRequest(
                name="TestPolicy",
                policy_type="network",
                action="deny",
                priority=-1,  # violates ge=0
            )
        errors = exc_info.value.errors()
        assert any("priority" in str(e) for e in errors), (
            f"Expected priority error, got: {errors}"
        )

    def test_evaluate_source_ip_invalid_raises(self):
        """source_ip must match IP/CIDR pattern; garbage string must raise."""
        EvaluateAccessRequest = self._get_evaluate_model()
        with pytest.raises(ValidationError) as exc_info:
            EvaluateAccessRequest(
                user="alice",
                device="laptop",
                source_ip="not-an-ip-address!!!",  # violates pattern
                destination="api.internal",
                resource="/admin",
                org_id="default",
            )
        errors = exc_info.value.errors()
        assert any("source_ip" in str(e) for e in errors), (
            f"Expected source_ip error, got: {errors}"
        )

    def test_record_access_event_invalid_decision_raises(self):
        """decision must be allow|deny|mfa_required; unknown value must raise."""
        RecordAccessEventRequest = self._get_record_model()
        with pytest.raises(ValidationError) as exc_info:
            RecordAccessEventRequest(
                user="alice",
                device="laptop",
                resource="/admin",
                decision="UNKNOWN_DECISION",  # not in Literal
                source_ip="",
                org_id="default",
            )
        errors = exc_info.value.errors()
        assert any("decision" in str(e) for e in errors), (
            f"Expected decision error, got: {errors}"
        )

    def test_valid_policy_request_accepted(self):
        """Well-formed CreatePolicyRequest must instantiate without error."""
        CreatePolicyRequest = self._get_create_model()
        req = CreatePolicyRequest(
            name="Block External",
            description="Deny all external traffic",
            policy_type="network",
            action="deny",
            priority=10,
            enabled=True,
        )
        assert req.name == "Block External"
        assert req.action == "deny"

    def test_valid_evaluate_request_accepted(self):
        """Well-formed EvaluateAccessRequest must instantiate without error."""
        EvaluateAccessRequest = self._get_evaluate_model()
        req = EvaluateAccessRequest(
            user="alice",
            device="laptop-01",
            source_ip="192.168.1.100",
            destination="api.internal",
            resource="/admin",
            org_id="default",
        )
        assert req.source_ip == "192.168.1.100"


# ===========================================================================
# 4. HTTP integration tests (FIXOPS_MODE=dev bypasses auth)
# ===========================================================================

_TEST_API_TOKEN = "hardener-test-token-2026"  # noqa: S105


@pytest.fixture(scope="module")
def dev_client():
    """TestClient with FIXOPS_API_TOKEN set so X-API-Key auth works."""
    import sys
    sys.path.insert(0, "suite-api")
    sys.path.insert(0, "suite-core")
    # Set token BEFORE importing app so _load_api_tokens() sees it on first call
    os.environ["FIXOPS_API_TOKEN"] = _TEST_API_TOKEN
    from fastapi.testclient import TestClient
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    os.environ.pop("FIXOPS_API_TOKEN", None)


_AUTH = {"X-API-Key": _TEST_API_TOKEN}


class TestHTTPValidation422:
    """HTTP-layer tests: invalid bodies must return 422 before business logic."""

    def test_ingest_invalid_scanner_type_returns_422(self, dev_client):
        """POST /api/v1/scanners/ingest with injection scanner_type → 422."""
        resp = dev_client.post(
            "/api/v1/scanners/ingest",
            json={"scanner_type": "../evil; rm -rf /", "org_id": "default"},
            headers=_AUTH,
        )
        assert resp.status_code == 422, (
            f"Expected 422, got {resp.status_code}: {resp.text[:300]}"
        )

    def test_ingest_overlong_org_id_returns_422(self, dev_client):
        """POST /api/v1/scanners/ingest with org_id > 128 chars → 422."""
        resp = dev_client.post(
            "/api/v1/scanners/ingest",
            json={"scanner_type": "semgrep", "org_id": "o" * 129},
            headers=_AUTH,
        )
        assert resp.status_code == 422, (
            f"Expected 422, got {resp.status_code}: {resp.text[:300]}"
        )

    def test_zero_trust_invalid_policy_type_returns_422(self, dev_client):
        """POST /api/v1/zero-trust-policy/policies with bad policy_type → 422."""
        resp = dev_client.post(
            "/api/v1/zero-trust-policy/policies",
            json={"name": "Test", "policy_type": "BADTYPE", "action": "deny"},
            headers=_AUTH,
        )
        assert resp.status_code == 422, (
            f"Expected 422, got {resp.status_code}: {resp.text[:300]}"
        )

    def test_zero_trust_negative_priority_returns_422(self, dev_client):
        """POST /api/v1/zero-trust-policy/policies with priority=-1 → 422."""
        resp = dev_client.post(
            "/api/v1/zero-trust-policy/policies",
            json={"name": "Test", "policy_type": "network", "action": "deny", "priority": -1},
            headers=_AUTH,
        )
        assert resp.status_code == 422, (
            f"Expected 422, got {resp.status_code}: {resp.text[:300]}"
        )
