"""
Tests for RBAC role enforcement and audit logging.

Covers:
- RBACRole / RBACPermission enums
- ROLE_PERMISSIONS mapping
- require_permission / require_role dependency logic
- get_current_user_role extraction
- AuditAction / AuditEntry model
- AuditLogger: log, query, get_user_activity, get_resource_history, export_csv
- Integration: write request triggers audit entry
"""
from __future__ import annotations

import sys
import types
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

# Ensure suite-core is importable
sys.path.insert(0, "suite-core")

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from core.rbac import (
    RBACPermission,
    RBACRole,
    ROLE_PERMISSIONS,
    get_current_user_role,
    require_permission,
    require_role,
)
from core.audit_log import (
    AuditAction,
    AuditEntry,
    AuditLogger,
    AuditMiddleware,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(role: str = "admin") -> MagicMock:
    """Build a minimal mock FastAPI Request with auth state."""
    req = MagicMock()
    auth = MagicMock()
    auth.role = role
    auth.email = f"{role}@example.com"
    req.state.auth = auth
    req.client.host = "127.0.0.1"
    req.headers = {}
    return req


def _fresh_logger() -> AuditLogger:
    """Return a fresh in-memory AuditLogger (not the singleton)."""
    AuditLogger.reset_instance()
    return AuditLogger(db_path=":memory:")


# ===========================================================================
# RBAC — RBACRole enum
# ===========================================================================

class TestRBACRoleEnum:
    def test_all_six_roles_exist(self):
        roles = {r.value for r in RBACRole}
        assert roles == {"admin", "security_analyst", "developer", "compliance_officer", "viewer", "sre"}

    def test_admin_has_highest_level(self):
        assert RBACRole.ADMIN.level > RBACRole.SECURITY_ANALYST.level
        assert RBACRole.ADMIN.level > RBACRole.SRE.level

    def test_viewer_has_lowest_level(self):
        for role in RBACRole:
            if role != RBACRole.VIEWER:
                assert RBACRole.VIEWER.level < role.level

    def test_level_ordering(self):
        ordered = sorted(RBACRole, key=lambda r: r.level)
        assert ordered[0] == RBACRole.VIEWER
        assert ordered[-1] == RBACRole.ADMIN


# ===========================================================================
# RBAC — RBACPermission enum
# ===========================================================================

class TestRBACPermissionEnum:
    def test_all_required_permissions_present(self):
        expected = {
            "read:findings", "write:findings", "delete:findings",
            "read:compliance", "write:compliance",
            "read:pipeline", "run:pipeline",
            "read:connectors", "write:connectors",
            "manage:users", "manage:settings",
            "read:audit_log", "read:dashboard",
        }
        actual = {p.value for p in RBACPermission}
        assert expected == actual

    def test_permission_values_are_strings(self):
        for p in RBACPermission:
            assert isinstance(p.value, str)
            assert ":" in p.value


# ===========================================================================
# RBAC — ROLE_PERMISSIONS mapping
# ===========================================================================

class TestRolePermissionsMapping:
    def test_all_roles_present_in_mapping(self):
        for role in RBACRole:
            assert role in ROLE_PERMISSIONS

    def test_admin_has_all_permissions(self):
        admin_perms = ROLE_PERMISSIONS[RBACRole.ADMIN]
        for p in RBACPermission:
            assert p in admin_perms

    def test_viewer_read_only(self):
        viewer_perms = ROLE_PERMISSIONS[RBACRole.VIEWER]
        assert RBACPermission.READ_FINDINGS in viewer_perms
        assert RBACPermission.READ_DASHBOARD in viewer_perms
        assert RBACPermission.WRITE_FINDINGS not in viewer_perms
        assert RBACPermission.DELETE_FINDINGS not in viewer_perms
        assert RBACPermission.MANAGE_USERS not in viewer_perms

    def test_security_analyst_can_write_findings(self):
        perms = ROLE_PERMISSIONS[RBACRole.SECURITY_ANALYST]
        assert RBACPermission.WRITE_FINDINGS in perms
        assert RBACPermission.RUN_PIPELINE in perms

    def test_security_analyst_cannot_manage_users(self):
        perms = ROLE_PERMISSIONS[RBACRole.SECURITY_ANALYST]
        assert RBACPermission.MANAGE_USERS not in perms

    def test_compliance_officer_audit_log_access(self):
        perms = ROLE_PERMISSIONS[RBACRole.COMPLIANCE_OFFICER]
        assert RBACPermission.READ_AUDIT_LOG in perms
        assert RBACPermission.WRITE_COMPLIANCE in perms

    def test_compliance_officer_cannot_delete_findings(self):
        perms = ROLE_PERMISSIONS[RBACRole.COMPLIANCE_OFFICER]
        assert RBACPermission.DELETE_FINDINGS not in perms

    def test_developer_read_only_access(self):
        perms = ROLE_PERMISSIONS[RBACRole.DEVELOPER]
        assert RBACPermission.READ_FINDINGS in perms
        assert RBACPermission.WRITE_FINDINGS not in perms

    def test_sre_pipeline_access(self):
        perms = ROLE_PERMISSIONS[RBACRole.SRE]
        assert RBACPermission.READ_PIPELINE in perms
        assert RBACPermission.RUN_PIPELINE in perms
        assert RBACPermission.WRITE_FINDINGS not in perms

    def test_viewer_no_audit_log_access(self):
        perms = ROLE_PERMISSIONS[RBACRole.VIEWER]
        assert RBACPermission.READ_AUDIT_LOG not in perms


# ===========================================================================
# RBAC — get_current_user_role
# ===========================================================================

class TestGetCurrentUserRole:
    def test_extracts_admin_role(self):
        req = _make_request("admin")
        assert get_current_user_role(req) == RBACRole.ADMIN

    def test_extracts_viewer_role(self):
        req = _make_request("viewer")
        assert get_current_user_role(req) == RBACRole.VIEWER

    def test_extracts_security_analyst_role(self):
        req = _make_request("security_analyst")
        assert get_current_user_role(req) == RBACRole.SECURITY_ANALYST

    def test_unknown_role_defaults_to_viewer(self):
        req = _make_request("unknown_role_xyz")
        assert get_current_user_role(req) == RBACRole.VIEWER

    def test_super_admin_maps_to_admin(self):
        req = _make_request("super_admin")
        assert get_current_user_role(req) == RBACRole.ADMIN

    def test_analyst_alias_maps_to_security_analyst(self):
        req = _make_request("analyst")
        assert get_current_user_role(req) == RBACRole.SECURITY_ANALYST

    def test_no_auth_defaults_to_viewer(self):
        req = MagicMock()
        req.state.auth = None
        req.state.user_role = "viewer"
        assert get_current_user_role(req) == RBACRole.VIEWER


# ===========================================================================
# RBAC — require_permission (async dependency via asyncio)
# ===========================================================================

class TestRequirePermission:
    def _run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def test_admin_passes_any_permission(self):
        dep = require_permission(RBACPermission.DELETE_FINDINGS)
        req = _make_request("admin")
        result = self._run(dep(req))
        assert result == RBACRole.ADMIN

    def test_viewer_denied_write_findings(self):
        from fastapi import HTTPException
        dep = require_permission(RBACPermission.WRITE_FINDINGS)
        req = _make_request("viewer")
        with pytest.raises(HTTPException) as exc_info:
            self._run(dep(req))
        assert exc_info.value.status_code == 403

    def test_security_analyst_allowed_run_pipeline(self):
        dep = require_permission(RBACPermission.RUN_PIPELINE)
        req = _make_request("security_analyst")
        result = self._run(dep(req))
        assert result == RBACRole.SECURITY_ANALYST

    def test_developer_denied_manage_users(self):
        from fastapi import HTTPException
        dep = require_permission(RBACPermission.MANAGE_USERS)
        req = _make_request("developer")
        with pytest.raises(HTTPException) as exc_info:
            self._run(dep(req))
        assert exc_info.value.status_code == 403

    def test_compliance_officer_allowed_audit_log(self):
        dep = require_permission(RBACPermission.READ_AUDIT_LOG)
        req = _make_request("compliance_officer")
        result = self._run(dep(req))
        assert result == RBACRole.COMPLIANCE_OFFICER


# ===========================================================================
# RBAC — require_role
# ===========================================================================

class TestRequireRole:
    def _run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def test_admin_passes_all_role_checks(self):
        for role in RBACRole:
            dep = require_role(role)
            req = _make_request("admin")
            result = self._run(dep(req))
            assert result == RBACRole.ADMIN

    def test_viewer_fails_security_analyst_requirement(self):
        from fastapi import HTTPException
        dep = require_role(RBACRole.SECURITY_ANALYST)
        req = _make_request("viewer")
        with pytest.raises(HTTPException) as exc_info:
            self._run(dep(req))
        assert exc_info.value.status_code == 403

    def test_viewer_passes_viewer_requirement(self):
        dep = require_role(RBACRole.VIEWER)
        req = _make_request("viewer")
        result = self._run(dep(req))
        assert result == RBACRole.VIEWER

    def test_sre_fails_admin_requirement(self):
        from fastapi import HTTPException
        dep = require_role(RBACRole.ADMIN)
        req = _make_request("sre")
        with pytest.raises(HTTPException) as exc_info:
            self._run(dep(req))
        assert exc_info.value.status_code == 403


# ===========================================================================
# AuditAction enum
# ===========================================================================

class TestAuditActionEnum:
    def test_all_required_actions_exist(self):
        values = {a.value for a in AuditAction}
        assert values == {"create", "update", "delete", "execute", "login", "logout", "export"}

    def test_action_values_are_strings(self):
        for a in AuditAction:
            assert isinstance(a.value, str)


# ===========================================================================
# AuditEntry model
# ===========================================================================

class TestAuditEntry:
    def test_required_fields(self):
        entry = AuditEntry(
            user_email="alice@example.com",
            user_role="admin",
            action=AuditAction.CREATE,
            resource_type="finding",
            resource_id="f-001",
        )
        assert entry.user_email == "alice@example.com"
        assert entry.action == "create"  # use_enum_values=True
        assert entry.resource_type == "finding"
        assert entry.resource_id == "f-001"

    def test_auto_generated_id_and_timestamp(self):
        entry = AuditEntry(
            user_email="bob@example.com",
            user_role="viewer",
            action=AuditAction.LOGIN,
            resource_type="session",
            resource_id="s-1",
        )
        assert entry.id
        assert isinstance(entry.timestamp, datetime)

    def test_details_defaults_to_empty_dict(self):
        entry = AuditEntry(
            user_email="x@y.com",
            user_role="viewer",
            action=AuditAction.EXPORT,
            resource_type="report",
            resource_id="r-1",
        )
        assert entry.details == {}

    def test_correlation_id_auto_generated(self):
        entry = AuditEntry(
            user_email="x@y.com",
            user_role="viewer",
            action=AuditAction.DELETE,
            resource_type="finding",
            resource_id="f-2",
        )
        assert entry.correlation_id


# ===========================================================================
# AuditLogger — core operations
# ===========================================================================

class TestAuditLogger:
    def setup_method(self):
        AuditLogger.reset_instance()
        self.logger = AuditLogger(db_path=":memory:")

    def test_log_returns_audit_entry(self):
        entry = self.logger.log(
            action=AuditAction.CREATE,
            resource_type="finding",
            resource_id="f-001",
            user_email="alice@example.com",
            user_role="admin",
        )
        assert isinstance(entry, AuditEntry)
        assert entry.action == "create"

    def test_logged_entry_is_queryable(self):
        self.logger.log(
            action=AuditAction.UPDATE,
            resource_type="policy",
            resource_id="p-1",
            user_email="bob@example.com",
            user_role="compliance_officer",
        )
        results = self.logger.query()
        assert len(results) == 1
        assert results[0].resource_id == "p-1"

    def test_query_filter_by_action(self):
        self.logger.log(AuditAction.CREATE, "finding", "f-1", user_email="a@b.com", user_role="admin")
        self.logger.log(AuditAction.DELETE, "finding", "f-2", user_email="a@b.com", user_role="admin")
        results = self.logger.query(filters={"action": "create"})
        assert len(results) == 1
        assert results[0].resource_id == "f-1"

    def test_query_filter_by_resource_type(self):
        self.logger.log(AuditAction.CREATE, "finding", "f-1", user_email="a@b.com", user_role="admin")
        self.logger.log(AuditAction.CREATE, "policy", "p-1", user_email="a@b.com", user_role="admin")
        results = self.logger.query(filters={"resource_type": "policy"})
        assert len(results) == 1
        assert results[0].resource_id == "p-1"

    def test_query_limit_and_offset(self):
        for i in range(5):
            self.logger.log(AuditAction.CREATE, "finding", f"f-{i}", user_email="u@e.com", user_role="admin")
        page1 = self.logger.query(limit=2, offset=0)
        page2 = self.logger.query(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert {e.resource_id for e in page1}.isdisjoint({e.resource_id for e in page2})

    def test_log_with_user_object(self):
        user = MagicMock()
        user.email = "carol@example.com"
        user.role = "security_analyst"
        entry = self.logger.log(
            action=AuditAction.EXECUTE,
            resource_type="pipeline",
            resource_id="pipeline-1",
            user=user,
        )
        assert entry.user_email == "carol@example.com"
        assert entry.user_role == "security_analyst"

    def test_log_with_details(self):
        entry = self.logger.log(
            action=AuditAction.DELETE,
            resource_type="finding",
            resource_id="f-99",
            user_email="admin@example.com",
            user_role="admin",
            details={"reason": "false_positive", "severity": "low"},
        )
        assert entry.details["reason"] == "false_positive"

    def test_log_with_ip_address(self):
        entry = self.logger.log(
            action=AuditAction.LOGIN,
            resource_type="session",
            resource_id="s-1",
            user_email="u@e.com",
            user_role="viewer",
            ip_address="10.0.0.1",
        )
        assert entry.ip_address == "10.0.0.1"

    def test_count_matches_entries(self):
        for i in range(3):
            self.logger.log(AuditAction.CREATE, "r", str(i), user_email="u@e.com", user_role="admin")
        assert self.logger.count() == 3


# ===========================================================================
# AuditLogger — get_user_activity
# ===========================================================================

class TestAuditLoggerUserActivity:
    def setup_method(self):
        AuditLogger.reset_instance()
        self.logger = AuditLogger(db_path=":memory:")

    def test_returns_entries_for_user(self):
        self.logger.log(AuditAction.CREATE, "finding", "f-1", user_email="alice@example.com", user_role="admin")
        self.logger.log(AuditAction.UPDATE, "finding", "f-2", user_email="bob@example.com", user_role="viewer")
        activity = self.logger.get_user_activity("alice@example.com")
        assert len(activity) == 1
        assert activity[0].user_email == "alice@example.com"

    def test_empty_for_unknown_user(self):
        self.logger.log(AuditAction.CREATE, "finding", "f-1", user_email="alice@example.com", user_role="admin")
        activity = self.logger.get_user_activity("nobody@example.com")
        assert activity == []

    def test_returns_list_of_audit_entries(self):
        self.logger.log(AuditAction.LOGIN, "session", "s-1", user_email="u@e.com", user_role="viewer")
        activity = self.logger.get_user_activity("u@e.com")
        assert all(isinstance(e, AuditEntry) for e in activity)


# ===========================================================================
# AuditLogger — get_resource_history
# ===========================================================================

class TestAuditLoggerResourceHistory:
    def setup_method(self):
        AuditLogger.reset_instance()
        self.logger = AuditLogger(db_path=":memory:")

    def test_returns_history_for_resource(self):
        self.logger.log(AuditAction.CREATE, "finding", "f-42", user_email="u@e.com", user_role="admin")
        self.logger.log(AuditAction.UPDATE, "finding", "f-42", user_email="u@e.com", user_role="admin")
        self.logger.log(AuditAction.CREATE, "finding", "f-99", user_email="u@e.com", user_role="admin")
        history = self.logger.get_resource_history("finding", "f-42")
        assert len(history) == 2
        assert all(e.resource_id == "f-42" for e in history)

    def test_empty_for_unknown_resource(self):
        history = self.logger.get_resource_history("finding", "nonexistent")
        assert history == []

    def test_returns_list_of_audit_entries(self):
        self.logger.log(AuditAction.DELETE, "policy", "p-1", user_email="u@e.com", user_role="admin")
        history = self.logger.get_resource_history("policy", "p-1")
        assert all(isinstance(e, AuditEntry) for e in history)


# ===========================================================================
# AuditLogger — export_csv
# ===========================================================================

class TestAuditLoggerExportCSV:
    def setup_method(self):
        AuditLogger.reset_instance()
        self.logger = AuditLogger(db_path=":memory:")

    def test_export_produces_csv_string(self):
        self.logger.log(AuditAction.CREATE, "finding", "f-1", user_email="a@b.com", user_role="admin")
        csv_output = self.logger.export_csv()
        assert isinstance(csv_output, str)
        assert "user_email" in csv_output  # header present

    def test_export_empty_when_no_entries(self):
        csv_output = self.logger.export_csv()
        assert csv_output == ""

    def test_export_with_filter(self):
        self.logger.log(AuditAction.CREATE, "finding", "f-1", user_email="a@b.com", user_role="admin")
        self.logger.log(AuditAction.DELETE, "policy", "p-1", user_email="a@b.com", user_role="admin")
        csv_output = self.logger.export_csv(filters={"resource_type": "finding"})
        assert "finding" in csv_output
        assert "policy" not in csv_output

    def test_export_contains_all_rows(self):
        import csv as _csv
        import io
        for i in range(3):
            self.logger.log(AuditAction.UPDATE, "connector", f"c-{i}", user_email="u@e.com", user_role="sre")
        csv_output = self.logger.export_csv()
        reader = _csv.DictReader(io.StringIO(csv_output))
        rows = list(reader)
        assert len(rows) == 3


# ===========================================================================
# Integration — write request triggers audit entry via AuditMiddleware
# ===========================================================================

class TestAuditMiddlewareIntegration:
    def setup_method(self):
        AuditLogger.reset_instance()
        self.audit = AuditLogger(db_path=":memory:")

    def test_middleware_logs_post_request(self):
        """AuditMiddleware.dispatch() should create a log entry for POST."""
        import asyncio

        async def _fake_handler(request):
            resp = MagicMock()
            resp.status_code = 201
            return resp

        middleware = AuditMiddleware(app=MagicMock(), audit_logger=self.audit)

        req = MagicMock()
        req.method = "POST"
        req.url.path = "/api/v1/findings"
        req.client.host = "192.168.1.1"
        req.headers = {}
        auth = MagicMock()
        auth.email = "creator@example.com"
        auth.role = "security_analyst"
        req.state.auth = auth

        asyncio.run(middleware.dispatch(req, _fake_handler))

        entries = self.audit.query()
        assert len(entries) == 1
        assert entries[0].action == "create"
        assert entries[0].user_email == "creator@example.com"

    def test_middleware_logs_delete_request(self):
        import asyncio

        async def _fake_handler(request):
            resp = MagicMock()
            resp.status_code = 204
            return resp

        middleware = AuditMiddleware(app=MagicMock(), audit_logger=self.audit)

        req = MagicMock()
        req.method = "DELETE"
        req.url.path = "/api/v1/findings/f-99"
        req.client.host = "10.0.0.1"
        req.headers = {}
        auth = MagicMock()
        auth.email = "admin@example.com"
        auth.role = "admin"
        req.state.auth = auth

        asyncio.run(middleware.dispatch(req, _fake_handler))

        entries = self.audit.query(filters={"action": "delete"})
        assert len(entries) == 1

    def test_middleware_skips_health_endpoint(self):
        import asyncio

        async def _fake_handler(request):
            resp = MagicMock()
            resp.status_code = 200
            return resp

        middleware = AuditMiddleware(app=MagicMock(), audit_logger=self.audit)

        req = MagicMock()
        req.method = "POST"
        req.url.path = "/health"
        req.client.host = "127.0.0.1"
        req.headers = {}
        req.state.auth = None

        asyncio.run(middleware.dispatch(req, _fake_handler))

        entries = self.audit.query()
        assert len(entries) == 0

    def test_middleware_skips_get_requests(self):
        import asyncio

        async def _fake_handler(request):
            resp = MagicMock()
            resp.status_code = 200
            return resp

        middleware = AuditMiddleware(app=MagicMock(), audit_logger=self.audit)

        req = MagicMock()
        req.method = "GET"
        req.url.path = "/api/v1/findings"
        req.client.host = "127.0.0.1"
        req.headers = {}
        req.state.auth = None

        asyncio.run(middleware.dispatch(req, _fake_handler))

        entries = self.audit.query()
        assert len(entries) == 0
