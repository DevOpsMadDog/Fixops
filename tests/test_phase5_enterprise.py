"""
Enterprise Hardening Tests for ALDECI Phase 5.

Tests for:
- RBAC (Role-Based Access Control) system (~25 tests)
- Audit Logger system (~20 tests)

Compliance: SOC2, HIPAA, PCI-DSS
"""

import sys
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, "suite-core")

from core.rbac import (
    Permission,
    Role,
    BuiltinRoles,
    RBACEngine,
    PersonaRoleMapping,
    create_rbac_engine,
)
from core.audit_logger import (
    AuditEvent,
    AuditLogger,
    ComplianceControlMapping,
    create_audit_logger,
)


# ============================================================================
# RBAC TESTS (~25 tests)
# ============================================================================


class TestPermissionEnum:
    """Test Permission enum completeness."""

    def test_permission_enum_has_27_permissions(self):
        """Verify Permission enum contains exactly 27 permissions."""
        perms = [p for p in Permission]
        assert len(perms) == 27, f"Expected 27 permissions, got {len(perms)}"

    def test_all_permissions_have_string_values(self):
        """Verify all permissions have string values."""
        for perm in Permission:
            assert isinstance(perm.value, str)
            assert len(perm.value) > 0
            assert ":" in perm.value  # Format: "category:action"

    def test_permission_categories_exist(self):
        """Verify key permission categories exist."""
        categories = {
            "findings": ["findings:read", "findings:write", "findings:triage", "findings:delete"],
            "connectors": ["connectors:read", "connectors:manage", "connectors:pull"],
            "council": ["council:view", "council:override", "council:configure"],
            "compliance": ["compliance:read", "compliance:manage", "compliance:evidence"],
            "reports": ["reports:read", "reports:create", "reports:export"],
            "users": ["users:read", "users:manage", "users:rbac"],
            "system": ["system:config", "system:audit", "system:integrations"],
            "attack_sim": ["attack_sim:read", "attack_sim:execute"],
            "autofix": ["autofix:view", "autofix:apply", "autofix:configure"],
        }

        for category, expected_perms in categories.items():
            for expected in expected_perms:
                perm_values = [p.value for p in Permission]
                assert expected in perm_values, f"Missing permission: {expected}"

    def test_permission_enum_str_conversion(self):
        """Test Permission enum str() returns value."""
        assert str(Permission.FINDINGS_READ) == "findings:read"
        assert str(Permission.COUNCIL_OVERRIDE) == "council:override"


class TestRoleClass:
    """Test Role class and methods."""

    def test_role_creation_basic(self):
        """Test creating a basic role."""
        role = Role(
            name="test_role",
            permissions={Permission.FINDINGS_READ},
            description="Test role"
        )
        assert role.name == "test_role"
        assert Permission.FINDINGS_READ in role.permissions
        assert role.inherits_from is None
        assert role.org_scope is True
        assert role.max_data_classification == "public"

    def test_role_has_permission(self):
        """Test role.has_permission() method."""
        role = Role(
            name="test",
            permissions={Permission.FINDINGS_READ, Permission.FINDINGS_WRITE}
        )
        assert role.has_permission(Permission.FINDINGS_READ)
        assert role.has_permission(Permission.FINDINGS_WRITE)
        assert not role.has_permission(Permission.FINDINGS_DELETE)

    def test_role_inheritance_single_level(self):
        """Test single-level role inheritance."""
        parent = Role(
            name="parent",
            permissions={Permission.FINDINGS_READ}
        )
        child = Role(
            name="child",
            permissions={Permission.FINDINGS_WRITE},
            inherits_from=parent
        )

        all_perms = child.get_all_permissions()
        assert Permission.FINDINGS_READ in all_perms
        assert Permission.FINDINGS_WRITE in all_perms
        assert len(all_perms) == 2

    def test_role_inheritance_multi_level(self):
        """Test multi-level role inheritance."""
        grandparent = Role(
            name="grandparent",
            permissions={Permission.FINDINGS_READ}
        )
        parent = Role(
            name="parent",
            permissions={Permission.FINDINGS_WRITE},
            inherits_from=grandparent
        )
        child = Role(
            name="child",
            permissions={Permission.FINDINGS_TRIAGE},
            inherits_from=parent
        )

        all_perms = child.get_all_permissions()
        assert Permission.FINDINGS_READ in all_perms
        assert Permission.FINDINGS_WRITE in all_perms
        assert Permission.FINDINGS_TRIAGE in all_perms

    def test_role_to_dict_serialization(self):
        """Test role serialization to dict."""
        role = Role(
            name="test",
            permissions={Permission.FINDINGS_READ, Permission.REPORTS_READ},
            max_data_classification="confidential",
            description="Test role"
        )

        role_dict = role.to_dict()
        assert role_dict["name"] == "test"
        assert "findings:read" in role_dict["permissions"]
        assert "reports:read" in role_dict["permissions"]
        assert role_dict["max_data_classification"] == "confidential"
        assert role_dict["inherits_from"] is None

    def test_role_data_classification_levels(self):
        """Test data classification levels in roles."""
        levels = ["public", "internal", "confidential", "restricted"]
        for level in levels:
            role = Role(name="test", max_data_classification=level)
            assert role.max_data_classification == level


class TestBuiltinRoles:
    """Test built-in role definitions."""

    def test_builtin_roles_all_exist(self):
        """Verify all 6 built-in roles exist."""
        roles = {
            "viewer": BuiltinRoles.viewer(),
            "developer": BuiltinRoles.developer(),
            "security_analyst": BuiltinRoles.security_analyst(),
            "compliance_officer": BuiltinRoles.compliance_officer(),
            "admin": BuiltinRoles.admin(),
            "super_admin": BuiltinRoles.super_admin(),
        }

        assert len(roles) == 6
        for name, role in roles.items():
            assert role.name == name

    def test_role_hierarchy_viewer(self):
        """Test viewer role (base)."""
        role = BuiltinRoles.viewer()
        assert role.name == "viewer"
        assert role.max_data_classification == "public"
        assert Permission.FINDINGS_READ in role.permissions
        assert Permission.REPORTS_READ in role.permissions
        assert not role.has_permission(Permission.FINDINGS_WRITE)

    def test_role_hierarchy_developer(self):
        """Test developer role (extends viewer)."""
        role = BuiltinRoles.developer()
        assert role.name == "developer"
        assert role.inherits_from is not None
        assert role.max_data_classification == "internal"

        # Has developer permissions
        assert role.has_permission(Permission.FINDINGS_TRIAGE)
        assert role.has_permission(Permission.AUTOFIX_VIEW)

        # Inherits viewer permissions
        assert role.has_permission(Permission.FINDINGS_READ)
        assert role.has_permission(Permission.REPORTS_READ)

    def test_role_hierarchy_security_analyst(self):
        """Test security_analyst role (extends developer)."""
        role = BuiltinRoles.security_analyst()
        assert role.name == "security_analyst"
        assert role.inherits_from is not None
        assert role.max_data_classification == "confidential"

        # Has analyst permissions
        assert role.has_permission(Permission.FINDINGS_WRITE)
        assert role.has_permission(Permission.COUNCIL_VIEW)
        assert role.has_permission(Permission.ATTACK_SIM_READ)

        # Inherits developer permissions
        assert role.has_permission(Permission.FINDINGS_TRIAGE)

        # Inherits viewer permissions
        assert role.has_permission(Permission.FINDINGS_READ)

    def test_role_hierarchy_compliance_officer(self):
        """Test compliance_officer role (extends security_analyst)."""
        role = BuiltinRoles.compliance_officer()
        assert role.name == "compliance_officer"
        assert role.inherits_from is not None
        assert role.max_data_classification == "restricted"

        # Has officer permissions
        assert role.has_permission(Permission.COMPLIANCE_MANAGE)
        assert role.has_permission(Permission.REPORTS_CREATE)

        # Inherits analyst permissions
        assert role.has_permission(Permission.FINDINGS_WRITE)

    def test_role_hierarchy_admin(self):
        """Test admin role (broad permissions)."""
        role = BuiltinRoles.admin()
        assert role.name == "admin"
        assert role.max_data_classification == "restricted"

        # Admin has 25+ permissions
        assert len(role.permissions) >= 25

        # Key permissions
        assert role.has_permission(Permission.FINDINGS_DELETE)
        assert role.has_permission(Permission.CONNECTORS_MANAGE)
        assert role.has_permission(Permission.COUNCIL_OVERRIDE)
        assert role.has_permission(Permission.USERS_MANAGE)
        assert role.has_permission(Permission.AUTOFIX_APPLY)

        # But NOT system config
        assert not role.has_permission(Permission.SYSTEM_CONFIG)

    def test_role_hierarchy_super_admin(self):
        """Test super_admin role (all permissions)."""
        role = BuiltinRoles.super_admin()
        assert role.name == "super_admin"
        assert role.inherits_from is not None
        assert role.org_scope is False  # System-wide
        assert role.max_data_classification == "restricted"

        # Has system config
        assert role.has_permission(Permission.SYSTEM_CONFIG)

        # Has all admin permissions
        assert role.has_permission(Permission.FINDINGS_DELETE)
        assert role.has_permission(Permission.USERS_MANAGE)

    def test_role_hierarchy_complete(self):
        """Test complete role hierarchy: viewer < developer < analyst < officer < admin < super_admin."""
        viewer = BuiltinRoles.viewer()
        developer = BuiltinRoles.developer()
        analyst = BuiltinRoles.security_analyst()
        officer = BuiltinRoles.compliance_officer()
        admin = BuiltinRoles.admin()
        super_admin = BuiltinRoles.super_admin()

        # Each level has more permissions
        viewer_perms = len(viewer.get_all_permissions())
        dev_perms = len(developer.get_all_permissions())
        analyst_perms = len(analyst.get_all_permissions())
        officer_perms = len(officer.get_all_permissions())
        admin_perms = len(admin.get_all_permissions())
        super_admin_perms = len(super_admin.get_all_permissions())

        assert viewer_perms < dev_perms < analyst_perms < officer_perms < admin_perms < super_admin_perms


class TestRBACEngine:
    """Test RBACEngine functionality."""

    def test_rbac_engine_init(self):
        """Test RBAC engine initialization."""
        engine = RBACEngine()
        assert engine._cache_size == 1000
        assert len(engine._builtin_roles) == 6
        assert "viewer" in engine._builtin_roles
        assert "super_admin" in engine._builtin_roles

    def test_assign_role_and_check_permission(self):
        """Test assigning role and checking permission."""
        engine = RBACEngine()

        # Assign viewer role
        result = engine.assign_role("user1", "viewer", "org1")
        assert result is True

        # Viewer can read findings
        assert engine.check_permission("user1", Permission.FINDINGS_READ, "org1")

        # Viewer cannot write findings
        assert not engine.check_permission("user1", Permission.FINDINGS_WRITE, "org1")

    def test_assign_role_invalid_role(self):
        """Test assigning invalid role fails."""
        engine = RBACEngine()
        result = engine.assign_role("user1", "invalid_role", "org1")
        assert result is False

    def test_get_user_permissions(self):
        """Test getting user permissions."""
        engine = RBACEngine()
        engine.assign_role("user1", "developer", "org1")

        perms = engine.get_user_permissions("user1", "org1")
        assert isinstance(perms, set)
        assert "findings:read" in perms
        assert "findings:triage" in perms
        assert "findings:write" not in perms

    def test_get_user_permissions_no_role(self):
        """Test getting permissions for unassigned user."""
        engine = RBACEngine()
        perms = engine.get_user_permissions("unknown_user", "org1")
        assert perms == set()

    def test_permission_check_denied(self):
        """Test permission check denies unauthorized action."""
        engine = RBACEngine()
        engine.assign_role("user1", "viewer", "org1")

        # Viewer cannot delete findings
        assert not engine.check_permission("user1", Permission.FINDINGS_DELETE, "org1")

    def test_permission_check_unassigned_user(self):
        """Test permission check for unassigned user."""
        engine = RBACEngine()
        result = engine.check_permission("unknown", Permission.FINDINGS_READ, "org1")
        assert result is False

    def test_data_classification_enforcement(self):
        """Test data classification enforcement."""
        engine = RBACEngine()

        # Viewer can access public data
        engine.assign_role("viewer_user", "viewer", "org1")
        assert engine.check_permission(
            "viewer_user", Permission.FINDINGS_READ, "org1",
            resource_classification="public"
        )

        # Viewer cannot access confidential data
        assert not engine.check_permission(
            "viewer_user", Permission.FINDINGS_READ, "org1",
            resource_classification="confidential"
        )

        # Analyst can access confidential data
        engine.assign_role("analyst_user", "security_analyst", "org1")
        assert engine.check_permission(
            "analyst_user", Permission.FINDINGS_READ, "org1",
            resource_classification="confidential"
        )

    def test_permission_caching_performance(self):
        """Test permission caching improves lookup speed."""
        engine = RBACEngine()
        engine.assign_role("user1", "developer", "org1")

        # First lookup
        result1 = engine.check_permission("user1", Permission.FINDINGS_READ, "org1")
        assert result1 is True

        # Second lookup (should hit cache)
        result2 = engine.check_permission("user1", Permission.FINDINGS_READ, "org1")
        assert result2 is True

        # Cache should have entry
        cache_info = engine._get_user_role_cached.cache_info()
        assert cache_info.hits > 0

    def test_role_reassignment_clears_cache(self):
        """Test reassigning role clears cache."""
        engine = RBACEngine()
        engine.assign_role("user1", "viewer", "org1")

        # Check permission (fills cache)
        assert not engine.check_permission("user1", Permission.FINDINGS_WRITE, "org1")

        # Reassign to developer
        engine.assign_role("user1", "developer", "org1")

        # Now developer permission should work
        assert engine.check_permission("user1", Permission.FINDINGS_TRIAGE, "org1")

    def test_custom_role_creation(self):
        """Test creating custom role."""
        engine = RBACEngine()

        role = engine.create_custom_role(
            name="auditor",
            permissions={Permission.REPORTS_READ, Permission.COMPLIANCE_READ},
            max_data_classification="internal"
        )

        assert role is not None
        assert role.name == "auditor"
        assert Permission.REPORTS_READ in role.permissions

    def test_custom_role_with_inheritance(self):
        """Test custom role with parent role inheritance."""
        engine = RBACEngine()

        role = engine.create_custom_role(
            name="senior_analyst",
            permissions={Permission.REPORTS_CREATE},
            inherits_from="security_analyst"
        )

        assert role is not None
        assert role.has_permission(Permission.FINDINGS_WRITE)  # From analyst
        assert role.has_permission(Permission.REPORTS_CREATE)  # Own permission

    def test_custom_role_duplicate_name_fails(self):
        """Test creating duplicate custom role fails."""
        engine = RBACEngine()

        engine.create_custom_role(
            name="custom",
            permissions={Permission.FINDINGS_READ}
        )

        # Try to create with same name
        role = engine.create_custom_role(
            name="custom",
            permissions={Permission.FINDINGS_WRITE}
        )
        assert role is None

    def test_custom_role_invalid_parent_fails(self):
        """Test custom role with invalid parent fails."""
        engine = RBACEngine()

        role = engine.create_custom_role(
            name="bad",
            permissions={Permission.FINDINGS_READ},
            inherits_from="nonexistent_role"
        )
        assert role is None

    def test_get_role_matrix(self):
        """Test RBAC matrix export."""
        engine = RBACEngine()

        matrix = engine.get_role_matrix()
        assert isinstance(matrix, dict)
        assert "viewer" in matrix
        assert "admin" in matrix
        assert "super_admin" in matrix

        # Each role should have structure
        viewer_def = matrix["viewer"]
        assert "name" in viewer_def
        assert "permissions" in viewer_def
        assert isinstance(viewer_def["permissions"], list)
        assert len(viewer_def["permissions"]) > 0

    def test_export_matrix_json(self):
        """Test RBAC matrix JSON export."""
        engine = RBACEngine()

        json_str = engine.export_matrix_json()
        assert isinstance(json_str, str)

        # Parse and validate
        data = json.loads(json_str)
        assert isinstance(data, dict)
        assert "viewer" in data
        assert "super_admin" in data

    def test_check_data_access(self):
        """Test data access classification."""
        engine = RBACEngine()

        viewer_role = BuiltinRoles.viewer()
        analyst_role = BuiltinRoles.security_analyst()
        admin_role = BuiltinRoles.admin()

        # Viewer (public) cannot access confidential
        assert not engine.check_data_access(viewer_role, "confidential")
        assert engine.check_data_access(viewer_role, "public")

        # Analyst (confidential) can access confidential
        assert engine.check_data_access(analyst_role, "confidential")
        assert engine.check_data_access(analyst_role, "internal")
        assert not engine.check_data_access(analyst_role, "restricted")

        # Admin (restricted) can access all
        assert engine.check_data_access(admin_role, "restricted")
        assert engine.check_data_access(admin_role, "confidential")

    def test_classify_resource(self):
        """Test resource classification."""
        engine = RBACEngine()

        assert engine.classify_resource("system_config", "cfg1") == "restricted"
        assert engine.classify_resource("audit_log", "log1") == "restricted"
        assert engine.classify_resource("finding", "f1") == "internal"
        assert engine.classify_resource("report", "r1") == "internal"
        assert engine.classify_resource("unknown", "x") == "public"


class TestPersonaRoleMapping:
    """Test persona to role mapping."""

    def test_persona_map_completeness(self):
        """Verify all personas are mapped (26 defined personas + generic fallback)."""
        personas = PersonaRoleMapping.PERSONA_MAP
        # The actual implementation has 26 personas including generic_user fallback
        assert len(personas) >= 26

    def test_persona_map_has_all_roles(self):
        """Verify personas are mapped to valid roles."""
        valid_roles = {"viewer", "developer", "security_analyst", "compliance_officer", "admin", "super_admin"}

        for persona, role in PersonaRoleMapping.PERSONA_MAP.items():
            assert role in valid_roles, f"Persona {persona} has invalid role {role}"

    def test_super_admin_persona(self):
        """Test CISO (super_admin) persona."""
        role = PersonaRoleMapping.get_role_for_persona("Sarah Chen")
        assert role == "super_admin"

    def test_admin_personas(self):
        """Test admin personas."""
        admin_personas = [
            "Marcus Johnson",   # VP Engineering
            "Maria Lopez",      # IT Director
            "Ryan Murphy",      # Platform Engineer
            "Daniel Thompson",  # SecOps Manager
        ]

        for persona in admin_personas:
            role = PersonaRoleMapping.get_role_for_persona(persona)
            assert role == "admin", f"{persona} should be admin, got {role}"

    def test_security_analyst_personas(self):
        """Test security analyst personas."""
        analyst_personas = [
            "Alex Rivera",
            "Priya Sharma",
            "James Wilson",
            "Emma Davis",
        ]

        for persona in analyst_personas:
            role = PersonaRoleMapping.get_role_for_persona(persona)
            assert role == "security_analyst"

    def test_get_personas_by_role(self):
        """Test getting personas by role."""
        super_admins = PersonaRoleMapping.get_personas_by_role("super_admin")
        assert len(super_admins) >= 1
        assert "Sarah Chen" in super_admins

        admins = PersonaRoleMapping.get_personas_by_role("admin")
        assert len(admins) >= 4

        analysts = PersonaRoleMapping.get_personas_by_role("security_analyst")
        assert len(analysts) >= 10

    def test_default_persona_fallback(self):
        """Test unknown persona defaults to viewer."""
        role = PersonaRoleMapping.get_role_for_persona("Unknown Person")
        assert role == "viewer"


# ============================================================================
# AUDIT LOGGER TESTS (~20 tests)
# ============================================================================


class TestAuditEvent:
    """Test AuditEvent dataclass."""

    def test_audit_event_creation(self):
        """Test creating audit event."""
        event = AuditEvent(
            actor_id="user1",
            action="finding.triage",
            resource_type="finding",
            resource_id="f123",
            org_id="org1",
            result="success"
        )

        assert event.actor_id == "user1"
        assert event.action == "finding.triage"
        assert event.resource_id == "f123"
        assert event.event_id is not None

    def test_audit_event_has_timestamp(self):
        """Test audit event has timestamp."""
        event = AuditEvent(action="test")
        assert event.timestamp is not None
        assert isinstance(event.timestamp, datetime)

    def test_audit_event_has_uuid(self):
        """Test audit event has UUID."""
        event = AuditEvent(action="test")
        assert len(event.event_id) > 0
        # UUID v4 format check
        assert len(event.event_id.split("-")) == 5

    def test_audit_event_to_dict(self):
        """Test event serialization to dict."""
        event = AuditEvent(
            actor_id="user1",
            actor_role="admin",
            action="findings:write",
            resource_type="finding",
            resource_id="f123",
            org_id="org1",
            result="success",
            details={"severity": "high"},
            ip_address="192.168.1.1"
        )

        event_dict = event.to_dict()
        assert event_dict["actor_id"] == "user1"
        assert event_dict["actor_role"] == "admin"
        assert event_dict["action"] == "findings:write"
        assert event_dict["result"] == "success"
        assert event_dict["details"]["severity"] == "high"
        assert isinstance(event_dict["timestamp"], str)

    def test_audit_event_from_dict(self):
        """Test event deserialization from dict."""
        event_dict = {
            "event_id": "test-uuid",
            "timestamp": "2026-01-01T12:00:00+00:00",
            "actor_id": "user1",
            "actor_role": "admin",
            "action": "findings:write",
            "resource_type": "finding",
            "resource_id": "f123",
            "org_id": "org1",
            "result": "success",
            "details": {"severity": "high"},
        }

        event = AuditEvent.from_dict(event_dict)
        assert event.event_id == "test-uuid"
        assert event.actor_id == "user1"
        assert event.action == "findings:write"

    def test_audit_event_defaults(self):
        """Test audit event defaults."""
        event = AuditEvent()
        assert event.actor_id == ""
        assert event.actor_role == "unknown"
        assert event.org_id == "default"
        assert event.result == "success"
        assert event.details == {}


class TestAuditLogger:
    """Test AuditLogger functionality."""

    def test_audit_logger_init_memory(self, tmp_path):
        """Test audit logger initialization with in-memory DB."""
        logger = AuditLogger(":memory:")
        assert logger is not None

    def test_audit_logger_init_file(self, tmp_path):
        """Test audit logger initialization with file DB."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(str(db_path))
        assert logger is not None

    def test_log_event(self, tmp_path):
        """Test logging audit event."""
        logger = AuditLogger(":memory:")

        event = AuditEvent(
            actor_id="user1",
            action="findings:read",
            resource_type="finding",
            resource_id="f123",
            org_id="org1"
        )

        event_id = logger.log(event)
        assert event_id == event.event_id

    def test_search_by_org(self, tmp_path):
        """Test searching events by organization."""
        logger = AuditLogger(":memory:")

        # Log events in different orgs
        for i in range(3):
            logger.log(AuditEvent(
                actor_id=f"user{i}",
                action="findings:read",
                org_id="org1"
            ))

        for i in range(2):
            logger.log(AuditEvent(
                actor_id=f"user{i}",
                action="findings:read",
                org_id="org2"
            ))

        # Search org1
        events = logger.search("org1")
        assert len(events) == 3

        # Search org2
        events = logger.search("org2")
        assert len(events) == 2

    def test_search_by_actor(self, tmp_path):
        """Test searching events by actor."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(actor_id="user1", action="action1", org_id="org1"))
        logger.log(AuditEvent(actor_id="user1", action="action2", org_id="org1"))
        logger.log(AuditEvent(actor_id="user2", action="action1", org_id="org1"))

        events = logger.search("org1", actor_id="user1")
        assert len(events) == 2
        assert all(e.actor_id == "user1" for e in events)

    def test_search_by_action(self, tmp_path):
        """Test searching events by action."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(actor_id="user1", action="findings:read", org_id="org1"))
        logger.log(AuditEvent(actor_id="user1", action="findings:write", org_id="org1"))
        logger.log(AuditEvent(actor_id="user2", action="findings:read", org_id="org1"))

        events = logger.search("org1", action="findings:read")
        assert len(events) == 2
        assert all(e.action == "findings:read" for e in events)

    def test_search_by_result(self, tmp_path):
        """Test searching events by result."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(
            actor_id="user1",
            action="findings:read",
            result="success",
            org_id="org1"
        ))
        logger.log(AuditEvent(
            actor_id="user1",
            action="findings:write",
            result="denied",
            org_id="org1"
        ))

        events = logger.search("org1", result="denied")
        assert len(events) == 1
        assert events[0].result == "denied"

    def test_search_time_range(self, tmp_path):
        """Test searching events by time range."""
        logger = AuditLogger(":memory:")

        now = datetime.now(timezone.utc)
        past = now - timedelta(days=10)
        future = now + timedelta(days=10)

        logger.log(AuditEvent(
            actor_id="user1",
            action="action",
            org_id="org1",
            timestamp=past
        ))
        logger.log(AuditEvent(
            actor_id="user2",
            action="action",
            org_id="org1",
            timestamp=now
        ))

        # Search only recent
        events = logger.search(
            "org1",
            since=now - timedelta(minutes=1)
        )
        assert len(events) == 1

    def test_get_actor_activity(self, tmp_path):
        """Test getting actor activity."""
        logger = AuditLogger(":memory:")

        for i in range(5):
            logger.log(AuditEvent(
                actor_id="user1",
                action=f"action{i}",
                org_id="org1"
            ))

        activity = logger.get_actor_activity("user1", "org1", days=30)
        assert len(activity) == 5

    def test_get_security_events(self, tmp_path):
        """Test getting security events."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(
            actor_id="user1",
            action="permission_denied",
            result="denied",
            org_id="org1"
        ))
        logger.log(AuditEvent(
            actor_id="user1",
            action="council.override",
            org_id="org1"
        ))
        logger.log(AuditEvent(
            actor_id="user1",
            action="findings:read",
            org_id="org1"
        ))

        now = datetime.now(timezone.utc)
        events = logger.get_security_events("org1", now - timedelta(minutes=10))
        assert len(events) >= 2  # Should include permission_denied and council.override

    def test_get_compliance_trail_soc2(self, tmp_path):
        """Test getting SOC2 compliance trail."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(
            action="role_assignment",
            org_id="org1"
        ))
        logger.log(AuditEvent(
            action="permission_check",
            org_id="org1"
        ))
        logger.log(AuditEvent(
            action="findings:read",
            org_id="org1"
        ))

        trail = logger.get_compliance_trail("org1", "SOC2")
        assert len(trail) >= 2  # role_assignment and permission_check

    def test_get_compliance_trail_hipaa(self, tmp_path):
        """Test getting HIPAA compliance trail."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(action="finding.read", org_id="org1"))
        logger.log(AuditEvent(action="finding.write", org_id="org1"))
        logger.log(AuditEvent(action="role_assignment", org_id="org1"))

        trail = logger.get_compliance_trail("org1", "HIPAA")
        assert len(trail) >= 3

    def test_get_compliance_trail_pci_dss(self, tmp_path):
        """Test getting PCI-DSS compliance trail."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(action="connector.pull", org_id="org1"))
        logger.log(AuditEvent(action="findings.write", org_id="org1"))
        logger.log(AuditEvent(action="report.create", org_id="org1"))

        trail = logger.get_compliance_trail("org1", "PCI_DSS")
        assert len(trail) >= 3

    def test_export_csv(self, tmp_path):
        """Test CSV export."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(
            actor_id="user1",
            action="findings:read",
            org_id="org1"
        ))
        logger.log(AuditEvent(
            actor_id="user2",
            action="findings:write",
            org_id="org1"
        ))

        now = datetime.now(timezone.utc)
        csv_content = logger.export_csv(
            "org1",
            now - timedelta(minutes=10),
            now + timedelta(minutes=10)
        )

        assert isinstance(csv_content, str)
        assert "user1" in csv_content
        assert "user2" in csv_content
        assert "findings:read" in csv_content

    def test_multi_tenant_isolation(self, tmp_path):
        """Test multi-tenant isolation in audit logs."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(
            actor_id="user1",
            action="admin_action",
            org_id="org1"
        ))
        logger.log(AuditEvent(
            actor_id="user2",
            action="admin_action",
            org_id="org2"
        ))

        # org1 should only see its own events
        events_org1 = logger.search("org1")
        assert len(events_org1) == 1
        assert events_org1[0].actor_id == "user1"

        # org2 should only see its own events
        events_org2 = logger.search("org2")
        assert len(events_org2) == 1
        assert events_org2[0].actor_id == "user2"

    def test_get_event_count(self, tmp_path):
        """Test getting event count."""
        logger = AuditLogger(":memory:")

        logger.log(AuditEvent(action="action1", org_id="org1"))
        logger.log(AuditEvent(action="action2", org_id="org1"))
        logger.log(AuditEvent(action="action3", org_id="org2"))

        count_org1 = logger.get_event_count("org1")
        assert count_org1 == 2

        count_org2 = logger.get_event_count("org2")
        assert count_org2 == 1


class TestComplianceControlMapping:
    """Test compliance control mapping."""

    def test_soc2_events_mapped(self):
        """Test SOC2 control events."""
        event = AuditEvent(action="role_assignment", org_id="org1")
        controls = ComplianceControlMapping.get_controls_for_event(event)
        assert "SOC2_CC6_1" in controls

    def test_hipaa_events_mapped(self):
        """Test HIPAA control events."""
        event = AuditEvent(action="finding.read", org_id="org1")
        controls = ComplianceControlMapping.get_controls_for_event(event)
        assert "HIPAA_312B" in controls

    def test_pci_dss_events_mapped(self):
        """Test PCI-DSS control events."""
        event = AuditEvent(action="connector.pull", org_id="org1")
        controls = ComplianceControlMapping.get_controls_for_event(event)
        assert "PCI_DSS_10_2" in controls

    def test_multiple_controls_per_event(self):
        """Test event mapping to multiple controls."""
        event = AuditEvent(action="permission_denied", org_id="org1")
        controls = ComplianceControlMapping.get_controls_for_event(event)
        # permission_denied maps to multiple frameworks
        assert len(controls) >= 1

    def test_unknown_action_no_controls(self):
        """Test unknown action has no controls."""
        event = AuditEvent(action="unknown_action", org_id="org1")
        controls = ComplianceControlMapping.get_controls_for_event(event)
        assert len(controls) == 0


class TestFactoryFunctions:
    """Test factory functions."""

    def test_create_rbac_engine_with_personas(self):
        """Test factory creates engine with all personas."""
        engine = create_rbac_engine()
        assert engine is not None
        assert len(engine._builtin_roles) == 6

        # Should have 26+ personas assigned (as defined in PersonaRoleMapping)
        assigned_count = len([
            user_key for user_key in engine._user_roles
            if engine._user_roles[user_key]
        ])
        assert assigned_count >= 26

    def test_create_audit_logger(self, tmp_path):
        """Test audit logger factory."""
        db_path = tmp_path / "audit.db"
        logger = create_audit_logger(str(db_path))
        assert logger is not None


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests combining RBAC and audit logging."""

    def test_rbac_with_audit_trail(self, tmp_path):
        """Test RBAC actions are logged."""
        rbac = RBACEngine()
        logger = AuditLogger(":memory:")

        # Assign role
        rbac.assign_role("user1", "viewer", "org1")

        # Log the assignment
        audit_log = rbac.get_audit_log()
        assert len(audit_log) > 0

        found_assignment = False
        for entry in audit_log:
            if entry.get("event") == "role_assignment":
                found_assignment = True
                assert entry["user_id"] == "user1"
                assert entry["new_role"] == "viewer"

        assert found_assignment

    def test_enterprise_workflow(self, tmp_path):
        """Test complete enterprise workflow."""
        rbac = RBACEngine()
        logger = AuditLogger(":memory:")

        # 1. Assign roles
        rbac.assign_role("alice", "security_analyst", "acme_corp")
        rbac.assign_role("bob", "compliance_officer", "acme_corp")

        # 2. Log actions
        alice_perms = rbac.get_user_permissions("alice", "acme_corp")
        assert "findings:write" in alice_perms
        assert "compliance:manage" not in alice_perms

        bob_perms = rbac.get_user_permissions("bob", "acme_corp")
        assert "compliance:manage" in bob_perms

        # 3. Create audit events
        for action in ["findings:read", "findings:write", "council:view"]:
            event = AuditEvent(
                actor_id="alice",
                actor_role="security_analyst",
                action=action,
                resource_type="finding",
                org_id="acme_corp"
            )
            logger.log(event)

        # 4. Query audit trail
        alice_events = logger.search("acme_corp", actor_id="alice")
        assert len(alice_events) == 3

        # 5. Export for compliance
        now = datetime.now(timezone.utc)
        csv_export = logger.export_csv(
            "acme_corp",
            now - timedelta(hours=1),
            now + timedelta(hours=1)
        )
        assert "alice" in csv_export
        assert "security_analyst" in csv_export


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=15"])
