"""
Enterprise RBAC (Role-Based Access Control) Matrix for ALDECI Phase 5.

This module provides a comprehensive role-based access control system with:
- Fine-grained permission model
- Role hierarchy and inheritance
- Data classification enforcement
- Permission caching with LRU
- Persona-to-role mapping for all 30 enterprise personas

Compliance: SOC2 CC6.1 (Logical access controls)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set

_logger = logging.getLogger(__name__)


# ============================================================================
# PERMISSION ENUM
# ============================================================================

class Permission(Enum):
    """Granular permissions across ALDECI platform."""

    # ── Findings Management ──
    FINDINGS_READ = "findings:read"
    FINDINGS_WRITE = "findings:write"
    FINDINGS_TRIAGE = "findings:triage"
    FINDINGS_DELETE = "findings:delete"

    # ── Connectors (scanners, integrations) ──
    CONNECTORS_READ = "connectors:read"
    CONNECTORS_MANAGE = "connectors:manage"
    CONNECTORS_PULL = "connectors:pull"

    # ── Council (decision & override) ──
    COUNCIL_VIEW = "council:view"
    COUNCIL_OVERRIDE = "council:override"
    COUNCIL_CONFIGURE = "council:configure"

    # ── Compliance & Evidence ──
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_MANAGE = "compliance:manage"
    COMPLIANCE_EVIDENCE = "compliance:evidence"

    # ── Reports ──
    REPORTS_READ = "reports:read"
    REPORTS_CREATE = "reports:create"
    REPORTS_EXPORT = "reports:export"

    # ── User Management ──
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    USERS_RBAC = "users:rbac"

    # ── System Administration ──
    SYSTEM_CONFIG = "system:config"
    SYSTEM_AUDIT = "system:audit"
    SYSTEM_INTEGRATIONS = "system:integrations"

    # ── Attack Simulation ──
    ATTACK_SIM_READ = "attack_sim:read"
    ATTACK_SIM_EXECUTE = "attack_sim:execute"

    # ── AutoFix & Remediation ──
    AUTOFIX_VIEW = "autofix:view"
    AUTOFIX_APPLY = "autofix:apply"
    AUTOFIX_CONFIGURE = "autofix:configure"

    def __str__(self) -> str:
        return self.value


# ============================================================================
# ROLE CLASS
# ============================================================================

@dataclass
class Role:
    """
    RBAC role definition with permissions, hierarchy, and data classification.

    Attributes:
        name: Role identifier (e.g., 'viewer', 'security_analyst')
        permissions: Set of Permission enums this role grants
        inherits_from: Optional parent role (inherits all parent permissions)
        org_scope: Whether role is organization-scoped (True) or system-wide (False)
        max_data_classification: Maximum sensitivity level ('public', 'internal',
                                'confidential', 'restricted')
        description: Human-readable role description
    """

    name: str
    permissions: Set[Permission] = field(default_factory=set)
    inherits_from: Optional[Role] = None
    org_scope: bool = True
    max_data_classification: str = "public"
    description: str = ""

    def get_all_permissions(self) -> Set[Permission]:
        """Recursively resolve all permissions including inherited ones.

        Perf fix 3: result is memoised on the instance after the first call;
        Role objects are effectively immutable after construction.
        """
        try:
            return self._cached_permissions  # type: ignore[attr-defined]
        except AttributeError:
            perms: Set[Permission] = set(self.permissions)
            if self.inherits_from:
                perms.update(self.inherits_from.get_all_permissions())
            object.__setattr__(self, "_cached_permissions", perms)
            return perms

    def has_permission(self, permission: Permission) -> bool:
        """Check if this role has a permission (including inherited)."""
        return permission in self.get_all_permissions()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize role to dict for JSON/API responses."""
        return {
            "name": self.name,
            "permissions": sorted([p.value for p in self.get_all_permissions()]),
            "inherits_from": self.inherits_from.name if self.inherits_from else None,
            "org_scope": self.org_scope,
            "max_data_classification": self.max_data_classification,
            "description": self.description,
        }


# ============================================================================
# ROLE DEFINITIONS (Built-in Roles)
# ============================================================================

class BuiltinRoles:
    """Factory for creating built-in enterprise roles."""

    @staticmethod
    def viewer() -> Role:
        """Read-only dashboard, findings, reports."""
        return Role(
            name="viewer",
            permissions={
                Permission.FINDINGS_READ,
                Permission.CONNECTORS_READ,
                Permission.REPORTS_READ,
                Permission.USERS_READ,
                Permission.COMPLIANCE_READ,
            },
            org_scope=True,
            max_data_classification="public",
            description="Read-only access to findings, reports, and compliance data",
        )

    @staticmethod
    def developer() -> Role:
        """Developer + triage + autofix suggestions."""
        viewer_role = BuiltinRoles.viewer()
        return Role(
            name="developer",
            permissions={
                Permission.FINDINGS_TRIAGE,
                Permission.AUTOFIX_VIEW,
                Permission.CONNECTORS_READ,
            },
            inherits_from=viewer_role,
            org_scope=True,
            max_data_classification="internal",
            description="Development team: triage findings, view autofix suggestions",
        )

    @staticmethod
    def security_analyst() -> Role:
        """Investigator + council view + attack simulation."""
        developer_role = BuiltinRoles.developer()
        return Role(
            name="security_analyst",
            permissions={
                Permission.FINDINGS_WRITE,
                Permission.COUNCIL_VIEW,
                Permission.ATTACK_SIM_READ,
                Permission.COMPLIANCE_READ,
            },
            inherits_from=developer_role,
            org_scope=True,
            max_data_classification="confidential",
            description="Security team: investigate, triage, view council decisions",
        )

    @staticmethod
    def compliance_officer() -> Role:
        """Manage compliance, evidence, and create reports."""
        analyst_role = BuiltinRoles.security_analyst()
        return Role(
            name="compliance_officer",
            permissions={
                Permission.COMPLIANCE_MANAGE,
                Permission.COMPLIANCE_EVIDENCE,
                Permission.REPORTS_CREATE,
                Permission.REPORTS_EXPORT,
            },
            inherits_from=analyst_role,
            org_scope=True,
            max_data_classification="restricted",
            description="Compliance team: manage frameworks, generate audit reports",
        )

    @staticmethod
    def admin() -> Role:
        """All permissions except system config."""
        return Role(
            name="admin",
            permissions={
                Permission.FINDINGS_READ,
                Permission.FINDINGS_WRITE,
                Permission.FINDINGS_TRIAGE,
                Permission.FINDINGS_DELETE,
                Permission.CONNECTORS_READ,
                Permission.CONNECTORS_MANAGE,
                Permission.CONNECTORS_PULL,
                Permission.COUNCIL_VIEW,
                Permission.COUNCIL_OVERRIDE,
                Permission.COUNCIL_CONFIGURE,
                Permission.COMPLIANCE_READ,
                Permission.COMPLIANCE_MANAGE,
                Permission.COMPLIANCE_EVIDENCE,
                Permission.REPORTS_READ,
                Permission.REPORTS_CREATE,
                Permission.REPORTS_EXPORT,
                Permission.USERS_READ,
                Permission.USERS_MANAGE,
                Permission.USERS_RBAC,
                Permission.SYSTEM_AUDIT,
                Permission.SYSTEM_INTEGRATIONS,
                Permission.ATTACK_SIM_READ,
                Permission.ATTACK_SIM_EXECUTE,
                Permission.AUTOFIX_VIEW,
                Permission.AUTOFIX_APPLY,
                Permission.AUTOFIX_CONFIGURE,
            },
            org_scope=True,
            max_data_classification="restricted",
            description="Organization admin: all permissions except system config",
        )

    @staticmethod
    def super_admin() -> Role:
        """All permissions including system config."""
        admin_role = BuiltinRoles.admin()
        return Role(
            name="super_admin",
            permissions={
                Permission.SYSTEM_CONFIG,
            },
            inherits_from=admin_role,
            org_scope=False,
            max_data_classification="restricted",
            description="System super admin: all permissions including system config",
        )


# ============================================================================
# RBAC ENGINE
# ============================================================================

class RBACEngine:
    """
    Enterprise RBAC engine with permission checking, role management, and caching.

    Provides:
    - Permission checks with LRU caching
    - Role assignment and management
    - Custom role creation
    - Data classification enforcement
    - RBAC matrix export
    """

    def __init__(self, cache_size: int = 1000):
        """
        Initialize RBAC engine.

        Args:
            cache_size: LRU cache size for permission lookups
        """
        self._cache_size = cache_size
        self._user_roles: Dict[str, Dict[str, str]] = {}  # user_id → {org_id: role_name}
        self._custom_roles: Dict[str, Role] = {}  # role_name → Role
        self._audit_log: List[Dict[str, Any]] = []
        self._logger = _logger

        # Pre-load built-in roles
        self._builtin_roles: Dict[str, Role] = {
            "viewer": BuiltinRoles.viewer(),
            "developer": BuiltinRoles.developer(),
            "security_analyst": BuiltinRoles.security_analyst(),
            "compliance_officer": BuiltinRoles.compliance_officer(),
            "admin": BuiltinRoles.admin(),
            "super_admin": BuiltinRoles.super_admin(),
        }

    def _get_role(self, role_name: str) -> Optional[Role]:
        """Get role by name (custom or built-in)."""
        return self._custom_roles.get(role_name) or self._builtin_roles.get(role_name)

    @lru_cache(maxsize=1000)
    def _get_user_role_cached(self, user_id: str, org_id: str) -> Optional[str]:
        """Cached role lookup. Must clear when role changes."""
        user_key = f"{user_id}:{org_id}"
        return self._user_roles.get(user_key)

    def check_permission(
        self,
        user_id: str,
        permission: Permission,
        org_id: str,
        resource_classification: Optional[str] = None,
    ) -> bool:
        """
        Check if user has required permission.

        Args:
            user_id: User ID
            permission: Permission to check
            org_id: Organization ID
            resource_classification: Data classification of resource being accessed
                ('public', 'internal', 'confidential', 'restricted')

        Returns:
            True if user has permission and clearance level
        """
        # Get user's role
        role_name = self._get_user_role_cached(user_id, org_id)
        if not role_name:
            return False

        role = self._get_role(role_name)
        if not role:
            return False

        # Check permission
        if not role.has_permission(permission):
            return False

        # Check data classification (if specified)
        if resource_classification:
            if not self.check_data_access(role, resource_classification):
                return False

        return True

    def get_user_permissions(self, user_id: str, org_id: str) -> Set[str]:
        """
        Get all permissions for a user.

        Args:
            user_id: User ID
            org_id: Organization ID

        Returns:
            Set of permission strings (e.g., "findings:read")
        """
        role_name = self._get_user_role_cached(user_id, org_id)
        if not role_name:
            return set()

        role = self._get_role(role_name)
        if not role:
            return set()

        return {p.value for p in role.get_all_permissions()}

    def assign_role(
        self, user_id: str, role_name: str, org_id: str = "default"
    ) -> bool:
        """
        Assign a role to a user in an organization.

        Args:
            user_id: User ID
            role_name: Role to assign (built-in or custom)
            org_id: Organization ID

        Returns:
            True if assignment successful
        """
        if not self._get_role(role_name):
            self._logger.warning(
                "Failed to assign unknown role %s to user %s", role_name, user_id
            )
            return False

        user_key = f"{user_id}:{org_id}"
        old_role = self._user_roles.get(user_key)
        self._user_roles[user_key] = role_name

        # Invalidate cache
        self._get_user_role_cached.cache_clear()

        # Log audit event
        self._audit_log.append({
            "timestamp": self._get_timestamp(),
            "event": "role_assignment",
            "user_id": user_id,
            "org_id": org_id,
            "new_role": role_name,
            "old_role": old_role,
        })

        self._logger.info(
            "Assigned role %s to user %s in org %s (was %s)",
            role_name, user_id, org_id, old_role,
        )
        return True

    def create_custom_role(
        self,
        name: str,
        permissions: Set[Permission],
        inherits_from: Optional[str] = None,
        org_scope: bool = True,
        max_data_classification: str = "internal",
    ) -> Optional[Role]:
        """
        Create a custom role.

        Args:
            name: Role name (must be unique)
            permissions: Set of Permission enums to grant
            inherits_from: Optional parent role name to inherit from
            org_scope: Whether role is org-scoped
            max_data_classification: Maximum data classification level

        Returns:
            Created Role or None if validation fails
        """
        if name in self._builtin_roles or name in self._custom_roles:
            self._logger.warning("Custom role %s already exists", name)
            return None

        parent_role = None
        if inherits_from:
            parent_role = self._get_role(inherits_from)
            if not parent_role:
                self._logger.warning("Parent role %s not found", inherits_from)
                return None

        role = Role(
            name=name,
            permissions=permissions,
            inherits_from=parent_role,
            org_scope=org_scope,
            max_data_classification=max_data_classification,
        )

        self._custom_roles[name] = role

        self._audit_log.append({
            "timestamp": self._get_timestamp(),
            "event": "custom_role_created",
            "role_name": name,
            "permissions": [p.value for p in permissions],
            "inherits_from": inherits_from,
        })

        self._logger.info("Created custom role %s", name)
        return role

    def get_role_matrix(self) -> Dict[str, Dict[str, Any]]:
        """
        Export complete RBAC matrix.

        Returns:
            Dict mapping role names to role definitions and permissions
        """
        matrix = {}
        all_roles = {**self._builtin_roles, **self._custom_roles}

        for role_name, role in all_roles.items():
            matrix[role_name] = role.to_dict()

        return matrix

    def check_data_access(self, role: Role, resource_classification: str) -> bool:
        """
        Check if role can access data at given classification level.

        Data hierarchy: public < internal < confidential < restricted

        Args:
            role: Role to check
            resource_classification: Classification of resource

        Returns:
            True if role can access resource
        """
        classification_levels = {
            "public": 0,
            "internal": 1,
            "confidential": 2,
            "restricted": 3,
        }

        role_level = classification_levels.get(role.max_data_classification, 0)
        resource_level = classification_levels.get(resource_classification, 0)

        return role_level >= resource_level

    def classify_resource(self, resource_type: str, resource_id: str) -> str:
        """
        Classify a resource by type.

        This is a simplified classifier. Production systems would query
        a database or policy engine.

        Args:
            resource_type: Type of resource (finding, report, config, etc.)
            resource_id: Resource ID

        Returns:
            Classification level string
        """
        # Example: system configs are "restricted", findings are "internal"
        classification_map = {
            "system_config": "restricted",
            "audit_log": "restricted",
            "user": "confidential",
            "api_key": "restricted",
            "policy": "confidential",
            "finding": "internal",
            "report": "internal",
            "connector": "internal",
            "evidence": "confidential",
        }
        return classification_map.get(resource_type, "public")

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get RBAC audit log."""
        return list(self._audit_log)

    def export_matrix_json(self) -> str:
        """Export RBAC matrix as JSON."""
        matrix = self.get_role_matrix()
        return json.dumps(matrix, indent=2, default=str)

    @staticmethod
    def _get_timestamp() -> str:
        """Get current ISO timestamp."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()


# ============================================================================
# PERSONA-TO-ROLE MAPPING
# ============================================================================

class PersonaRoleMapping:
    """Map enterprise personas to RBAC roles."""

    # All 30 personas mapped to the 6 enterprise roles
    PERSONA_MAP: Dict[str, str] = {
        # Admins
        "Sarah Chen": "super_admin",      # CISO
        "Marcus Johnson": "admin",        # VP Engineering
        "Maria Lopez": "admin",           # IT Director
        "Ryan Murphy": "admin",           # Platform Engineer
        "Daniel Thompson": "admin",       # SecOps Manager

        # Security Analysts
        "Alex Rivera": "security_analyst",      # SOC Analyst T1
        "Priya Sharma": "security_analyst",     # SOC Analyst T2
        "James Wilson": "security_analyst",     # Security Engineer
        "Emma Davis": "security_analyst",       # DevSecOps Engineer
        "Lisa Zhang": "security_analyst",       # Penetration Tester
        "Tom Anderson": "security_analyst",     # AppSec Lead
        "Jennifer Wu": "security_analyst",      # Cloud Security Architect
        "Karen Taylor": "security_analyst",     # Incident Response Lead
        "Chris Lee": "security_analyst",        # Security Data Scientist
        "Nina Patel": "security_analyst",       # Threat Intel Analyst
        "Richard Adams": "security_analyst",    # Security Architect
        "Amanda Scott": "security_analyst",     # Supply Chain Security
        "Brian Hall": "security_analyst",       # QA Security Tester

        # Compliance Officers
        "Robert Kim": "compliance_officer",     # Compliance Officer
        "Olivia Martin": "compliance_officer",  # GRC Analyst

        # Developers
        "Emily Chang": "developer",  # Developer (Security Champion)

        # Viewers
        "David Park": "viewer",      # Risk Manager
        "Michael Brown": "viewer",   # Audit Manager
        "Catherine Williams": "viewer",  # Board Member
        "Mark Roberts": "viewer",    # External Auditor

        # Extended personas (if more are added)
        "generic_user": "viewer",
    }

    @classmethod
    def get_role_for_persona(cls, persona_name: str) -> str:
        """
        Get role for a persona.

        Args:
            persona_name: Persona name

        Returns:
            Role name or "viewer" as default
        """
        return cls.PERSONA_MAP.get(persona_name, "viewer")

    @classmethod
    def get_personas_by_role(cls, role_name: str) -> List[str]:
        """
        Get all personas assigned to a role.

        Args:
            role_name: Role name

        Returns:
            List of persona names
        """
        return [
            persona for persona, role in cls.PERSONA_MAP.items()
            if role == role_name
        ]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_rbac_engine() -> RBACEngine:
    """Factory function to create and initialize RBAC engine."""
    engine = RBACEngine(cache_size=1000)

    # Pre-populate with all 30 personas
    for persona_name, role_name in PersonaRoleMapping.PERSONA_MAP.items():
        user_id = hashlib.md5(persona_name.encode(), usedforsecurity=False).hexdigest()[:16]
        engine.assign_role(user_id, role_name, org_id="default")

    return engine


__all__ = [
    "Permission",
    "Role",
    "BuiltinRoles",
    "RBACEngine",
    "PersonaRoleMapping",
    "create_rbac_engine",
    # New RBAC additions
    "RBACRole",
    "RBACPermission",
    "ROLE_PERMISSIONS",
    "require_permission",
    "require_role",
    "get_current_user_role",
]


# ============================================================================
# NEW: Simple Role + Permission enums for FastAPI dependency injection
# ============================================================================

from enum import Enum as _Enum
from typing import Callable as _Callable


class RBACRole(_Enum):
    """Six built-in ALDECI roles (ordered by privilege level, lowest first)."""

    VIEWER = "viewer"
    DEVELOPER = "developer"
    SRE = "sre"
    COMPLIANCE_OFFICER = "compliance_officer"
    SECURITY_ANALYST = "security_analyst"
    ADMIN = "admin"

    # Numeric level for hierarchy comparisons
    @property
    def level(self) -> int:
        _levels = {
            "viewer": 0,
            "developer": 1,
            "sre": 2,
            "compliance_officer": 3,
            "security_analyst": 4,
            "admin": 5,
        }
        return _levels[self.value]


class RBACPermission(_Enum):
    """Granular permissions used by require_permission()."""

    READ_FINDINGS = "read:findings"
    WRITE_FINDINGS = "write:findings"
    DELETE_FINDINGS = "delete:findings"
    READ_COMPLIANCE = "read:compliance"
    WRITE_COMPLIANCE = "write:compliance"
    READ_PIPELINE = "read:pipeline"
    RUN_PIPELINE = "run:pipeline"
    READ_CONNECTORS = "read:connectors"
    WRITE_CONNECTORS = "write:connectors"
    MANAGE_USERS = "manage:users"
    MANAGE_SETTINGS = "manage:settings"
    READ_AUDIT_LOG = "read:audit_log"
    READ_DASHBOARD = "read:dashboard"


# Role → frozenset of allowed permissions
ROLE_PERMISSIONS: Dict[RBACRole, Set[RBACPermission]] = {
    RBACRole.ADMIN: frozenset(RBACPermission),  # type: ignore[arg-type]
    RBACRole.SECURITY_ANALYST: frozenset({
        RBACPermission.READ_FINDINGS,
        RBACPermission.WRITE_FINDINGS,
        RBACPermission.RUN_PIPELINE,
        RBACPermission.READ_COMPLIANCE,
        RBACPermission.READ_CONNECTORS,
        RBACPermission.READ_DASHBOARD,
    }),
    RBACRole.DEVELOPER: frozenset({
        RBACPermission.READ_FINDINGS,
        RBACPermission.READ_COMPLIANCE,
        RBACPermission.READ_DASHBOARD,
    }),
    RBACRole.COMPLIANCE_OFFICER: frozenset({
        RBACPermission.READ_FINDINGS,
        RBACPermission.READ_COMPLIANCE,
        RBACPermission.WRITE_COMPLIANCE,
        RBACPermission.READ_AUDIT_LOG,
        RBACPermission.READ_DASHBOARD,
    }),
    RBACRole.VIEWER: frozenset({
        RBACPermission.READ_FINDINGS,
        RBACPermission.READ_COMPLIANCE,
        RBACPermission.READ_DASHBOARD,
    }),
    RBACRole.SRE: frozenset({
        RBACPermission.READ_FINDINGS,
        RBACPermission.READ_PIPELINE,
        RBACPermission.RUN_PIPELINE,
        RBACPermission.READ_CONNECTORS,
        RBACPermission.READ_DASHBOARD,
    }),
}


def get_current_user_role(request: Any) -> RBACRole:
    """Extract the RBAC role from request state (set by auth middleware).

    Falls back to VIEWER when no role information is present.
    """
    # Auth middleware stores AuthContext in request.state.auth
    auth = getattr(getattr(request, "state", None), "auth", None)
    role_str: str = ""
    if auth is not None:
        role_str = getattr(auth, "role", "")
    if not role_str:
        # Fallback: check query/path context stored directly
        role_str = getattr(getattr(request, "state", None), "user_role", "viewer")

    # Map string role → RBACRole (lenient: unknown → VIEWER)
    _alias: Dict[str, str] = {
        "admin": "admin",
        "super_admin": "admin",
        "analyst": "security_analyst",
        "security_analyst": "security_analyst",
        "developer": "developer",
        "compliance_officer": "compliance_officer",
        "sre": "sre",
        "viewer": "viewer",
        "service": "admin",
    }
    normalized = _alias.get(role_str.lower(), "viewer")
    try:
        return RBACRole(normalized)
    except ValueError:
        return RBACRole.VIEWER


def require_permission(permission: RBACPermission) -> _Callable:
    """FastAPI dependency factory — 403 if user lacks the given permission."""
    try:
        from fastapi import Depends, HTTPException, Request
        from fastapi import status as _status

        async def _check(request: Request) -> RBACRole:
            role = get_current_user_role(request)
            allowed = ROLE_PERMISSIONS.get(role, frozenset())
            if permission not in allowed:
                raise HTTPException(
                    status_code=_status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission.value} required (role={role.value})",
                )
            return role

        return _check
    except ImportError:
        # FastAPI not available (e.g., during unit tests without FastAPI)
        def _stub() -> RBACRole:  # type: ignore[return]
            return RBACRole.ADMIN

        return _stub


def require_role(minimum_role: RBACRole) -> _Callable:
    """FastAPI dependency factory — 403 if user's role level is below minimum."""
    try:
        from fastapi import HTTPException, Request
        from fastapi import status as _status

        async def _check(request: Request) -> RBACRole:
            role = get_current_user_role(request)
            if role.level < minimum_role.level:
                raise HTTPException(
                    status_code=_status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Insufficient role: {minimum_role.value} or higher required "
                        f"(current={role.value})"
                    ),
                )
            return role

        return _check
    except ImportError:
        def _stub() -> RBACRole:  # type: ignore[return]
            return RBACRole.ADMIN

        return _stub
