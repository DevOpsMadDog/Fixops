# PRD — Community 561: RBAC Built-in Role — admin

## Master Goal Mapping
**ALDECI Pillar:** Role-Based Access Control (RBAC) system — defines the `admin` built-in role with curated permission set and inheritance chain for ALDECI's 30-persona, 6-role enterprise security model.

## Architecture Diagram
```mermaid
graph LR
    A[BuiltinRoles.admin] --> B[Role object]
    B -->|permissions set| C[RBAC permission check]
    B -->|inherits_from| D[parent Role permissions merged]
    C --> E[API endpoint auth gate]
```

## Code Proof
**File:** `suite-core/core/rbac.py:L212`  
**Module:** `rbac.BuiltinRoles.admin`

```python
@staticmethod
def admin() -> Role:
    """All permissions except system config."""
    return Role(
        name="admin",
        permissions={...},  # All permissions except SYSTEM_CONFIG
        inherits_from=None,
        org_scope=True,
        ...
    )
```

## Inter-Dependencies
- `BuiltinRoles.admin()` factory used by `RBACManager.create_default_roles()`
- `PersonaRoleMapping` — C565/C566 — maps 30 personas to these roles
- `RBACManager.check_permission()` — evaluates effective permissions
- `/api/v1/rbac` router — admin role management endpoints

## Data Flow
Factory static method → `Role` dataclass instantiation with permission set and inheritance → RBAC manager stores → permission checks at API boundaries.

## Referenced Docs
- ALDECI Rearchitecture v2 §RBAC & Persona Model
- NIST SP 800-207 (Zero Trust Architecture)
- RBAC standard (ANSI INCITS 359-2004)

## Acceptance Criteria
- [ ] Role name = `admin`
- [ ] Permission set contains exactly: All permissions except SYSTEM_CONFIG
- [ ] Inheritance from `None — explicit full grant` correctly merges parent permissions
- [ ] `org_scope=True` (scoped to organization)
- [ ] No permission outside defined set granted

## Effort Estimate
S — 1 day per role (all implemented; add permission inheritance integration tests)

## Status
DONE — implemented at L212
