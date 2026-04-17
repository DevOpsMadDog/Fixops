# PRD — Community 566: RBAC — Role-to-Personas Reverse Lookup

## Master Goal Mapping
**ALDECI Pillar:** RBAC persona model — returns all personas assigned to a given role, enabling role-based bulk notifications, access reviews, and persona discovery.

## Architecture Diagram
```mermaid
graph LR
    A[role_name: str] --> B[get_personas_by_role]
    B -->|PERSONA_MAP filter| C[List[str] personas]
    C --> D[bulk notification / access review]
```

## Code Proof
**File:** `suite-core/core/rbac.py:L617`  
**Module:** `rbac.PersonaRoleMapping.get_personas_by_role`

```python
@classmethod
def get_personas_by_role(cls, role_name: str) -> List[str]:
    """Get all personas assigned to a role.
    Args:
        role_name: Role name
    Returns:
        List of persona names
    """
    return [
        persona for persona, role in cls.PERSONA_MAP.items()
        if role == role_name
    ]
```

## Inter-Dependencies
- `PERSONA_MAP` class-level dict — source of truth
- C565 `get_role_for_persona` — inverse operation
- User access review engine — uses this for role-scoped reviews
- Bulk notification system — notify all personas in a role

## Data Flow
Role name → filter `PERSONA_MAP` where value matches → list of matching persona names.

## Referenced Docs
- ALDECI Rearchitecture v2 §30 Persona Model
- User Access Review engine (`user_access_review_engine.py`)

## Acceptance Criteria
- [ ] `'viewer'` → list of all viewer-assigned personas
- [ ] Unknown role → empty list (not exception)
- [ ] No persona counted twice (PERSONA_MAP has unique keys)
- [ ] Result is reproducible (deterministic order)

## Effort Estimate
S — 1 day (implemented; add reverse-lookup test per role)

## Status
DONE — implemented at L617
