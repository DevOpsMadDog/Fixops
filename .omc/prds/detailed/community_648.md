# Community 648 PRD — Audit Logging / Test Isolation

## Master Goal Mapping
- **ALDECI Domain**: Audit Logging / Test Isolation
- **Module**: `AuditLogger`
- **Source**: `suite-core/core/audit_log.py:L127`
- **Function/Method**: `reset_instance`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `reset_instance` within the Audit Logging / Test Isolation subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["reset_instance()"]
    B --> C[AuditLogger]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/audit_log.py` — **Line**: `L127`

**Signature**: `classmethod def reset_instance(cls) -> None`

```python
@classmethod
def reset_instance(cls) -> None:
    """Reset singleton (useful for tests)."""
    with cls._instance_lock:
        cls._instance = None
```

## Inter-Dependencies

- `_instance_lock`
- `get_instance`

## Data Flow

lock → _instance = None

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/audit_log.py` — Full module implementation

## Acceptance Criteria

- [ ] Clears singleton under lock
- [ ] Next get_instance creates new AuditLogger
- [ ] Enables independent test runs

## Effort Estimate

**XS**

## Status

**Implemented**
