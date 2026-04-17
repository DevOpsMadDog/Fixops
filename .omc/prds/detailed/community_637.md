# Community 637 PRD — Legal/Compliance Hold

## Master Goal Mapping
- **ALDECI Domain**: Legal/Compliance Hold
- **Module**: `StorageBackend (ABC)`
- **Source**: `suite-core/core/storage_backends.py:L233`
- **Function/Method**: `set_legal_hold`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `set_legal_hold` within the Legal/Compliance Hold subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["set_legal_hold()"]
    B --> C[StorageBackend (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/storage_backends.py` — **Line**: `L233`

**Signature**: `def set_legal_hold(key: str, enabled: bool) -> None`

```python
"""Enable or disable legal hold on an object.
Args:
    key: Object identifier
    enabled: True to enable, False to disable
Raises:
    ObjectNotFoundError: If object does not exist
"""
```

## Inter-Dependencies

- `delete() — blocked when legal hold active`
- `LocalFileBackend.set_legal_hold`

## Data Flow

key + enabled flag → update hold metadata → None; delete() checks hold before proceeding

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/storage_backends.py` — Full module implementation

## Acceptance Criteria

- [ ] Enables legal hold preventing deletion
- [ ] Disables legal hold allowing deletion
- [ ] Raises ObjectNotFoundError for unknown keys
- [ ] Persists hold status in StorageMetadata

## Effort Estimate

**S**

## Status

**Implemented**
