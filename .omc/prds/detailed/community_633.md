# Community 633 PRD — Object Storage Abstraction

## Master Goal Mapping
- **ALDECI Domain**: Object Storage Abstraction
- **Module**: `StorageBackend (ABC)`
- **Source**: `suite-core/core/storage_backends.py:L180`
- **Function/Method**: `get_metadata`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `get_metadata` within the Object Storage Abstraction subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["get_metadata()"]
    B --> C[StorageBackend (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/storage_backends.py` — **Line**: `L180`

**Signature**: `def get_metadata(key: str) -> StorageMetadata`

```python
"""Retrieve metadata for an object.
Args:
    key: Object identifier
Returns:
    StorageMetadata for the object
Raises:
    ObjectNotFoundError: If object does not exist
"""
```

## Inter-Dependencies

- `StorageMetadata dataclass`
- `LocalFileBackend.get_metadata`

## Data Flow

key → metadata-only lookup → StorageMetadata (no content bytes transferred)

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/storage_backends.py` — Full module implementation

## Acceptance Criteria

- [ ] Returns StorageMetadata without loading object body
- [ ] Raises ObjectNotFoundError when key absent

## Effort Estimate

**XS (abstract interface)**

## Status

**Implemented**
