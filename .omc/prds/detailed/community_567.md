# PRD — Community 567: Data Discovery Engine — CSV Data Types Deserializer

## Master Goal Mapping
**ALDECI Pillar:** Data Discovery engine — converts the comma-joined `data_types_found` CSV string stored in SQLite back into a Python list for API responses.

## Architecture Diagram
```mermaid
graph LR
    A[SQLite datastore row] --> B[_parse_datastore]
    B -->|split CSV| C[List[str] data_types_found]
    C --> D[API response / risk scoring]
```

## Code Proof
**File:** `suite-core/core/data_discovery_engine.py:L136`  
**Module:** `data_discovery_engine.DataDiscoveryEngine._parse_datastore`

```python
@staticmethod
def _parse_datastore(record: Dict[str, Any]) -> Dict[str, Any]:
    """Split data_types_found CSV back into a list."""
    raw = record.get("data_types_found", "")
    record["data_types_found"] = (
        [t for t in raw.split(",") if t] if raw else []
    )
    return record
```

## Inter-Dependencies
- `register_datastore()` — stores CSV; `_parse_datastore` reverses on read
- `list_datastores()` / `get_datastore()` — call `_parse_datastore` per row
- Data Discovery risk scoring — uses `data_types_found` list for PII classification
- `/api/v1/data-discovery` router

## Data Flow
Raw SQLite row with CSV string → split on comma → filter empty tokens → list stored back into record dict → returned to caller.

## Referenced Docs
- ALDECI Rearchitecture v2 §Data Discovery & Classification
- GDPR Article 30 data mapping requirements

## Acceptance Criteria
- [ ] `'pii,financial,health'` → `['pii', 'financial', 'health']`
- [ ] Empty string → `[]`
- [ ] `'pii,'` (trailing comma) → `['pii']` (empty token filtered)
- [ ] None → `[]`

## Effort Estimate
XS — 0.5 day (implemented; add CSV parse unit test)

## Status
DONE — implemented at L136
