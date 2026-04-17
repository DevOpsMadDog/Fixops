# PRD — Community 571: Threat Simulation Engine — Simulation Row JSON Deserializer

## Master Goal Mapping
**ALDECI Pillar:** Threat Simulation engine — deserializes JSON-encoded `target_systems` and `detections` arrays from SQLite simulation rows into Python lists for API responses.

## Architecture Diagram
```mermaid
graph LR
    A[SQLite simulation row] --> B[_deserialize_sim]
    B -->|json.loads target_systems| C[List[str]]
    B -->|json.loads detections| D[List[dict]]
    C & D --> E[API simulation response]
```

## Code Proof
**File:** `suite-core/core/threat_simulation_engine.py:L123`  
**Module:** `threat_simulation_engine.ThreatSimulationEngine._deserialize_sim`

```python
@staticmethod
def _deserialize_sim(row: Dict[str, Any]) -> Dict[str, Any]:
    """Parse JSON fields in a simulation row."""
    for field in ("target_systems", "detections"):
        if isinstance(row.get(field), str):
            try:
                row[field] = json.loads(row[field])
            except (json.JSONDecodeError, TypeError):
                row[field] = []
    return row
```

## Inter-Dependencies
- `list_simulations()` / `get_simulation()` — call `_deserialize_sim`
- `create_simulation()` — stores these as JSON strings
- C572 `_deserialize_scenario` — sibling method for scenario rows
- `/api/v1/threat-simulation` router

## Data Flow
Raw SQLite row → JSON deserialization of list fields → Python list types → returned for API serialization.

## Referenced Docs
- ALDECI Rearchitecture v2 §Threat Simulation Engine
- Red team / blue team exercise data model

## Acceptance Criteria
- [ ] Valid JSON string `'["host1"]'` → list `['host1']`
- [ ] Invalid JSON → empty list (not exception)
- [ ] Non-string (already list) left unchanged
- [ ] Both fields deserialized in single call

## Effort Estimate
XS — 0.5 day (implemented; add deserialization test)

## Status
DONE — implemented at L123
