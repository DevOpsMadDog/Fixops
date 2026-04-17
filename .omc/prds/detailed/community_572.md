# PRD — Community 572: Threat Simulation Engine — Scenario Row JSON Deserializer

## Master Goal Mapping
**ALDECI Pillar:** Threat Simulation engine — deserializes `mitre_techniques` JSON array from SQLite scenario rows into Python lists for MITRE ATT&CK technique display in exercise reports.

## Architecture Diagram
```mermaid
graph LR
    A[SQLite scenario row] --> B[_deserialize_scenario]
    B -->|json.loads mitre_techniques| C[List[str] technique IDs]
    C --> D[Scenario API response]
    D --> E[MITRE ATT&CK heatmap]
```

## Code Proof
**File:** `suite-core/core/threat_simulation_engine.py:L134`  
**Module:** `threat_simulation_engine.ThreatSimulationEngine._deserialize_scenario`

```python
@staticmethod
def _deserialize_scenario(row: Dict[str, Any]) -> Dict[str, Any]:
    """Parse JSON fields in a scenario row."""
    if isinstance(row.get("mitre_techniques"), str):
        try:
            row["mitre_techniques"] = json.loads(row["mitre_techniques"])
        except (json.JSONDecodeError, TypeError):
            row["mitre_techniques"] = []
    return row
```

## Inter-Dependencies
- `list_scenarios()` / `get_scenario()` — call `_deserialize_scenario`
- `create_scenario()` — stores techniques as JSON string
- C571 `_deserialize_sim` — sibling for simulation rows
- MITRE ATT&CK coverage heatmap — consumes technique IDs

## Data Flow
Raw scenario row → `mitre_techniques` JSON deserialization → list of technique IDs → scenario response → ATT&CK heatmap rendering.

## Referenced Docs
- ALDECI Rearchitecture v2 §Threat Simulation
- MITRE ATT&CK technique ID format (T1234)

## Acceptance Criteria
- [ ] `'["T1059","T1078"]'` → `['T1059', 'T1078']`
- [ ] Invalid JSON → `[]`
- [ ] Already a list → unchanged
- [ ] Missing field → row returned unchanged

## Effort Estimate
XS — 0.5 day (implemented; add scenario deserialization test)

## Status
DONE — implemented at L134
