# PRD — Community 616: Security Registry Engine — Tag String Splitter

## Master Goal Mapping
**ALDECI Pillar:** Security artifact registry — splits comma-joined tag strings stored in SQLite back into Python lists, enabling API responses to return properly typed tag arrays for registry artifacts.

## Architecture Diagram
```mermaid
graph LR
    A[SQLite tag_list VARCHAR] --> B[_split_tags]
    B -->|split + strip + filter| C[List[str] tags]
    C --> D[_artifact_to_dict]
    D --> E[API artifact response]
```

## Code Proof
**File:** `suite-core/core/security_registry_engine.py:L152`  
**Module:** `security_registry_engine.SecurityRegistryEngine._split_tags`

```python
@staticmethod
def _split_tags(tag_list_str: str) -> List[str]:
    """Split a comma-joined tag string into a list, filtering empties."""
    if not tag_list_str: return []
    return [t.strip() for t in tag_list_str.split(",") if t.strip()]
```

## Inter-Dependencies
- `_artifact_to_dict()` — calls `_split_tags` on each registry row
- `list_artifacts()` / `get_artifact()` — produce dicts via `_artifact_to_dict`
- `create_artifact()` — stores tags as comma-joined string
- `/api/v1/security-registry` router

## Data Flow
Comma-joined tag string → split on comma → strip whitespace → filter empties → list of tag strings.

## Referenced Docs
- ALDECI Rearchitecture v2 §Security Registry
- OSCAL artifact registry data model

## Acceptance Criteria
- [ ] `'vuln,policy,runbook'` → `['vuln', 'policy', 'runbook']`
- [ ] Empty string → `[]`
- [ ] `'tag1, tag2 '` (spaces) → `['tag1', 'tag2']`
- [ ] `'tag,'` (trailing comma) → `['tag']`
- [ ] None-like falsy → `[]`

## Effort Estimate
XS — 0.5 day (implemented; add split edge-case test)

## Status
DONE — implemented at L152
