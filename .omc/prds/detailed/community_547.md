# PRD — Community 547: Privacy GDPR Engine — Raw Row to API Dict Converter

## Master Goal Mapping
**ALDECI Pillar:** GDPR/Privacy compliance engine — deserializes JSON-string fields and converts SQLite boolean integers into Python types, ensuring API responses are correctly typed.

## Architecture Diagram
```mermaid
graph LR
    A[SQLite Row dict] --> B[_row_from_dict]
    B -->|json.loads| C[list fields deserialized]
    B -->|bool()| D[dpiad_required as bool]
    C & D --> E[API Response dict]
```

## Code Proof
**File:** `suite-core/core/privacy_gdpr_engine.py:L605`  
**Module:** `privacy_gdpr_engine.PrivacyGDPREngine._row_from_dict`

```python
@staticmethod
def _row_from_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Convert raw insert dict to API-friendly dict."""
    result = dict(d)
    for field in ("data_categories", "data_subjects",
                  "third_party_recipients", "international_transfers"):
        if field in result and isinstance(result[field], str):
            try: result[field] = json.loads(result[field])
            except (json.JSONDecodeError, TypeError): pass
    for field in ("dpiad_required",):
        if field in result: result[field] = bool(result[field])
    return result
```

## Inter-Dependencies
- `register_processing_activity()` — calls this after INSERT
- `list_processing_activities()` — calls this per row
- GDPR RoPA data model

## Data Flow
Raw SQLite row dict → JSON string deserialization for list fields → boolean coercion for flag fields → clean API response dict.

## Referenced Docs
- ALDECI Rearchitecture v2 §Privacy & GDPR Engine
- GDPR Article 30 (Records of processing activities)

## Acceptance Criteria
- [ ] JSON string `'["pii"]'` → list `["pii"]`
- [ ] Integer `1` → `True` for `dpiad_required`
- [ ] Invalid JSON string left as-is (parse error silently swallowed)
- [ ] Non-string list field left unchanged

## Effort Estimate
S — 1 day (implemented; add deserialization tests)

## Status
DONE — implemented at L605
