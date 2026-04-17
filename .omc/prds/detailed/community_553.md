# PRD — Community 553: PKI Management Engine — Certificate Row JSON Deserializer

## Master Goal Mapping
**ALDECI Pillar:** PKI Certificate Lifecycle Management — converts raw SQLite certificate rows into API-ready dicts by deserializing SAN JSON arrays and coercing auto_renew to boolean.

## Architecture Diagram
```mermaid
graph LR
    A[SQLite cert row] --> B[_format_cert]
    B -->|json.loads SANs| C[list of alt names]
    B -->|bool()| D[auto_renew flag]
    C & D --> E[API cert response dict]
```

## Code Proof
**File:** `suite-core/core/pki_management_engine.py:L448`  
**Module:** `pki_management_engine.PKIManagementEngine._format_cert`

```python
@staticmethod
def _format_cert(row: Dict[str, Any]) -> Dict[str, Any]:
    """Deserialize JSON fields in a certificate row."""
    san = row.get("subject_alt_names", "[]")
    if isinstance(san, str):
        try:
            row["subject_alt_names"] = json.loads(san)
        except (json.JSONDecodeError, TypeError):
            row["subject_alt_names"] = []
    row["auto_renew"] = bool(row.get("auto_renew", 0))
    return row
```

## Inter-Dependencies
- `list_certificates()` — calls `_format_cert` per row
- `get_certificate()` — calls `_format_cert` on single row
- `/api/v1/pki` router — serves formatted cert dicts
- C553 is mirrored by similar patterns in C590 (SignatureChainEntry) and C571 (threat_sim)

## Data Flow
SQLite row dict → SAN string deserialized to list → auto_renew integer coerced to bool → clean API response.

## Referenced Docs
- ALDECI Rearchitecture v2 §PKI & Certificate Management
- RFC 5280 (Subject Alternative Names)
- X.509 certificate lifecycle management

## Acceptance Criteria
- [ ] SAN JSON string `'["example.com"]'` → list `["example.com"]`
- [ ] Invalid SAN JSON → empty list (not exception)
- [ ] `auto_renew=1` → `True`, `auto_renew=0` → `False`
- [ ] Missing SAN → defaults to empty list

## Effort Estimate
S — 1 day (implemented; add deserialization unit test)

## Status
DONE — implemented at L448
