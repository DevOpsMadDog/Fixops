# PRD — Community 611: SAST Engine — Total Rule Count

## Master Goal Mapping
**ALDECI Pillar:** SAST engine metadata — returns the exact count of all registered SAST detection rules, displayed on the developer portal and used for coverage reporting.

## Architecture Diagram
```mermaid
graph LR
    A[SAST_RULES tuple] --> B[get_rule_count]
    B -->|len()| C[int rule count]
    C --> D[/api/v1/sast/stats]
    C --> E[OpenAPI developer portal]
```

## Code Proof
**File:** `suite-core/core/sast_engine.py:L2170`  
**Module:** `sast_engine.SASTEngine.get_rule_count`

```python
@staticmethod
def get_rule_count() -> int:
    """Return total number of SAST rules."""
    return len(SAST_RULES)
```

## Inter-Dependencies
- `SAST_RULES` — master rules list (source of truth)
- C610 `get_supported_languages` — uses same `SAST_RULES`
- C612 `get_owasp_coverage` — companion coverage method
- SAST stats endpoint — displays total rules

## Data Flow
`len(SAST_RULES)` → integer returned to stats endpoint and developer portal.

## Referenced Docs
- ALDECI Rearchitecture v2 §SAST Engine
- OWASP Top 10 2021 mapping

## Acceptance Criteria
- [ ] Returns positive integer
- [ ] Matches `len(SAST_RULES)` exactly
- [ ] No side effects
- [ ] Pure static method (no instance required)

## Effort Estimate
XS — 0.5 day (implemented; add count assertion test)

## Status
DONE — implemented at L2170
