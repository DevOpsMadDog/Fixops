# PRD: Community 527 — security_hardening.parse_ip_networks

## Master Goal Mapping
**ALDECI Pillar**: Security Hardening — IP Access Control  
**Persona**: All API consumers (enforced at middleware layer)  
**Business Value**: Parse a list of IP/CIDR strings into ipaddress.ip_network objects. Used by IPAccessManager to build allow/deny lists. Addresses NIST 800-53 SC-7 (Information Input Validation).

## Architecture Diagram
```mermaid
graph TD
    A[API request parameter] --> B[security_hardening.parse_ip_networks]
    B --> C{Validation check}
    C -->|PASS| D[Return sanitized/validated value]
    C -->|FAIL| E[Raise ValueError / return False]
    D --> F[Business logic / DB query]
    E --> G[422 Unprocessable Entity]
    style B fill:#c1121f,color:#fff
```

## Code Proof
**File**: `suite-core/core/security_hardening.py`  
Function: `parse_ip_networks` — part of the FedRAMP-grade security hardening module.

NIST 800-53 controls addressed:
- SC-7: Information Input Validation
- SI-3: Malicious Code Protection
- SC-7: Boundary Protection (for IP functions)

The module provides:
```python
from core.security_hardening import parse_ip_networks
# Used in FastAPI endpoints and engine methods
value = parse_ip_networks(user_input)  # Raises ValueError or returns safe value
```

## Inter-Dependencies
- **Upstream**: All FastAPI route handlers (344 engines × N parameters)
- **Downstream**: SQLite queries, filesystem operations, subprocess calls
- **Sibling**: Other functions in `security_hardening.py` (Communities 512-527)
- **Middleware**: `RequestSizeLimiter`, `RateLimiter` (same module)

## Data Flow
```
POST /api/v1/findings/search {"query": "' OR 1=1 --", "column": "title"}
  → validate_no_sql_injection("' OR 1=1 --")
    → has_sql_injection → True
    → raise ValueError("SQL injection detected")
  → 422 Unprocessable Entity: "SQL injection detected"
```

## Referenced Docs
- `suite-core/core/security_hardening.py`
- NIST SP 800-53 Rev 5: SC-7
- OWASP Input Validation Cheat Sheet

## Acceptance Criteria
- [ ] Function correctly identifies/sanitizes the target attack vector
- [ ] Passes valid inputs without modification (no false positives)
- [ ] Raises `ValueError` (not 500) on malicious input
- [ ] No silent data corruption — raises or returns unchanged
- [ ] Used in ≥ 1 production API endpoint
- [ ] Parametrized tests cover: clean input, injection attempt, edge cases (empty, None, unicode)

## Effort Estimate
**XS** — 0.5 days per function. Functions complete; security regression tests.

## Status
**COMPLETE** — All functions implemented. Security regression test suite needed.
