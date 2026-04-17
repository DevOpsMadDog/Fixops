# PRD: Community 503 — dast_engine._ip_to_int

## Master Goal Mapping
**ALDECI Pillar**: DAST — SSRF Prevention (IP Range Validation)  
**Persona**: Security Engineer  
**Business Value**: Converts a dotted-quad IPv4 address to a 32-bit integer for O(1) CIDR range comparisons, used in the DAST SSRF prevention layer to block scan requests targeting private/internal IP ranges.

## Architecture Diagram
```mermaid
graph TD
    A[Target URL: http://192.168.1.1/api] --> B[_ip_to_int]
    B --> C[Split: 192.168.1.1 → [192,168,1,1]]
    C --> D[Bitshift: 192<<24 | 168<<16 | 1<<8 | 1]
    D --> E[Integer: 3232235777]
    E --> F[Compare against blocked ranges]
    F -->|in 192.168.0.0/16| G[BLOCKED: SSRF risk]
    F -->|not in any range| H[ALLOWED: public IP]
    style B fill:#e9c46a,color:#000
```

## Code Proof
**File**: `suite-core/core/dast_engine.py`  
```python
def _ip_to_int(ip: str) -> int:
    """Convert dotted-quad IP to integer for range comparison."""
    parts = ip.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
```

## Inter-Dependencies
- **Upstream**: `_init_blocked_ranges` (Community 504), `validate_target_url` (Community 505)
- **Downstream**: CIDR range check in SSRF protection layer
- **Sibling**: `security_hardening.SSRFProtection` (uses ipaddress module for same purpose)

## Data Flow
```
validate_target_url("http://10.0.0.1/admin")
  → parsed_host = "10.0.0.1"
  → ip_int = _ip_to_int("10.0.0.1") = 167772161
  → check against blocked_ranges[(167772160, 184549375)]  # 10.0.0.0/8
  → 167772160 <= 167772161 <= 184549375 → BLOCKED
```

## Referenced Docs
- `suite-core/core/dast_engine.py`
- CWE-918: Server-Side Request Forgery (SSRF)

## Acceptance Criteria
- [ ] "0.0.0.0" → 0
- [ ] "255.255.255.255" → 4294967295
- [ ] "192.168.1.1" → 3232235777
- [ ] "10.0.0.1" → 167772161
- [ ] Invalid input raises ValueError (no silent corruption)

## Effort Estimate
**XS** — 0.5 days. Function complete; boundary value tests.

## Status
**COMPLETE** — Implementation exists. Boundary tests needed.
