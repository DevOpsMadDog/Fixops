# PRD — Community 629: Email Security Engine — SPF/DKIM/DMARC Compliance Score

## Master Goal Mapping
**ALDECI Pillar:** Email security hardening — computes a 0–100 compliance score from SPF, DKIM, and DMARC configuration status, providing a single actionable metric for email authentication posture.

## Architecture Diagram
```mermaid
graph LR
    A[spf_status] --> B[_compute_compliance_score]
    A2[dkim_status] --> B
    A3[dmarc_policy] --> B
    B -->|lookup tables| C[raw_score]
    C -->|clamp 0-100| D[compliance_score int]
    D --> E[EmailDomainReport.compliance_score]
    D --> F[/api/v1/email-security dashboard]
```

## Code Proof
**File:** `suite-core/core/email_security_engine.py:L157`  
**Module:** `email_security_engine.EmailSecurityEngine._compute_compliance_score`

```python
@staticmethod
def _compute_compliance_score(spf_status: str, dkim_status: str, dmarc_policy: str) -> int:
    """Compute 0-100 compliance score from SPF/DKIM/DMARC values.
    Scoring breakdown:
      SPF status:   pass=30, fail=5, missing=0
      DKIM status:  pass=30, fail=5, missing=0
      DMARC policy: reject=40, quarantine=25, none=10, missing=0
    """
    score = (
        _RECORD_STATUS_SCORES.get(spf_status, 0)
        + _RECORD_STATUS_SCORES.get(dkim_status, 0)
        + _DMARC_POLICY_SCORES.get(dmarc_policy, 0)
    )
    return min(100, max(0, score))
```

## Inter-Dependencies
- `_RECORD_STATUS_SCORES` dict — SPF/DKIM score lookup
- `_DMARC_POLICY_SCORES` dict — DMARC policy score lookup
- `analyze_domain()` — calls `_compute_compliance_score` after DNS lookups
- `EmailDomainReport` — stores compliance score
- `/api/v1/email-security` router

## Data Flow
Three email auth status strings → lookup score tables → sum → clamp to [0,100] → integer compliance score.

## Referenced Docs
- ALDECI Rearchitecture v2 §Email Security Engine
- RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)
- Email authentication best practices (pass SPF+DKIM+DMARC reject = 100 points)

## Acceptance Criteria
- [ ] All pass/reject → score = 100
- [ ] All missing → score = 0
- [ ] SPF pass (30) + DKIM pass (30) + DMARC none (10) = 70
- [ ] SPF pass (30) + DKIM pass (30) + DMARC reject (40) = 100
- [ ] Score always in [0, 100] range

## Effort Estimate
S — 1 day (implemented; add scoring table test matrix)

## Status
DONE — implemented at L157
