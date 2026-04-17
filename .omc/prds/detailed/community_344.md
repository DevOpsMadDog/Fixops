# PRD: Community 344 — MPTE Fail Engine — Recommendation Builder

## Master Goal Mapping
**Goal:** Build human-readable MPTE recommendation strings from dimension scores and gaps, generating actionable improvement guidance for security teams from drill results.

**Domain:** Attack Simulation / Recommendations
**Personas:** CISO, Security Analyst
**Node Count:** 1 | **Status:** Implemented

---

## Source Files
- `suite-attack/attack/fail_engine.py`

## Graph Nodes (Labels)
- Build human-readable recommendation string.

---

## Architecture Diagram

```mermaid
graph TD
    A[GradingDimensions] --> B[build_recommendation(dims)]
    B --> C[Identify lowest scores]
    C --> D[Template-based rec text]
    D --> E[Priority recommendation string]
```

---

## Code Proof

- `suite-attack/attack/fail_engine.py:L1` — Build human-readable recommendation string from dimensions

---

## Inter-Dependencies

- `suite-attack/attack/fail_engine.py (339-343)`
- `suite-attack/api/attack_sim_router.py`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
dimension list → sort by score asc → template fill for lowest 3 → joined recommendation
```

---

## Referenced Docs

- `suite-attack/attack/fail_engine.py`
- `suite-attack/api/attack_sim_router.py`

---

## Acceptance Criteria

- [ ] Returns non-empty string
- [ ] Prioritizes lowest-scoring dimensions
- [ ] No PII in recommendations

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
