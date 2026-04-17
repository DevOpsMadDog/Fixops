# PRD: Community 345 — MPTE Attack Sim Router — Score to Grade (Router Layer)

## Master Goal Mapping
**Goal:** Expose the score-to-letter-grade conversion as a utility within the attack_sim_router, providing consistent grading across all attack simulation API responses.

**Domain:** Attack Simulation / API
**Personas:** Red Team Engineer, Platform Engineer
**Node Count:** 1 | **Status:** Implemented

---

## Source Files
- `suite-attack/attack/fail_engine.py`

## Graph Nodes (Labels)
- Convert numeric score to letter grade.

---

## Architecture Diagram

```mermaid
graph TD
    A[attack_sim_router] --> B[score_to_letter_grade(score)]
    B --> C[Threshold table]
    C --> D[A/B/C/D/F]
    D --> E[API response field]
```

---

## Code Proof

- `suite-attack/attack/fail_engine.py:L1` — Convert numeric score to letter grade — router-layer utility

---

## Inter-Dependencies

- `suite-attack/api/attack_sim_router.py`
- `suite-attack/attack/fail_engine.py (338-344)`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
API score → letter_grade() → included in /attack-sim response payload
```

---

## Referenced Docs

- `suite-attack/api/attack_sim_router.py`

---

## Acceptance Criteria

- [ ] Consistent with fail_engine grade mapping
- [ ] Used in all attack sim endpoints
- [ ] Documented in API schema

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
