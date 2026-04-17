# PRD: Community 339 — MPTE Fail Engine — Score to Letter Grade Converter

## Master Goal Mapping
**Goal:** Convert numeric MPTE security scores (0-10 scale) to letter grades (A-F) for executive-readable drill assessment reports and CISO dashboards.

**Domain:** Attack Simulation / Reporting
**Personas:** CISO, Red Team Engineer
**Node Count:** 1 | **Status:** Implemented

---

## Source Files
- `suite-attack/attack/fail_engine.py`

## Graph Nodes (Labels)
- Convert numeric score (0-10) to letter grade.

---

## Architecture Diagram

```mermaid
graph TD
    A[MPTE score 0-10] --> B[score_to_grade(score)]
    B --> C{score >= 9?}
    C -->|A| D[return A]
    C -->|B-F| E[tiered thresholds]
    E --> F[Letter grade]
```

---

## Code Proof

- `suite-attack/attack/fail_engine.py:L1` — Convert numeric score (0-10) to letter grade — grading utility

---

## Inter-Dependencies

- `suite-attack/attack/fail_engine.py (338, 340-345)`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
0-10 score → threshold table lookup → A/B/C/D/F grade string
```

---

## Referenced Docs

- `suite-attack/attack/fail_engine.py`
- `suite-attack/api/attack_sim_router.py`

---

## Acceptance Criteria

- [ ] 9.0+ → A
- [ ] 7.0-8.9 → B
- [ ] 5.0-6.9 → C
- [ ] 3.0-4.9 → D
- [ ] <3.0 → F

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
