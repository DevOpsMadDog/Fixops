# PRD: Community 340 — MPTE Fail Engine — Industry Percentile Estimator

## Master Goal Mapping
**Goal:** Estimate ALDECI customer percentile ranking against industry baselines for MPTE overall scores, enabling competitive security posture benchmarking in board reports.

**Domain:** Attack Simulation / Benchmarking
**Personas:** CISO, Executive
**Node Count:** 1 | **Status:** Implemented

---

## Source Files
- `suite-attack/attack/fail_engine.py`

## Graph Nodes (Labels)
- Estimate percentile ranking vs industry based on overall score.

---

## Architecture Diagram

```mermaid
graph TD
    A[MPTE overall score] --> B[estimate_percentile(score)]
    B --> C[Industry baseline lookup]
    C --> D[Interpolated percentile 0-100]
    D --> E[Board report metric]
```

---

## Code Proof

- `suite-attack/attack/fail_engine.py:L1` — Estimate percentile ranking vs industry based on overall score

---

## Inter-Dependencies

- `suite-attack/attack/fail_engine.py (338-339, 341-345)`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
overall_score → industry_baseline_table → interpolate → percentile int
```

---

## Referenced Docs

- `suite-attack/attack/fail_engine.py`
- `docs/ALDECI_REARCHITECTURE_v2.md §MPTE`

---

## Acceptance Criteria

- [ ] Score 10 → 99th percentile
- [ ] Score 5 → ~50th percentile
- [ ] Monotonically increasing function

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
