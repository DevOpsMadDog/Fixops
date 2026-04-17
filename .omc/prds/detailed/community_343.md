# PRD: Community 343 — MPTE Fail Engine — Drill Neglect Risk Scorer

## Master Goal Mapping
**Goal:** Convert days-since-last-drill to a risk score (0-10) penalizing organizations that neglect regular security drill exercises, feeding into overall posture scores.

**Domain:** Attack Simulation / Risk Scoring
**Personas:** CISO, Red Team Engineer
**Node Count:** 1 | **Status:** Implemented

---

## Source Files
- `suite-attack/attack/fail_engine.py`

## Graph Nodes (Labels)
- Convert days since last drill to neglect risk score (0-10).

---

## Architecture Diagram

```mermaid
graph TD
    A[days_since_drill] --> B[neglect_risk_score(days)]
    B --> C{days > 365?}
    C -->|yes| D[score = 10.0]
    C -->|no| E[linear interpolation]
    E --> F[float 0-10]
```

---

## Code Proof

- `suite-attack/attack/fail_engine.py:L1` — Convert days since last drill to neglect risk score (0-10)

---

## Inter-Dependencies

- `suite-attack/attack/fail_engine.py (342)`
- `suite-attack/attack/fail_engine.py (344-345)`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
days_since_drill → min(days/365 * 10, 10.0) → risk score
```

---

## Referenced Docs

- `suite-attack/attack/fail_engine.py`

---

## Acceptance Criteria

- [ ] 0 days → 0.0
- [ ] 365 days → 10.0
- [ ] 999 (never) → 10.0
- [ ] Linear between

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
