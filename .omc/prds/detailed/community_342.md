# PRD: Community 342 — MPTE Fail Engine — Days Since Last Drill Calculator

## Master Goal Mapping
**Goal:** Calculate days elapsed since the last MPTE drill execution, returning 999 for never-drilled organizations to surface drill neglect in security posture scoring.

**Domain:** Attack Simulation / Drill Tracking
**Personas:** CISO, Red Team Engineer
**Node Count:** 1 | **Status:** Implemented

---

## Source Files
- `suite-attack/attack/fail_engine.py`

## Graph Nodes (Labels)
- Return days since the last drill, or 999 if never drilled.

---

## Architecture Diagram

```mermaid
graph TD
    A[MPTE org record] --> B[days_since_drill(last_drill_ts)]
    B --> C{ever drilled?}
    C -->|no| D[return 999]
    C -->|yes| E[(now - last_drill).days]
    E --> F[int days]
```

---

## Code Proof

- `suite-attack/attack/fail_engine.py:L1` — Return days since last drill, or 999 if never drilled

---

## Inter-Dependencies

- `suite-attack/attack/fail_engine.py (338-341, 343-345)`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
last_drill_timestamp → (now - ts).days → int, or None → 999
```

---

## Referenced Docs

- `suite-attack/attack/fail_engine.py`

---

## Acceptance Criteria

- [ ] Never drilled → 999
- [ ] 1 day ago → 1
- [ ] Today → 0

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
