# PRD: Community 338 — MPTE Fail Engine — ISO Timestamp Differencer

## Master Goal Mapping
**Goal:** Compute minutes elapsed between two ISO 8601 timestamps for MPTE drill duration tracking, enabling SLA measurement of red team exercise time-to-detect.

**Domain:** Attack Simulation / MPTE Metrics
**Personas:** Red Team Engineer, CISO
**Node Count:** 1 | **Status:** Implemented

---

## Source Files
- `suite-attack/attack/fail_engine.py`

## Graph Nodes (Labels)
- Compute minutes between two ISO timestamps.

---

## Architecture Diagram

```mermaid
graph TD
    A[MPTE drill record] --> B[compute_minutes(t1, t2)]
    B --> C[datetime.fromisoformat parse]
    C --> D[(t2-t1).total_seconds/60]
    D --> E[float minutes]
```

---

## Code Proof

- `suite-attack/attack/fail_engine.py:L1` — Compute minutes between two ISO timestamps — MPTE timing utility

---

## Inter-Dependencies

- `suite-attack/attack/fail_engine.py (339-345)`
- `suite-attack/api/attack_sim_router.py`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
ISO timestamp pair → datetime.fromisoformat() → timedelta → minutes float
```

---

## Referenced Docs

- `suite-attack/attack/fail_engine.py`
- `ISO 8601`

---

## Acceptance Criteria

- [ ] 30min gap returns 30.0
- [ ] Cross-day gap correct
- [ ] Invalid ISO string raises ValueError

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
